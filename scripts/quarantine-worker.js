import pg from "pg";
import {pathToFileURL} from "node:url";
import {openQuarantine} from "../server/quarantine.js";
import {scanClamav} from "../server/clamav.js";
import {parseQuarantinedInvoiceCsv,UnsafeCsvError} from "../server/secure-invoice-csv.js";

export async function runQuarantineCycle(db,{keyId,secret,scan,limit=10,expire=false}){
 if(!Number.isSafeInteger(limit)||limit<1||limit>20)throw new Error("Invalid worker cycle limit");
 if(typeof scan!=="function")throw new Error("Scanner required");
 const counts={claimed:0,clean:0,infected:0,error:0,stale:0,disposed:0,contentValidated:0,contentRejected:0,promoted:0,promotionFailed:0};
 for(let i=0;i<limit;i++){
  const {rows}=await db.query("SELECT * FROM private.claim_quarantine_scan()");
  const row=rows[0];if(!row)break;
  counts.claimed++;
  let verdict="error",contentState="not_checked",plain,manifest=null;
  try{
   plain=openQuarantine({sha:row.file_sha256,keyId:row.key_id,nonce:row.nonce,tag:row.auth_tag,ciphertext:row.ciphertext},row.tenant_id,row.batch_id,{id:keyId,secret});
   const result=await scan(plain);
   if(result==="infected")verdict="infected";
   else if(result==="clean"){
    try{manifest=parseQuarantinedInvoiceCsv(plain);contentState="validated";verdict="clean";}
    catch(e){if(e instanceof UnsafeCsvError){contentState="rejected";verdict="clean";}else throw e;}
   }
  }catch{/* Do not log plaintext, key, scanner signature, or exception details. */}
  finally{plain?.fill(0);}
  const complete=await db.query("SELECT private.finish_quarantine_manifest($1,$2,$3,$4,$5,$6) AS recorded",[row.tenant_id,row.batch_id,row.lease_id,verdict,contentState,manifest===null?null:JSON.stringify(manifest)]);
  if(!complete.rows[0]?.recorded)counts.stale++;else{
   counts[verdict]++;
   if(contentState==="validated")counts.contentValidated++;
   if(contentState==="rejected")counts.contentRejected++;
  }
  // A scanner outage or bad key should not burn through the entire retry queue.
  if(verdict==="error")break;
 }
 // Independently re-open, re-scan and re-parse only previously approved manifests.
 for(let i=0;i<limit&&!counts.error;i++){
  const {rows}=await db.query("SELECT * FROM private.claim_quarantine_promotion()");
  const row=rows[0];if(!row)break;
  let plain,parsed=null;
  try{
   plain=openQuarantine({sha:row.file_sha256,keyId:row.key_id,nonce:row.nonce,tag:row.auth_tag,ciphertext:row.ciphertext},row.tenant_id,row.batch_id,{id:keyId,secret});
   if(await scan(plain)==="clean")parsed=parseQuarantinedInvoiceCsv(plain);
  }catch{/* fail closed; no source values logged */}
  finally{plain?.fill(0);}
  const result=await db.query("SELECT private.finish_quarantine_promotion($1,$2,$3,$4) AS n",[row.tenant_id,row.batch_id,row.lease_id,parsed===null?null:JSON.stringify(parsed)]);
  const n=result.rows[0]?.n;
  if(Number.isInteger(n)&&n>0)counts.promoted++;
  else if(n===-1)counts.stale++;
  else{counts.promotionFailed++;break;}
 }
 if(expire)counts.disposed=(await db.query("SELECT private.expire_quarantine_bytes() AS n")).rows[0].n;
 return counts;
}
async function main(){
 const env=process.env;
 if(env.NODE_ENV==="production"||env.QUARANTINE_WORKER_ENABLED!=="true")throw new Error("Worker not approved for production");
 const url=new URL(env.QUARANTINE_SCANNER_DATABASE_URL||"");
 if(!["postgres:","postgresql:"].includes(url.protocol)||decodeURIComponent(url.username)!=="profitpilot_scanner"||!url.password||url.search||url.hash||!env.QUARANTINE_SCANNER_DATABASE_CA)throw new Error("Restricted scanner role with verified TLS required");
 if(!/^[0-9a-f]{64}$/.test(env.QUARANTINE_ENCRYPTION_KEY||"")||!env.QUARANTINE_KEY_ID||!env.CLAMAV_SOCKET_PATH)throw new Error("Incomplete scanner configuration");
 const db=new pg.Pool({connectionString:url.href,ssl:{ca:env.QUARANTINE_SCANNER_DATABASE_CA,rejectUnauthorized:true},max:1,connectionTimeoutMillis:5000,statement_timeout:3000});
 try{
  const counts=await runQuarantineCycle(db,{keyId:env.QUARANTINE_KEY_ID,secret:env.QUARANTINE_ENCRYPTION_KEY,scan:bytes=>scanClamav(bytes,{socketPath:env.CLAMAV_SOCKET_PATH}),expire:env.QUARANTINE_EXPIRY_APPROVED==="yes"});
  process.stdout.write(JSON.stringify({event:"quarantine_cycle",...counts})+"\n");
  if(counts.error||counts.stale||counts.promotionFailed)process.exitCode=1;
 }finally{await db.end();}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 main().catch(()=>{process.stderr.write("Quarantine worker failed; details suppressed.\n");process.exitCode=1;});
}

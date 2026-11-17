// Operator-only tool. Never put the manifest or signing key in the repository or backup.
import {createHmac,createHash,timingSafeEqual} from "node:crypto";
import {readFile,writeFile} from "node:fs/promises";
import {pathToFileURL} from "node:url";
import pg from "pg";

const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const hex=/^[a-f0-9]{64}$/;
function keyBytes(key){
 if(typeof key!=="string"||!hex.test(key))throw Error("Independent 32-byte checkpoint key required");
 return Buffer.from(key,"hex");
}
function cleanState(state){
 if(!state||!Array.isArray(state.markers)||!Array.isArray(state.violations)||state.violations.length)throw Error("Privacy state missing or inconsistent");
 const seen=new Set();
 return state.markers.map(m=>{
  // Global account security markers intentionally have no tenant or provider identifier.
  if(m?.kind==="access_change_applied"){
   if(!uuid.test(m.id)||!uuid.test(m.tenantId)||!uuid.test(m.userId)||typeof m.at!=="string"||!/^\d+(\.\d+)?$/.test(m.at)||!hex.test(m.evidence||"")||!["owner","admin","analyst","reviewer","read_only"].includes(m.role)||!["active","revoked"].includes(m.status))throw Error("Invalid access change marker");
   const index=m.kind+":"+m.id;
   if(seen.has(index))throw Error("Duplicate privacy marker");
   seen.add(index);
   return {kind:m.kind,id:m.id,tenantId:m.tenantId,userId:m.userId,at:m.at,evidence:m.evidence,role:m.role,status:m.status};
  }
  if(m?.kind==="signing_key_retired"){
   if(typeof m.id!=="string"||!hex.test(m.id)||typeof m.fingerprint!=="string"||!hex.test(m.fingerprint)||typeof m.at!=="string"||!/^\d+(\.\d+)?$/.test(m.at))throw Error("Invalid retired signing key marker");
   const index=m.kind+":"+m.id;
   if(seen.has(index))throw Error("Duplicate privacy marker");
   seen.add(index);
   return {kind:m.kind,id:m.id,fingerprint:m.fingerprint,at:m.at};
  }
  if(m?.kind==="audit_restore_anchor"){
   if(!uuid.test(m.id)||!uuid.test(m.tenantId)||typeof m.position!=="string"||!/^[1-9]\d{0,18}$/.test(m.position)||BigInt(m.position)>9223372036854775807n||typeof m.eventHash!=="string"||!hex.test(m.eventHash)||typeof m.at!=="string"||!/^\d+(\.\d+)?$/.test(m.at))throw Error("Invalid audit anchor marker");
   const index=m.kind+":"+m.id;
   if(seen.has(index))throw Error("Duplicate privacy marker");
   seen.add(index);
   return {kind:m.kind,id:m.id,tenantId:m.tenantId,position:m.position,eventHash:m.eventHash,at:m.at};
  }
  if(["account_contained","account_recovered"].includes(m?.kind)){
   if(!uuid.test(m.id)||!uuid.test(m.userId)||typeof m.at!=="string"||!/^\d+(\.\d+)?$/.test(m.at)||!hex.test(m.evidence||""))throw Error("Invalid account incident marker");
   const index=m.kind+":"+m.id;
   if(seen.has(index))throw Error("Duplicate privacy marker");
   seen.add(index);
   return {kind:m.kind,id:m.id,userId:m.userId,at:m.at,evidence:m.evidence};
  }
  if(m?.kind==="individual_session_revocation"){
   if(!uuid.test(m.id)||!hex.test(m.tokenFingerprint||"")||typeof m.at!=="string"||typeof m.expiresAt!=="string"||!/^\d+(\.\d+)?$/.test(m.at)||!/^\d+(\.\d+)?$/.test(m.expiresAt))throw Error("Invalid individual session revocation marker");
   const index=m.kind+":"+m.id;
   if(seen.has(index))throw Error("Duplicate privacy marker");
   seen.add(index);
   return {kind:m.kind,id:m.id,tokenFingerprint:m.tokenFingerprint,at:m.at,expiresAt:m.expiresAt};
  }
  if(m?.kind==="account_session_revocation"){
   if(!uuid.test(m.id)||!uuid.test(m.userId)||typeof m.at!=="string"||!/^\d{1,15}$/.test(m.at)||!Number.isSafeInteger(Number(m.at)))throw Error("Invalid session revocation marker");
   const index=m.kind+":"+m.id;
   if(seen.has(index))throw Error("Duplicate privacy marker");
   seen.add(index);
   return {kind:m.kind,id:m.id,userId:m.userId,at:m.at};
  }
  if(!m||!["closure","redaction","session_cleanup","provider_erasure","import_purge","local_email_correction","attachment_discard","source_ingestion_restricted","source_ingestion_released"].includes(m.kind)||!uuid.test(m.id)||!uuid.test(m.tenantId)||typeof m.at!=="string"||!/^\d+(\.\d+)?$/.test(m.at))throw Error("Invalid privacy marker");
  const index=m.kind+":"+m.id;
  if(seen.has(index))throw Error("Duplicate privacy marker");
  seen.add(index);
  if(m.kind==="closure"){
   if(!uuid.test(m.requestId)||typeof m.emailErased!=="boolean")throw Error("Invalid closure marker");
   return {kind:m.kind,id:m.id,tenantId:m.tenantId,requestId:m.requestId,at:m.at,emailErased:m.emailErased};
  }
  if(m.kind==="import_purge"){
   if(!Number.isSafeInteger(m.rowCount)||m.rowCount<1)throw Error("Invalid import purge marker");
   return {kind:m.kind,id:m.id,tenantId:m.tenantId,at:m.at,rowCount:m.rowCount};
  }
  if(["provider_erasure","local_email_correction","source_ingestion_restricted","source_ingestion_released"].includes(m.kind)){
   if(!uuid.test(m.userId))throw Error("Invalid provider erasure marker");
   return {kind:m.kind,id:m.id,tenantId:m.tenantId,userId:m.userId,at:m.at};
  }
  if(m.kind==="session_cleanup"){
   if(!uuid.test(m.userId)||typeof m.cutoff!=="string"||!/^\d+(\.\d+)?$/.test(m.cutoff))throw Error("Invalid cleanup marker");
   return {kind:m.kind,id:m.id,tenantId:m.tenantId,userId:m.userId,at:m.at,cutoff:m.cutoff};
  }
  return {kind:m.kind,id:m.id,tenantId:m.tenantId,at:m.at};
 }).sort((a,b)=>(a.kind+":"+a.id).localeCompare(b.kind+":"+b.id));
}
function identity(value){
 if(typeof value!=="string"||!/^[a-zA-Z0-9._-]{3,128}$/.test(value))throw Error("Expected deployment identity required");
 return value;
}
export function signCheckpoint(state,{key,deploymentId,now=Date.now()}){
 const payload={version:1,deploymentId:identity(deploymentId),createdAt:new Date(now).toISOString(),markers:cleanState(state)};
 const signature=createHmac("sha256",keyBytes(key)).update(JSON.stringify(payload)).digest("hex");
 return {payload,signature};
}
export function checkpointDigest(document){return createHash("sha256").update(JSON.stringify(document)).digest("hex");}
export function verifyCheckpoint(doc,state,{key,deploymentId,expectedDigest,now=Date.now(),maxAgeHours=24}){
 if(!doc||!doc.payload||!hex.test(doc.signature||"")||!hex.test(expectedDigest||""))throw Error("Signed checkpoint and independently recorded digest required");
 if(checkpointDigest(doc)!==expectedDigest)throw Error("Checkpoint does not match latest independently recorded digest");
 const p=doc.payload;
 const actual=createHmac("sha256",keyBytes(key)).update(JSON.stringify(p)).digest();
 if(!timingSafeEqual(actual,Buffer.from(doc.signature,"hex")))throw Error("Checkpoint signature invalid");
 if(p.version!==1||p.deploymentId!==identity(deploymentId))throw Error("Checkpoint deployment mismatch");
 const capture=Date.parse(p.createdAt);
 if(!Number.isFinite(capture)||capture>now||!Number.isInteger(maxAgeHours)||maxAgeHours<1||maxAgeHours>168||now-capture>maxAgeHours*3600000)throw Error("Checkpoint stale or future-dated");
 const required=cleanState({markers:p.markers,violations:[]});
 const present=new Map(cleanState(state).map(m=>[m.kind+":"+m.id,JSON.stringify(m)]));
 for(const marker of required){if(present.get(marker.kind+":"+marker.id)!==JSON.stringify(marker))throw Error("Restore is missing or has changed a required privacy marker");}
 return {verified:true,requiredMarkers:required.length};
}
export function assessBackupInventory(inventory,{now=Date.now(),maxRetentionDays}){
 if(!Array.isArray(inventory)||!inventory.length||!Number.isInteger(maxRetentionDays)||maxRetentionDays<1||maxRetentionDays>36500)throw Error("Approved retention policy and nonempty backup inventory required");
 const seen=new Set();
 return inventory.map(b=>{
  if(!b||typeof b.id!=="string"||!b.id||seen.has(b.id)||typeof b.legalHold!=="boolean"||typeof b.encrypted!=="boolean")throw Error("Invalid or duplicate backup record");
  seen.add(b.id);
  const created=Date.parse(b.createdAt),expires=Date.parse(b.expiresAt);
  if(!Number.isFinite(created)||!Number.isFinite(expires)||created>now||expires<=created)throw Error("Invalid backup dates");
  const issues=[];
  if(!b.encrypted)issues.push("encryption_not_confirmed");
  if(!b.legalHold&&expires-created>maxRetentionDays*86400000)issues.push("retention_exceeds_policy");
  if(!b.legalHold&&expires<=now)issues.push("expiry_due_or_overdue");
  if(b.legalHold&&(typeof b.holdReference!=="string"||!b.holdReference.trim()))issues.push("missing_hold_evidence");
  return {id:b.id,legalHold:b.legalHold,expiryReviewDue:!b.legalHold&&expires<=now,issues};
 });
}
export function restorePoolOptions(connectionString){
 if(!connectionString)throw Error("Operator database connection required");
 let url;
 try{url=new URL(connectionString);}catch{throw Error("Invalid operator PostgreSQL URL");}
 // pg connection-string parameters can override the explicit SSL configuration.
 // Accept only plain PostgreSQL URLs; verification options are set here, not by URL.
 if(!["postgres:","postgresql:"].includes(url.protocol)||!url.hostname||url.search||url.hash)
  throw Error("Operator PostgreSQL URL must not contain query parameters or fragments");
 return {connectionString,ssl:{rejectUnauthorized:true},max:1,connectionTimeoutMillis:5000,statement_timeout:15000};
}
async function readState({capture=false}={}){
 const pool=new pg.Pool(restorePoolOptions(process.env.PRIVACY_ADMIN_DATABASE_URL));
 const client=await pool.connect();
 try{
  await client.query(capture?"BEGIN ISOLATION LEVEL REPEATABLE READ":"BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
  if(capture)await client.query("SELECT private.capture_audit_restore_anchors()");
  const state=(await client.query("SELECT private.privacy_restore_state() AS state")).rows[0].state;
  cleanState(state);
  await client.query("COMMIT");
  return state;
 }catch(error){try{await client.query("ROLLBACK");}catch{}throw error;}
 finally{client.release();await pool.end();}
}
async function main(){
 const [mode,file]=process.argv.slice(2);
 if(!file||!["capture","verify","inventory"].includes(mode))throw Error("Usage: capture|verify|inventory <file>");
 if(mode==="inventory"){
  const result=assessBackupInventory(JSON.parse(await readFile(file,"utf8")),{maxRetentionDays:Number(process.env.PRIVACY_BACKUP_MAX_DAYS)});
  console.log(JSON.stringify(result,null,2));
  if(result.some(x=>x.issues.length))process.exitCode=1;
  return;
 }
 const options={key:process.env.PRIVACY_CHECKPOINT_KEY,deploymentId:process.env.PRIVACY_DEPLOYMENT_ID};
 if(mode==="capture"){
  const doc=signCheckpoint(await readState({capture:true}),options);
  await writeFile(file,JSON.stringify(doc),{flag:"wx",mode:0o600});
  console.log(JSON.stringify({sha256:checkpointDigest(doc),markers:doc.payload.markers.length}));
 }else{
  const doc=JSON.parse(await readFile(file,"utf8"));
  console.log(JSON.stringify(verifyCheckpoint(doc,await readState(),{...options,expectedDigest:process.env.PRIVACY_EXPECTED_CHECKPOINT_SHA256})));
 }
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(error=>{console.error("Privacy safeguard failed: "+(error instanceof Error?error.message:"unknown error"));process.exitCode=1;});

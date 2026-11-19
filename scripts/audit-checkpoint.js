import {createPrivateKey,createPublicKey,sign,verify} from "node:crypto";
import {readFile,writeFile} from "node:fs/promises";
import {pathToFileURL} from "node:url";
import pg from "pg";
const format="profitpilot-audit-checkpoint-v1";
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const hash=/^[a-f0-9]{64}$/;
function canonical(entries,createdAt){
 if(!Array.isArray(entries)||entries.length>100000||typeof createdAt!=="string"||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(createdAt)||!Number.isFinite(Date.parse(createdAt)))throw new Error("Invalid checkpoint");
 const normalized=entries.map(x=>{
  if(!uuid.test(x?.tenant_id||"")||typeof x.entry_count!=="string"||!/^[1-9]\d{0,18}$/.test(x.entry_count)||BigInt(x.entry_count)>9223372036854775807n||!hash.test(x.head_hash||""))throw new Error("Invalid checkpoint entry");
  return {tenant_id:x.tenant_id,entry_count:x.entry_count,head_hash:x.head_hash};
 }).sort((a,b)=>a.tenant_id<b.tenant_id?-1:a.tenant_id>b.tenant_id?1:0);
 if(new Set(normalized.map(x=>x.tenant_id)).size!==normalized.length)throw new Error("Duplicate tenant checkpoint");
 return {format,createdAt,entries:normalized};
}
export function signCheckpoint(entries,privateKey,createdAt=new Date().toISOString()){
 const key=typeof privateKey==="object"&&privateKey.type==="private"?privateKey:createPrivateKey(privateKey);
 if(key.asymmetricKeyType!=="ed25519")throw new Error("Expected Ed25519 independent audit signing key");
 const payload=canonical(entries,createdAt);
 return {payload,signature:sign(null,Buffer.from(JSON.stringify(payload)),key).toString("base64")};
}
export function verifyCheckpoint(document,publicKey){
 const key=typeof publicKey==="object"&&publicKey.type==="public"?publicKey:createPublicKey(publicKey);
 if(key.asymmetricKeyType!=="ed25519"||document?.payload?.format!==format||typeof document.signature!=="string"||!/^[A-Za-z0-9+/]{86}==$/.test(document.signature))throw new Error("Invalid checkpoint envelope");
 const payload=canonical(document.payload.entries,document.payload.createdAt);
 if(JSON.stringify(payload)!==JSON.stringify(document.payload)||!verify(null,Buffer.from(JSON.stringify(payload)),key,Buffer.from(document.signature,"base64")))throw new Error("Checkpoint signature invalid");
 return payload;
}
export async function verifyHistoricalCheckpoint(db,document,publicKey){
 const payload=verifyCheckpoint(document,publicKey);
 for(const row of payload.entries){
  const result=await db.query("SELECT private.audit_checkpoint_matches($1,$2,$3) AS ok",[row.tenant_id,row.entry_count,row.head_hash]);
  if(result.rows[0]?.ok!==true)throw new Error("Historical checkpoint mismatch");
 }
 return {verified:payload.entries.length};
}
async function main(){
 const [mode,path]=process.argv.slice(2);
 if(!["sign","verify"].includes(mode)||!path)throw new Error("Invalid checkpoint command");
 const url=new URL(process.env.AUDIT_READER_DATABASE_URL||"");
 if(!["postgres:","postgresql:"].includes(url.protocol)||decodeURIComponent(url.username)!=="profitpilot_audit_reader"||!url.password||url.search||url.hash||!process.env.AUDIT_READER_DATABASE_CA)throw new Error("Restricted verified TLS audit connection required");
 const db=new pg.Pool({connectionString:url.href,ssl:{ca:process.env.AUDIT_READER_DATABASE_CA,rejectUnauthorized:true},max:1,connectionTimeoutMillis:5000,statement_timeout:30000});
 try{
  if(mode==="sign"){
   const rows=(await db.query("SELECT * FROM private.audit_checkpoint_heads()")).rows;
   const document=signCheckpoint(rows,process.env.AUDIT_CHECKPOINT_PRIVATE_KEY);
   await writeFile(path,JSON.stringify(document)+"\n",{flag:"wx",mode:0o600});
   process.stdout.write(JSON.stringify({event:"audit_checkpoint_signed",count:rows.length})+"\n");
  }else{
   const raw=await readFile(path);
   if(raw.length>32000000)throw new Error("Checkpoint too large");
   const result=await verifyHistoricalCheckpoint(db,JSON.parse(raw.toString("utf8")),process.env.AUDIT_CHECKPOINT_PUBLIC_KEY);
   process.stdout.write(JSON.stringify({event:"audit_checkpoint_verified",...result})+"\n");
  }
 }finally{await db.end();}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 main().catch(()=>{process.stderr.write("Audit checkpoint operation failed; details suppressed.\n");process.exitCode=1;});
}

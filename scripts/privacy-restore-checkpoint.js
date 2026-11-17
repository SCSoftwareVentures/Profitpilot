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
  if(!m||!["closure","redaction"].includes(m.kind)||!uuid.test(m.id)||!uuid.test(m.tenantId)||typeof m.at!=="string"||!/^\d+(\.\d+)?$/.test(m.at))throw Error("Invalid privacy marker");
  const index=m.kind+":"+m.id;
  if(seen.has(index))throw Error("Duplicate privacy marker");
  seen.add(index);
  if(m.kind==="closure"){
   if(!uuid.test(m.requestId)||typeof m.emailErased!=="boolean")throw Error("Invalid closure marker");
   return {kind:m.kind,id:m.id,tenantId:m.tenantId,requestId:m.requestId,at:m.at,emailErased:m.emailErased};
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
async function readState(){
 const pool=new pg.Pool(restorePoolOptions(process.env.PRIVACY_ADMIN_DATABASE_URL));
 try{return (await pool.query("SELECT private.privacy_restore_state() AS state")).rows[0].state;}
 finally{await pool.end();}
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
  const doc=signCheckpoint(await readState(),options);
  await writeFile(file,JSON.stringify(doc),{flag:"wx",mode:0o600});
  console.log(JSON.stringify({sha256:checkpointDigest(doc),markers:doc.payload.markers.length}));
 }else{
  const doc=JSON.parse(await readFile(file,"utf8"));
  console.log(JSON.stringify(verifyCheckpoint(doc,await readState(),{...options,expectedDigest:process.env.PRIVACY_EXPECTED_CHECKPOINT_SHA256})));
 }
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(error=>{console.error("Privacy safeguard failed: "+(error instanceof Error?error.message:"unknown error"));process.exitCode=1;});

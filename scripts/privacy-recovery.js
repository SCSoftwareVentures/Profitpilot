import {createHash,createPrivateKey,createPublicKey,sign,verify} from "node:crypto";
import {createReadStream} from "node:fs";
import {open,writeFile} from "node:fs/promises";
import {pathToFileURL} from "node:url";
import pg from "pg";

const FORMAT="profitpilot-privacy-recovery-v1", MAX_ROWS=100000, MAX_BYTES=32000000;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SHA=/^[0-9a-f]{64}$/;
const REF=/^[A-Za-z][A-Za-z0-9_-]{2,63}$/;
const STAMP=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/;
const keyOf=x=>x.tenant_id+":"+x.batch_id;
function validTimestamp(x){
 if(typeof x!=="string"||!STAMP.test(x))return false;
 const ms=x.slice(0,23)+"Z",t=Date.parse(ms);
 return Number.isFinite(t)&&new Date(t).toISOString()===ms;
}
function exactKeys(value,expected){
 return value!==null&&typeof value==="object"&&!Array.isArray(value)&&
  Object.keys(value).length===expected.length&&expected.every(k=>Object.hasOwn(value,k));
}
export function canonicalInventory(input){
 if(!exactKeys(input,["disposals","expiries","holds"])||
 ![input.disposals,input.expiries,input.holds].every(Array.isArray)||
 input.disposals.length+input.expiries.length+input.holds.length>MAX_ROWS)throw new Error("Invalid privacy recovery inventory");
 function rows(values,kind){
  const normalized=values.map(row=>{
   const fields=kind==="holds"?["tenant_id","batch_id"]:kind==="expiries"?["tenant_id","batch_id","file_sha256","disposed_at"]:["tenant_id","batch_id","file_sha256","authority_ref","disposed_at"];
   if(!exactKeys(row,fields)||typeof row.tenant_id!=="string"||!UUID.test(row.tenant_id)||typeof row.batch_id!=="string"||!UUID.test(row.batch_id))throw new Error("Invalid recovery receipt");
   const out={tenant_id:row.tenant_id,batch_id:row.batch_id};
   if(kind!=="holds"){
    if(typeof row.file_sha256!=="string"||!SHA.test(row.file_sha256)||!validTimestamp(row.disposed_at))throw new Error("Invalid recovery receipt");
    out.file_sha256=row.file_sha256;
    if(kind==="disposals"){
     if(typeof row.authority_ref!=="string"||!REF.test(row.authority_ref))throw new Error("Invalid disposal authority");
     out.authority_ref=row.authority_ref;
    }
    out.disposed_at=row.disposed_at;
   }
   return out;
  }).sort((a,b)=>keyOf(a)<keyOf(b)?-1:keyOf(a)>keyOf(b)?1:0);
  if(new Set(normalized.map(keyOf)).size!==normalized.length)throw new Error("Duplicate recovery receipt");
  return normalized;
 }
 const disposals=rows(input.disposals,"disposals"),expiries=rows(input.expiries,"expiries"),holds=rows(input.holds,"holds");
 const hashes=new Set();
 for(const d of disposals){
  const k=d.tenant_id+":"+d.file_sha256;
  if(hashes.has(k))throw new Error("Conflicting disposal checksum");
  hashes.add(k);
 }
 const deleted=new Set(disposals.map(keyOf));
 if(expiries.some(x=>deleted.has(keyOf(x)))||holds.some(x=>deleted.has(keyOf(x))))throw new Error("Conflicting deleted batch inventory");
 return {disposals,expiries,holds};
}
function canonicalPayload(inventory,backupSha256,issuedAt){
 if(typeof backupSha256!=="string"||!SHA.test(backupSha256)||typeof issuedAt!=="string"||
 !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(issuedAt)||!Number.isFinite(Date.parse(issuedAt))||
 new Date(issuedAt).toISOString()!==issuedAt)throw new Error("Invalid recovery package binding");
 return {format:FORMAT,backupSha256,issuedAt,inventory:canonicalInventory(inventory)};
}
export function signPrivacyRecovery(inventory,backupSha256,key,issuedAt=new Date().toISOString()){
 const signingKey=key?.type==="private"?key:createPrivateKey(key);
 if(signingKey.asymmetricKeyType!=="ed25519")throw new Error("Independent Ed25519 recovery signing key required");
 const payload=canonicalPayload(inventory,backupSha256,issuedAt);
 for(const row of [...payload.inventory.disposals,...payload.inventory.expiries]){
  if(Date.parse(row.disposed_at)>Date.parse(issuedAt))throw new Error("Receipt postdates recovery package");
 }
 return {payload,signature:sign(null,Buffer.from(JSON.stringify(payload)),signingKey).toString("base64")};
}
export function privacyRecoveryDigest(document){
 return createHash("sha256").update(JSON.stringify(document),"utf8").digest("hex");
}
export function verifyPrivacyRecovery(document,publicKey,{backupSha256,expectedManifestSha256}){
 if(typeof expectedManifestSha256!=="string"||!SHA.test(expectedManifestSha256)||
 privacyRecoveryDigest(document)!==expectedManifestSha256)throw new Error("Recovery package does not match independently approved digest");
 if(!exactKeys(document,["payload","signature"])||!exactKeys(document.payload,["format","backupSha256","issuedAt","inventory"])||
 document.payload.format!==FORMAT||document.payload.backupSha256!==backupSha256||
 typeof document.signature!=="string"||!/^[A-Za-z0-9+/]{86}==$/.test(document.signature))
 throw new Error("Invalid recovery package envelope or backup binding");
 const key=publicKey?.type==="public"?publicKey:createPublicKey(publicKey);
 const payload=canonicalPayload(document.payload.inventory,document.payload.backupSha256,document.payload.issuedAt);
 if(key.asymmetricKeyType!=="ed25519"||JSON.stringify(payload)!==JSON.stringify(document.payload)||
 !verify(null,Buffer.from(JSON.stringify(payload)),key,Buffer.from(document.signature,"base64")))throw new Error("Recovery signature invalid");
 if(Date.parse(payload.issuedAt)>Date.now()+5000)throw new Error("Recovery package was issued in the future");
 for(const row of [...payload.inventory.disposals,...payload.inventory.expiries]){
  if(Date.parse(row.disposed_at)>Date.parse(payload.issuedAt))throw new Error("Receipt postdates recovery package");
 }
 return payload;
}
export async function readPrivacyInventory(db){
 const result=await db.query("SELECT private.privacy_recovery_inventory() AS inventory");
 return canonicalInventory(result.rows[0]?.inventory);
}
function assertSubset(current,authoritative,label){
 const known=new Map(authoritative.map(x=>[keyOf(x),JSON.stringify(x)]));
 if(current.some(row=>known.get(keyOf(row))!==JSON.stringify(row)))throw new Error("Restored "+label+" inventory conflicts with approved package");
}
// Transaction belongs exclusively to this function. Caller supplies isolated
// administrative target, externally authenticated backup and latest digest.
// No API credentials or automatic legal-hold releases are involved.
export async function replayPrivacyRecovery(pool,document,publicKey,binding){
 const {inventory}=verifyPrivacyRecovery(document,publicKey,binding);
 const c=await pool.connect();
 let discard=false;
 try{
  await c.query("BEGIN ISOLATION LEVEL SERIALIZABLE");
  await c.query("SET LOCAL lock_timeout='3s'");
  await c.query("SET LOCAL statement_timeout='30s'");
  await c.query("SELECT pg_advisory_xact_lock(hashtextextended('profitpilot-privacy-recovery-v1',0))");
  const prior=await readPrivacyInventory(c);
  for(const kind of ["disposals","expiries","holds"])assertSubset(prior[kind],inventory[kind],kind);
  const existing=Object.fromEntries(Object.entries(prior).map(([k,rows])=>[k,new Set(rows.map(keyOf))]));
  const applied={holds:0,disposals:0,expiries:0};
  for(const x of inventory.holds){
   if(existing.holds.has(keyOf(x)))continue;
   await c.query("SELECT private.set_import_disposal_hold($1,$2,true,'RECOVERY_PRIVACY_HOLD')",[x.tenant_id,x.batch_id]);
   applied.holds++;
  }
  for(const x of inventory.disposals){
   if(existing.disposals.has(keyOf(x)))continue;
   await c.query("SELECT private.replay_import_disposal($1,$2,$3,$4,$5)",[x.tenant_id,x.batch_id,x.file_sha256,x.authority_ref,x.disposed_at]);
   applied.disposals++;
  }
  for(const x of inventory.expiries){
   if(existing.expiries.has(keyOf(x)))continue;
   await c.query("SELECT private.replay_quarantine_expiry($1,$2,$3,$4)",[x.tenant_id,x.batch_id,x.file_sha256,x.disposed_at]);
   applied.expiries++;
  }
  const after=await readPrivacyInventory(c);
  if(JSON.stringify(after)!==JSON.stringify(inventory))throw new Error("Recovery inventory did not reconcile exactly");
  // Never certify a tombstone whose associated source rows survived.
  const mismatch=await c.query("SELECT EXISTS(SELECT 1 FROM private.import_disposal_tombstones d JOIN public.import_batches b ON d.tenant_id=b.tenant_id AND (d.batch_id=b.id OR d.file_sha256=b.file_sha256)) OR EXISTS(SELECT 1 FROM private.quarantine_expiry_receipts e LEFT JOIN private.quarantined_files q USING(tenant_id,batch_id) WHERE q.batch_id IS NULL OR q.scan_state<>'disposed' OR q.ciphertext IS NOT NULL OR q.file_sha256 IS DISTINCT FROM e.file_sha256 OR q.disposed_at IS DISTINCT FROM e.disposed_at) AS mismatch");
  if(mismatch.rows[0]?.mismatch!==false)throw new Error("Recovery disposal state inconsistent");
  await c.query("COMMIT");
  return applied;
 }catch(e){
  try{await c.query("ROLLBACK");}catch{discard=true;}
  throw e;
 }finally{c.release(discard);}
}
async function archiveDigest(path){
 const h=createHash("sha256");for await(const chunk of createReadStream(path))h.update(chunk);return h.digest("hex");
}
async function readDocument(path){
 const file=await open(path,"r");
 try{
  const stat=await file.stat();
  if(!stat.isFile()||stat.size<1||stat.size>MAX_BYTES)throw new Error("Invalid recovery package size");
  const buffer=Buffer.alloc(stat.size);
  let offset=0;
  while(offset<buffer.length){const read=await file.read(buffer,offset,buffer.length-offset,offset);if(!read.bytesRead)throw new Error("Truncated package");offset+=read.bytesRead;}
  if((await file.stat()).size!==stat.size)throw new Error("Recovery package changed while reading");
  const raw=buffer.toString("utf8"),doc=JSON.parse(raw);
  if(raw!==JSON.stringify(doc)+"\n")throw new Error("Noncanonical package encoding");
  return doc;
 }finally{await file.close();}
}
function database(urlValue,ca,reader){
 const url=new URL(urlValue||"");
 if(!["postgres:","postgresql:"].includes(url.protocol)||!url.hostname||!url.username||!url.password||!url.pathname.slice(1)||url.search||url.hash||!ca)throw new Error("Verified TLS database connection required");
 const user=decodeURIComponent(url.username);
 if(reader?user!=="profitpilot_recovery_reader":["profitpilot_app","profitpilot_scanner","profitpilot_audit_reader","profitpilot_identity_operator","profitpilot_recovery_reader"].includes(user))throw new Error("Invalid recovery database authority");
 return new pg.Pool({connectionString:url.href,ssl:{ca,rejectUnauthorized:true},max:1,connectionTimeoutMillis:5000,statement_timeout:30000});
}
async function main(){
 const [mode,archive,path,...rest]=process.argv.slice(2),env=process.env;
 if(!["sign","replay"].includes(mode)||!archive||!path||rest.length)throw new Error("Invalid recovery command");
 const backupSha256=await archiveDigest(archive);
 if(mode==="sign"){
  if(env.RECOVERY_SOURCE_FROZEN!=="yes")throw new Error("Authoritative source must be quiescent");
  const db=database(env.RECOVERY_READER_DATABASE_URL,env.RECOVERY_DATABASE_CA,true);
  try{
   const doc=signPrivacyRecovery(await readPrivacyInventory(db),backupSha256,env.RECOVERY_SIGNING_PRIVATE_KEY);
   const bytes=JSON.stringify(doc)+"\n";
   if(Buffer.byteLength(bytes)>MAX_BYTES)throw new Error("Recovery package too large");
   await writeFile(path,bytes,{flag:"wx",mode:0o600});
   process.stdout.write(JSON.stringify({event:"privacy_recovery_signed",manifestSha256:privacyRecoveryDigest(doc)})+"\n");
  }finally{await db.end();}
 }else{
  if(env.RECOVERY_TARGET_ISOLATED!=="yes")throw new Error("Restore target must be isolated from service traffic");
  const doc=await readDocument(path);
  const binding={backupSha256,expectedManifestSha256:env.RECOVERY_EXPECTED_MANIFEST_SHA256};
  verifyPrivacyRecovery(doc,env.RECOVERY_SIGNING_PUBLIC_KEY,binding);
  const db=database(env.RECOVERY_TARGET_DATABASE_URL,env.RECOVERY_DATABASE_CA,false);
  try{
   const result=await replayPrivacyRecovery(db,doc,env.RECOVERY_SIGNING_PUBLIC_KEY,binding);
   process.stdout.write(JSON.stringify({event:"privacy_recovery_reconciled",...result})+"\n");
  }finally{await db.end();}
 }
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 main().catch(()=>{process.stderr.write("Privacy recovery failed; keep the restore isolated. Details suppressed.\n");process.exitCode=1;});
}

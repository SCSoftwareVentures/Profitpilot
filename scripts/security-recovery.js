import {createHash,createPrivateKey,createPublicKey,sign,verify} from "node:crypto";
import {createReadStream,lstatSync,readFileSync,writeFileSync} from "node:fs";
import {pathToFileURL} from "node:url";
import pg from "pg";
const FORMAT="profitpilot-security-recovery-v1",MAX=100000,MAX_BYTES=32000000;
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/,SHA=/^[a-f0-9]{64}$/;
const fields={
 tenants:["id","status"],users:["id","status","subject_hash"],memberships:["tenant_id","user_id","role","status"],cutoffs:["user_id","revoked_through"],sessions:["user_id","session_digest"],keys:["key_id","active"],incidents:["incident_id","tenant_id","category","released"]
};
const key=(k,x)=>k==="memberships"?x.tenant_id+":"+x.user_id:k==="sessions"?x.user_id+":"+x.session_digest:k==="cutoffs"?x.user_id:k==="keys"?x.key_id:k==="incidents"?x.incident_id:x.id;
const exact=(v,keys)=>v!==null&&typeof v==="object"&&!Array.isArray(v)&&Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));
const matches=(v,p)=>typeof v==="string"&&p.test(v);
const oneOf=(v,values)=>values.includes(v);
const iso=x=>typeof x==="string"&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(x)&&Number.isFinite(Date.parse(x))&&new Date(Date.parse(x)).toISOString()===x;
export function canonicalSecurityInventory(input){
 const kinds=Object.keys(fields);
 if(!exact(input,kinds)||kinds.some(k=>!Array.isArray(input[k]))||kinds.reduce((n,k)=>n+input[k].length,0)>MAX)throw Error("Invalid security inventory");
 const out={};
 for(const k of kinds){
  const rows=input[k].map(x=>{
   if(!exact(x,fields[k])||fields[k].filter(f=>f==="id"||f.endsWith("_id")&&f!=="key_id").some(f=>!matches(x[f],UUID)))throw Error("Invalid inventory identity");
   if(k==="tenants"&&!oneOf(x.status,["active","suspended","closed"])||
    k==="users"&&(!oneOf(x.status,["active","disabled"])||!matches(x.subject_hash,SHA))||
    k==="memberships"&&(!oneOf(x.role,["owner","admin","analyst","reviewer","read_only"])||!oneOf(x.status,["active","revoked"]))||
    k==="cutoffs"&&(!matches(x.revoked_through,/^(?:0|[1-9]\d{0,18})$/)||BigInt(x.revoked_through)>BigInt(Math.floor(Date.now()/1000)))||
    k==="sessions"&&!matches(x.session_digest,SHA)||
    k==="keys"&&(!matches(x.key_id,/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/)||typeof x.active!=="boolean")||
    k==="incidents"&&(!oneOf(x.category,["suspected_compromise","data_exposure","integrity_failure","operational_emergency"])||typeof x.released!=="boolean"))throw Error("Invalid inventory entry");
   return Object.fromEntries(fields[k].map(f=>[f,x[f]]));
  }).sort((a,b)=>key(k,a)<key(k,b)?-1:key(k,a)>key(k,b)?1:0);
  if(new Set(rows.map(x=>key(k,x))).size!==rows.length)throw Error("Duplicate inventory entry");
  out[k]=rows;
 }
 const users=new Set(out.users.map(x=>x.id)),tenants=new Set(out.tenants.map(x=>x.id)),active=new Set();
 if(new Set(out.users.map(x=>x.subject_hash)).size!==out.users.length||
 out.memberships.some(x=>!users.has(x.user_id)||!tenants.has(x.tenant_id))||
 [...out.sessions,...out.cutoffs].some(x=>!users.has(x.user_id))||
 out.incidents.some(x=>!tenants.has(x.tenant_id)))throw Error("Inconsistent inventory references");
 for(const x of out.incidents.filter(x=>!x.released)){if(active.has(x.tenant_id))throw Error("Duplicate active incident");active.add(x.tenant_id);}
 return out;
}
function payload(inventory,backupSha256,issuedAt){
 if(!matches(backupSha256,SHA)||!iso(issuedAt)||Date.parse(issuedAt)>Date.now()+5000)throw Error("Invalid recovery binding");
 const canonical=canonicalSecurityInventory(inventory);
 if(canonical.cutoffs.some(x=>BigInt(x.revoked_through)>BigInt(Math.floor(Date.parse(issuedAt)/1000))))throw Error("Cutoff postdates recovery package");
 return {format:FORMAT,backupSha256,issuedAt,inventory:canonical};
}
export const securityRecoveryDigest=doc=>createHash("sha256").update(JSON.stringify(doc)).digest("hex");
export function signSecurityRecovery(inventory,backupSha256,privateKey,issuedAt=new Date().toISOString()){
 const k=privateKey?.type==="private"?privateKey:createPrivateKey(privateKey);
 if(k.asymmetricKeyType!=="ed25519")throw Error("Independent Ed25519 key required");
 const p=payload(inventory,backupSha256,issuedAt);
 return {payload:p,signature:sign(null,Buffer.from(JSON.stringify(p)),k).toString("base64")};
}
export function verifySecurityRecovery(doc,publicKey,binding){
 if(!matches(binding?.expectedManifestSha256,SHA)||securityRecoveryDigest(doc)!==binding.expectedManifestSha256||
 !exact(doc,["payload","signature"])||!exact(doc.payload,["format","backupSha256","issuedAt","inventory"])||
 doc.payload.format!==FORMAT||doc.payload.backupSha256!==binding.backupSha256||!matches(doc.signature,/^[A-Za-z0-9+/]{86}==$/))throw Error("Invalid independently approved recovery binding");
 const k=publicKey?.type==="public"?publicKey:createPublicKey(publicKey),p=payload(doc.payload.inventory,doc.payload.backupSha256,doc.payload.issuedAt);
 if(k.asymmetricKeyType!=="ed25519"||JSON.stringify(p)!==JSON.stringify(doc.payload)||!verify(null,Buffer.from(JSON.stringify(p)),k,Buffer.from(doc.signature,"base64")))throw Error("Invalid recovery signature");
 return p.inventory;
}
export async function readSecurityInventory(db){
 const r=await db.query("SELECT private.security_recovery_inventory() AS inventory");
 if(r.rowCount!==1)throw Error("Missing recovery inventory");
 return canonicalSecurityInventory(r.rows[0].inventory);
}
// Deny-only reconciliation. Unrecognized identities, newly granted or changed
// membership roles, new key material, and incident releases require separately
// approved manual reconciliation. Never silently re-enable privileges.
export function recoveryPlan(current,authoritative){
 const a=canonicalSecurityInventory(authoritative),c=canonicalSecurityInventory(current);
 const maps=Object.fromEntries(Object.keys(fields).map(k=>[k,new Map(c[k].map(x=>[key(k,x),x]))]));
 const desired=Object.fromEntries(Object.keys(fields).map(k=>[k,new Map(a[k].map(x=>[key(k,x),x]))]));
 const plan={memberships:[],tenants:[],users:[],keys:[],cutoffs:[],sessions:[],incidents:[]};
 const conflict=()=>{throw Error("Manual security reconciliation required; keep target isolated");};
 for(const k of ["tenants","users","memberships","keys"]){
  if(c[k].length!==a[k].length||c[k].some(x=>!desired[k].has(key(k,x))))conflict();
  for(const x of a[k]){
   const old=maps[k].get(key(k,x));if(!old)conflict();
   if(k==="users"&&x.subject_hash!==old.subject_hash||k==="memberships"&&x.role!==old.role)conflict();
   if(k==="keys"){if(x.active&&!old.active)conflict();if(!x.active&&old.active)plan.keys.push(x);continue;}
   if(x.status!==old.status){
    if(old.status!=="active"||x.status==="active")conflict();
    plan[k].push(x);
   }
  }
 }
 for(const x of c.sessions)if(!desired.sessions.has(key("sessions",x)))conflict();
 for(const x of a.sessions)if(!maps.sessions.has(key("sessions",x)))plan.sessions.push(x);
 for(const x of c.cutoffs)if(!desired.cutoffs.has(x.user_id))conflict();
 for(const x of a.cutoffs){const old=maps.cutoffs.get(x.user_id);if(!old||BigInt(old.revoked_through)<BigInt(x.revoked_through))plan.cutoffs.push(x);}
 for(const x of c.incidents){const target=desired.incidents.get(x.incident_id);if(!target||JSON.stringify(x)!==JSON.stringify(target))conflict();}
 for(const x of a.incidents){if(maps.incidents.has(x.incident_id))continue;if(x.released)conflict();plan.incidents.push(x);}
 return plan;
}
export async function replaySecurityRecovery(pool,doc,key,binding){
 const authoritative=verifySecurityRecovery(doc,key,binding),c=await pool.connect();let discard=false;
 try{
  await c.query("BEGIN ISOLATION LEVEL SERIALIZABLE");
  await c.query("SET LOCAL lock_timeout='3s'");await c.query("SET LOCAL statement_timeout='30s'");
  await c.query("SELECT pg_advisory_xact_lock(hashtextextended('profitpilot-security-recovery-v1',0))");
  if((await c.query("SELECT private.verify_security_catalog() AS ok")).rows[0]?.ok!==true)throw Error("Unverified recovery schema");
  const plan=recoveryPlan(await readSecurityInventory(c),authoritative);
  for(const x of plan.memberships)await c.query("SELECT private.administer_membership($1,$2,NULL,'revoke','RECOVERY_SECURITY')",[x.tenant_id,x.user_id]);
  for(const x of plan.tenants)await c.query("UPDATE public.tenants SET status=$2 WHERE id=$1 AND status='active'",[x.id,x.status]);
  for(const x of plan.users)await c.query("SELECT private.revoke_identity_access($1,'disable','RECOVERY_SECURITY',NULL)",[x.id]);
  for(const x of plan.keys)await c.query("UPDATE private.tenant_context_keys SET active=false WHERE key_id=$1 AND active",[x.key_id]);
  const replay=async(user,cutoff,digest)=>c.query("SELECT private.replay_identity_revocation(id,auth_subject,$2,$3,false,'RECOVERY_SECURITY') FROM public.users WHERE id=$1",[user,cutoff,digest]);
  for(const x of plan.cutoffs)await replay(x.user_id,x.revoked_through,null);
  for(const x of plan.sessions)await replay(x.user_id,null,x.session_digest);
  for(const x of plan.incidents)await c.query("SELECT private.activate_tenant_emergency($1,$2,$3,'RECOVERY_SECURITY')",[x.tenant_id,x.incident_id,x.category]);
  const after=await readSecurityInventory(c),remaining=recoveryPlan(after,authoritative);
  // Fresh invalidation cutoffs created by membership/status replay may exceed
  // the authoritative cutoff and are intentionally never decreased.
  if(Object.values(remaining).some(x=>x.length))throw Error("Recovery state did not reconcile");
  await c.query("COMMIT");return Object.fromEntries(Object.entries(plan).map(([k,v])=>[k,v.length]));
 }catch(e){try{await c.query("ROLLBACK");}catch{discard=true;}throw e;}
 finally{c.release(discard);}
}
async function archiveDigest(path){const h=createHash("sha256");for await(const chunk of createReadStream(path))h.update(chunk);return h.digest("hex");}
function connection(env,role,urlValue){
 if(env.NODE_TLS_REJECT_UNAUTHORIZED==="0"||env.PGOPTIONS||env.PGSERVICE||env.PGSERVICEFILE||env.PGSSLCERT||env.PGSSLKEY||env.PGSSLROOTCERT)throw Error("Unsafe recovery connection configuration");
 const url=new URL(urlValue||"");
 if(!["postgres:","postgresql:"].includes(url.protocol)||decodeURIComponent(url.username)!==role||decodeURIComponent(url.password).length<24||url.search||url.hash||!url.hostname||!url.pathname.slice(1)||!env.SECURITY_RECOVERY_CA)throw Error("Verified TLS recovery connection required");
 return new pg.Pool({connectionString:url.href,ssl:{ca:env.SECURITY_RECOVERY_CA,rejectUnauthorized:true},max:1,statement_timeout:30000,connectionTimeoutMillis:5000});
}
async function main(){
 const [mode,archive,path,...extra]=process.argv.slice(2),env=process.env;
 if(extra.length||!archive||!path||!["sign","replay"].includes(mode))throw Error("Invalid recovery operation");
 const backupSha256=await archiveDigest(archive);
 if(mode==="sign"){
  if(env.SECURITY_RECOVERY_SOURCE_FROZEN!=="yes")throw Error("Require frozen authoritative source");
  const db=connection(env,"profitpilot_recovery_reader",env.SECURITY_RECOVERY_READER_URL);
  try{
   const doc=signSecurityRecovery(await readSecurityInventory(db),backupSha256,env.SECURITY_RECOVERY_PRIVATE_KEY);
   const raw=JSON.stringify(doc)+"\n";if(Buffer.byteLength(raw)>MAX_BYTES)throw Error("Recovery inventory too large");
   writeFileSync(path,raw,{flag:"wx",mode:0o600});
   process.stdout.write(JSON.stringify({event:"security_recovery_signed",manifestSha256:securityRecoveryDigest(doc)})+"\n");
  }finally{await db.end();}
 }else{
  if(env.SECURITY_RECOVERY_TARGET_ISOLATED!=="yes")throw Error("Require isolated recovery target");
  const st=lstatSync(path);if(!st.isFile()||st.size<1||st.size>MAX_BYTES)throw Error("Invalid recovery document size");
  const raw=readFileSync(path,"utf8"),doc=JSON.parse(raw);if(raw!==JSON.stringify(doc)+"\n")throw Error("Noncanonical document");
  const binding={backupSha256,expectedManifestSha256:env.SECURITY_RECOVERY_EXPECTED_SHA256};
  verifySecurityRecovery(doc,env.SECURITY_RECOVERY_PUBLIC_KEY,binding);
  const db=connection(env,"profitpilot_admin",env.SECURITY_RECOVERY_TARGET_URL);
  try{process.stdout.write(JSON.stringify({event:"security_recovery_reconciled",...await replaySecurityRecovery(db,doc,env.SECURITY_RECOVERY_PUBLIC_KEY,binding)})+"\n");}finally{await db.end();}
 }
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(()=>{process.stderr.write("Security recovery failed; keep target isolated. Details suppressed.\n");process.exitCode=1;});

import {createHash,createPrivateKey,createPublicKey,sign,verify} from "node:crypto";

export const AUDIT_MAX_ROWS=10000;
const MAX_TOTAL_BYTES=16*1024*1024;
const HEX=/^[a-f0-9]{64}$/;
const UUID=/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/;
const TIMESTAMP=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/;
const ROW_FIELDS=["id","tenant_id","actor_user_id","action","object_type","object_id","reason","correlation_id","metadata","created_at"];
function hash(prefix,value){return createHash("sha256").update(prefix,"utf8").update(value).digest("hex");}
function fail(message){throw new Error("Invalid audit evidence: "+message);}
function validId(id){return typeof id==="string"&&UUID.test(id);}
function compareKey(a,b){return a.created_at===b.created_at?a.id.localeCompare(b.id):a.created_at.localeCompare(b.created_at);}
function canonicalRows(rows,tenant){
 if(!Array.isArray(rows)||rows.length>AUDIT_MAX_ROWS)fail("row limit exceeded");
 let bytes=0,previous=null;
 const unique=new Set();
 return rows.map(row=>{
  if(!row||typeof row!=="object"||Array.isArray(row)||Object.keys(row).length!==ROW_FIELDS.length||
   ROW_FIELDS.some(field=>!Object.hasOwn(row,field))||!validId(row.id)||row.tenant_id!==tenant||
   !TIMESTAMP.test(row.created_at)||!validId(row.tenant_id))fail("malformed row");
  for(const field of ROW_FIELDS){
   const value=row[field];
   if(value!==null&&typeof value!=="string")fail("unexpected field type");
   if(value!==null)bytes+=Buffer.byteLength(value,"utf8");
  }
  if(bytes>MAX_TOTAL_BYTES)fail("snapshot byte limit exceeded");
  if(unique.has(row.id)||(previous&&compareKey(previous,row)>=0))fail("duplicate or unsorted rows");
  unique.add(row.id);previous=row;
  return {id:row.id,createdAt:row.created_at,digest:hash("profitpilot.audit.entry.v1\n",JSON.stringify(ROW_FIELDS.map(field=>row[field])))};
 });
}
function chain(entries){
 let head="0".repeat(64);
 for(const entry of entries)head=hash("profitpilot.audit.chain.v1\n",head+"\n"+entry.digest);
 return head;
}
function assertEntries(entries){
 if(!Array.isArray(entries)||entries.length>AUDIT_MAX_ROWS)fail("invalid entry count");
 let prior=null;const ids=new Set();
 for(const e of entries){
  if(!e||typeof e!=="object"||Object.keys(e).sort().join()!=="createdAt,digest,id"||
   !validId(e.id)||!TIMESTAMP.test(e.createdAt)||!HEX.test(e.digest)||ids.has(e.id))fail("malformed entry");
  if(prior&&(prior.createdAt>e.createdAt||(prior.createdAt===e.createdAt&&prior.id>=e.id)))fail("entries not sorted");
  ids.add(e.id);prior=e;
 }
}
export function buildAuditManifest(tenantId,rows,{capturedAt=new Date().toISOString(),previousCheckpointDigest=null}={}){
 if(!validId(tenantId)||typeof capturedAt!=="string"||Number.isNaN(Date.parse(capturedAt))||
  (previousCheckpointDigest!==null&&!HEX.test(previousCheckpointDigest)))fail("manifest scope");
 const entries=canonicalRows(rows,tenantId);
 return {format:"profitpilot-audit-checkpoint-v1",tenantId,capturedAt,previousCheckpointDigest,
  count:entries.length,entries,headHash:chain(entries)};
}
function validateManifest(m){
 if(!m||typeof m!=="object"||Object.keys(m).sort().join()!=="capturedAt,count,entries,format,headHash,previousCheckpointDigest,tenantId"||
 m.format!=="profitpilot-audit-checkpoint-v1"||!validId(m.tenantId)||
 typeof m.capturedAt!=="string"||Number.isNaN(Date.parse(m.capturedAt))||
 !Number.isSafeInteger(m.count)||(m.previousCheckpointDigest!==null&&!HEX.test(m.previousCheckpointDigest))||
 !HEX.test(m.headHash))fail("manifest shape");
 assertEntries(m.entries);
 if(m.count!==m.entries.length||chain(m.entries)!==m.headHash)fail("manifest chain");
 return m;
}
function encodedManifest(m){return JSON.stringify(m);}
function spkiDigest(key){const pub=key?.type==="public"?key:createPublicKey(key);return createHash("sha256").update(pub.export({type:"spki",format:"der"})).digest("hex");}
export function signAuditManifest(manifest,pem){
 validateManifest(manifest);
 const key=pem?.type==="private"?pem:createPrivateKey(pem);
 if(key.asymmetricKeyType!=="ed25519")fail("Ed25519 signing key required");
 const body=Buffer.from(encodedManifest(manifest),"utf8");
 return {manifest,manifestDigest:hash("profitpilot.audit.manifest.v1\n",body),publicKeySha256:spkiDigest(key),
  signature:sign(null,body,key).toString("base64")};
}
export function verifyAuditCheckpoint(bundle,publicKey){
 if(!bundle||typeof bundle!=="object"||
 Object.keys(bundle).sort().join()!=="manifest,manifestDigest,publicKeySha256,signature")fail("bundle shape");
 const pub=publicKey?.type==="public"?publicKey:createPublicKey(publicKey);
 if(pub.asymmetricKeyType!=="ed25519")fail("Ed25519 public key required");
 const manifest=validateManifest(bundle.manifest);
 if(bundle.publicKeySha256!==spkiDigest(pub))fail("signer key mismatch");
 const body=Buffer.from(encodedManifest(manifest),"utf8");
 if(bundle.manifestDigest!==hash("profitpilot.audit.manifest.v1\n",body)||
 typeof bundle.signature!=="string"||!/^[A-Za-z0-9+/]+={0,2}$/.test(bundle.signature)||
 !verify(null,body,pub,Buffer.from(bundle.signature,"base64")))fail("signature invalid");
 return manifest;
}
export async function loadAuditRows(client,tenantId,cutoff=null){
 if(!validId(tenantId))fail("tenant UUID required");
 if(cutoff!==null&&(!validId(cutoff.id)||!TIMESTAMP.test(cutoff.createdAt)))fail("cutoff");
 const sql="SELECT id::text AS id, tenant_id::text AS tenant_id, actor_user_id::text AS actor_user_id, "+
  "action, object_type, object_id::text AS object_id, reason, correlation_id::text AS correlation_id, "+
  "metadata::text AS metadata, to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS created_at "+
  "FROM public.audit_events WHERE tenant_id=$1 "+
  (cutoff===null?"":"AND (created_at,id)<=($2::timestamptz,$3::uuid) ")+
  "ORDER BY created_at,id LIMIT "+(AUDIT_MAX_ROWS+1);
 const r=await client.query(sql,cutoff===null?[tenantId]:[tenantId,cutoff.createdAt,cutoff.id]);
 if(r.rows.length>AUDIT_MAX_ROWS)fail("tenant audit exceeds 10,000 rows; requires a reviewed paginated protocol");
 return r.rows;
}
// A successor must preserve every signed historic event, not merely link to an
// arbitrary file. Only a separately entrusted public key makes this meaningful.
export function assertCheckpointPrefix(bundle,publicKey,rows){
 const m=verifyAuditCheckpoint(bundle,publicKey);
 const actual=canonicalRows(rows,m.tenantId);
 if(actual.length<m.entries.length)fail("historic checkpoint entries omitted");
 for(let i=0;i<m.entries.length;i++){
  const expected=m.entries[i],found=actual[i];
  if(found.id!==expected.id||found.createdAt!==expected.createdAt||found.digest!==expected.digest)
   fail("historic audit prefix changed or backdated");
 }
 return true;
}
export function checkpointDigest(bundle,publicKey){
 verifyAuditCheckpoint(bundle,publicKey);
 return createHash("sha256").update(JSON.stringify(bundle),"utf8").digest("hex");
}
export function assertCheckpointSuccessor(previous,next,publicKey){
 const old=verifyAuditCheckpoint(previous,publicKey);
 const current=verifyAuditCheckpoint(next,publicKey);
 if(current.tenantId!==old.tenantId||current.previousCheckpointDigest!==checkpointDigest(previous,publicKey)||
  Date.parse(current.capturedAt)<Date.parse(old.capturedAt)||current.count<old.count)
  fail("checkpoint linkage, tenant or time invalid");
 for(let i=0;i<old.count;i++){
  const expected=old.entries[i],found=current.entries[i];
  if(found.id!==expected.id||found.createdAt!==expected.createdAt||found.digest!==expected.digest)
   fail("signed historical prefix altered");
 }
 return true;
}
export function assertCheckpointMatchesRows(bundle,publicKey,rows){
 const m=verifyAuditCheckpoint(bundle,publicKey);
 const actual=buildAuditManifest(m.tenantId,rows,{capturedAt:m.capturedAt,previousCheckpointDigest:m.previousCheckpointDigest});
 if(encodedManifest(actual)!==encodedManifest(m))fail("database historical prefix differs from independently signed checkpoint");
 return true;
}

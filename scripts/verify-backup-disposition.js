// Offline verifier only. Never deletes, releases holds or authorises disposal.
// The expected plan and trust pins must be independently obtained from
// authoritative custody. Signed claims do not independently prove destruction.
import {createHash,createPublicKey,verify} from "node:crypto";
const ROLES=Object.freeze(["counsel","custodian","assessor","owner"]);
const KINDS=["backup","snapshot","replica","export","subprocessor"];
const METHODS=["media_sanitisation","cryptographic_erasure","provider_verified_deletion"];
const exact=(x,keys)=>x!==null&&typeof x==="object"&&!Array.isArray(x)&&Object.keys(x).length===keys.length&&keys.every(k=>Object.hasOwn(x,k));
const hex=x=>typeof x==="string"&&/^[a-f0-9]{64}$/.test(x)&&!/^0+$/.test(x);
const uuid=x=>typeof x==="string"&&/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(x)&&!/^0{8}-0{4}-0{4}-0{4}-0{12}$/.test(x);
const date=x=>typeof x==="string"&&/^\d{4}-\d{2}-\d{2}$/.test(x)&&Number.isFinite(Date.parse(x+"T00:00:00.000Z"))&&new Date(x+"T00:00:00.000Z").toISOString().slice(0,10)===x;
const iso=x=>typeof x==="string"&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(x)&&Number.isFinite(Date.parse(x))&&new Date(x).toISOString()===x;
const hash=x=>createHash("sha256").update(x).digest("hex");
const deny=()=>{throw Error("Backup disposition evidence denied");};
const bytes=x=>Buffer.from(JSON.stringify(x),"utf8");
function entries(rows,validate){
 if(!Array.isArray(rows)||rows.length<1||rows.length>256)deny();
 const result=rows.map(validate);
 if(result.some((r,i)=>i>0&&r[0]<=result[i-1][0]))deny(); // sorted, unique opaque copy IDs
 return result;
}
export function inventoryDigest(inventory){
 return hash(bytes(["profitpilot-copy-inventory-v1",entries(inventory,r=>{
  if(!exact(r,["copyId","kind","contentSha256","retainThrough"])||!hex(r.copyId)||!KINDS.includes(r.kind)||!hex(r.contentSha256)||!date(r.retainThrough))deny();
  return [r.copyId,r.kind,r.contentSha256,r.retainThrough];
 })]));
}
export function dispositionDigest(plan){
 return hash(bytes(["profitpilot-copy-disposition-v1",entries(plan,r=>{
  if(!exact(r,["copyId","method","authoritySha256"])||!hex(r.copyId)||!METHODS.includes(r.method)||!hex(r.authoritySha256))deny();
  return [r.copyId,r.method,r.authoritySha256];
 })]));
}
const RECORD=["format","tenantId","allocationRunId","receiptSha256","orderId","inventorySha256","dispositionSha256","checkedOn","issuedAt","expiresAt","receipts"];
const BINDING=["tenantId","allocationRunId","receiptSha256","orderId","inventorySha256","dispositionSha256","checkedOn"];
export function canonicalDisposalEvidence(r){
 if(!exact(r,RECORD)||r.format!=="profitpilot-backup-disposition-evidence-v1"||
 ![r.tenantId,r.allocationRunId,r.orderId].every(uuid)||![r.receiptSha256,r.inventorySha256,r.dispositionSha256].every(hex)||!date(r.checkedOn)||!iso(r.issuedAt)||!iso(r.expiresAt))deny();
 const receipts=entries(r.receipts,x=>{
  if(!exact(x,["copyId","method","completedAt","evidenceSha256","status"])||!hex(x.copyId)||!METHODS.includes(x.method)||!iso(x.completedAt)||!hex(x.evidenceSha256)||x.status!=="disposition-evidenced")deny();
  return [x.copyId,x.method,x.completedAt,x.evidenceSha256,x.status];
 });
 if(new Set(receipts.map(x=>x[3])).size!==receipts.length)deny();
 return bytes([r.format,...BINDING.map(k=>r[k]),r.issuedAt,r.expiresAt,receipts]);
}
function signature(s){
 if(typeof s!=="string"||!/^[A-Za-z0-9+/]{86}==$/.test(s))deny();
 const b=Buffer.from(s,"base64");
 if(b.length!==64||b.toString("base64")!==s)deny();
 return b;
}
export function verifyBackupDisposition({bundle,expected,inventory,plan,trust,evidence,now=Date.now()}){
 if(!exact(bundle,["record","signatures"])||!exact(expected,BINDING)||!exact(trust,ROLES)||!exact(bundle.signatures,ROLES)||!Number.isSafeInteger(now)||!(evidence instanceof Map))deny();
 const r=bundle.record,canonical=canonicalDisposalEvidence(r);
 if(BINDING.some(k=>r[k]!==expected[k])||inventoryDigest(inventory)!==expected.inventorySha256||dispositionDigest(plan)!==expected.dispositionSha256||inventory.length!==plan.length||inventory.length!==r.receipts.length||evidence.size!==inventory.length)deny();
 const issued=Date.parse(r.issuedAt),expires=Date.parse(r.expiresAt);
 // This is a time-bounded verification receipt, not ongoing disposal permission.
 if(issued>now||expires<=now||expires<=issued||expires-issued>86400000||r.issuedAt.slice(0,10)<r.checkedOn||now-issued>86400000)deny();
 let total=0;
 for(let i=0;i<inventory.length;i++){
  const x=inventory[i],p=plan[i],v=r.receipts[i];
  if(x.copyId!==p.copyId||x.copyId!==v.copyId||p.method!==v.method||v.completedAt.slice(0,10)<=x.retainThrough||v.completedAt.slice(0,10)<r.checkedOn||Date.parse(v.completedAt)>issued)deny();
  const proof=evidence.get(v.evidenceSha256);
  if(!Buffer.isBuffer(proof)||proof.length<1||proof.length>1048576||hash(proof)!==v.evidenceSha256)deny();
  total+=proof.length;if(total>16777216)deny();
 }
 const pins=new Set();
 for(const role of ROLES){
  const t=trust[role];
  if(!exact(t,["publicKey","fingerprint"])||!hex(t.fingerprint))deny();
  const k=t.publicKey?.type==="public"?t.publicKey:createPublicKey(t.publicKey);
  if(k.asymmetricKeyType!=="ed25519"||hash(k.export({type:"spki",format:"der"}))!==t.fingerprint||pins.has(t.fingerprint))deny();
  pins.add(t.fingerprint);
  if(!verify(null,canonical,k,signature(bundle.signatures[role])))deny();
 }
 return Object.freeze({status:"signed-evidence-verified",copies:inventory.length,authorizesDisposal:false,provesPhysicalErasure:false});
}

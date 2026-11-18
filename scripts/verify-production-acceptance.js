import {createHash,createPublicKey,verify} from "node:crypto";
import {readFileSync,statSync} from "node:fs";
import {pathToFileURL} from "node:url";
import {canonicalApproval,verifyAustralianRelease} from "./verify-australian-compliance.js";

export const RELEASE_GATES=Object.freeze(["INDEPENDENT_PENTEST","INDEPENDENT_RETEST","PRODUCTION_RECOVERY","IDENTITY_EDGE_LOAD","SCANNER_AND_ALERTS","PRIVACY_OPERATIONS","SIGNED_ARTIFACT"]);
const ROLES=Object.freeze(["assessor","operations","owner"]);
const exact=(x,keys)=>x!==null&&typeof x==="object"&&!Array.isArray(x)&&Object.keys(x).length===keys.length&&keys.every(k=>Object.hasOwn(x,k));
const hex=(x,n)=>typeof x==="string"&&x.length===n&&/^[0-9a-f]+$/.test(x)&&!/^0+$/.test(x);
const iso=x=>typeof x==="string"&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(x)&&Number.isFinite(Date.parse(x))&&new Date(x).toISOString()===x;
const deny=()=>{throw Error("Production acceptance denied");};
const hash=x=>createHash("sha256").update(x).digest("hex");
const asKey=x=>x?.type==="public"?x:createPublicKey(x);
const pin=k=>hash(k.export({type:"spki",format:"der"}));
function signature(s){
 if(typeof s!=="string"||!/^[A-Za-z0-9+/]{86}==$/.test(s))deny();
 const b=Buffer.from(s,"base64");if(b.length!==64||b.toString("base64")!==s)deny();return b;
}
export function legalApprovalDigest(bundle){
 if(!exact(bundle,["record","counselSignature","ownerSignature"]))deny();
 signature(bundle.counselSignature);signature(bundle.ownerSignature);
 return hash(JSON.stringify(["profitpilot-legal-bundle-v1",canonicalApproval(bundle.record).toString("base64"),bundle.counselSignature,bundle.ownerSignature]));
}
export function canonicalProductionAcceptance(r){
 if(!exact(r,["format","commit","scopeSha256","manifestSha256","legalSha256","approvedAt","expiresAt","gates"])||
 r.format!=="profitpilot-production-acceptance-v1"||!hex(r.commit,40)||!hex(r.scopeSha256,64)||!hex(r.manifestSha256,64)||!hex(r.legalSha256,64)||
 !iso(r.approvedAt)||!iso(r.expiresAt)||!Array.isArray(r.gates)||r.gates.length!==RELEASE_GATES.length)deny();
 const gates=r.gates.map((g,i)=>{
  if(!exact(g,["id","status","evidenceSha256"])||g.id!==RELEASE_GATES[i]||g.status!=="approved"||!hex(g.evidenceSha256,64))deny();
  return [g.id,g.status,g.evidenceSha256];
 });
 if(new Set(gates.map(g=>g[2])).size!==gates.length)deny();
 return Buffer.from(JSON.stringify([r.format,r.commit,r.scopeSha256,r.manifestSha256,r.legalSha256,r.approvedAt,r.expiresAt,gates]),"utf8");
}
// The expected commit, configuration and actual verified manifest digest must
// come from a separately controlled release runner. Keys in the bundle are
// never trusted. Signature validation does not establish human independence.
export function verifyProductionAcceptance(bundle,expected,trust,now=Date.now()){
 if(!exact(bundle,["legal","record","signatures"])||!exact(expected,["commit","scopeSha256","manifestSha256"])||
 !exact(trust,["counsel","assessor","operations","owner"])||!exact(bundle.signatures,ROLES)||!Number.isFinite(now))deny();
 const keys={};
 for(const role of Object.keys(trust)){
  const t=trust[role];if(!exact(t,["key","fingerprint"])||!hex(t.fingerprint,64))deny();
  keys[role]=asKey(t.key);
  if(keys[role].type!=="public"||keys[role].asymmetricKeyType!=="ed25519"||pin(keys[role])!==t.fingerprint)deny();
 }
 if(new Set(Object.values(keys).map(pin)).size!==4)deny();
 if(!verifyAustralianRelease(bundle.legal,{commit:expected.commit,scopeSha256:expected.scopeSha256},{
  counselKey:keys.counsel,ownerKey:keys.owner,counselFingerprint:trust.counsel.fingerprint,ownerFingerprint:trust.owner.fingerprint
 },now))deny();
 const r=bundle.record,bytes=canonicalProductionAcceptance(r);
 if(r.commit!==expected.commit||r.scopeSha256!==expected.scopeSha256||r.manifestSha256!==expected.manifestSha256||
 r.legalSha256!==legalApprovalDigest(bundle.legal))deny();
 const from=Date.parse(r.approvedAt),until=Date.parse(r.expiresAt);
 if(from>now||until<=now||until<=from||until-from>30*86400000||
 from<Date.parse(bundle.legal.record.approvedAt)||until>Date.parse(bundle.legal.record.expiresAt))deny();
 for(const role of ROLES)if(!verify(null,bytes,keys[role],signature(bundle.signatures[role])))deny();
 return true;
}
export function checkProductionEvidenceFromEnvironment(manifestPath,env=process.env){
 if(!manifestPath||statSync(manifestPath).size>32768)deny();
 const manifestBytes=readFileSync(manifestPath);const m=JSON.parse(manifestBytes.toString("utf8"));
 if(m.repository!=="luxhustle01-ux/Profitpilot"||m.commit!==env.GITHUB_SHA||m.format!=="profitpilot-release-candidate-v1")deny();
 const supplied=env.PROFITPILOT_PRODUCTION_APPROVAL;
 if(typeof supplied!=="string"||Buffer.byteLength(supplied)>65536)deny();
 const trust={};for(const role of ["counsel",...ROLES])trust[role]={key:env["RELEASE_"+role.toUpperCase()+"_PUBLIC_KEY"],fingerprint:env["RELEASE_"+role.toUpperCase()+"_FINGERPRINT"]};
 return verifyProductionAcceptance(JSON.parse(supplied),{commit:env.GITHUB_SHA,scopeSha256:env.RELEASE_SCOPE_SHA256,manifestSha256:hash(manifestBytes)},trust);
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 try{
  if(process.argv.length!==3||!checkProductionEvidenceFromEnvironment(process.argv[2]))deny();
  console.log("Production acceptance evidence verified. Deployment and live activation remain disabled.");
 }catch{console.error("Production acceptance evidence DENIED");process.exitCode=1;}
}

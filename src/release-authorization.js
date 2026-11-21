// B13: offline, cryptographic two-role RELEASE REVIEW preflight only.
// Signatures are not evidence that independent testing, legal clearance,
// human identity, payment authority or a production deployment occurred.
import {createHash,createPublicKey,verify} from "node:crypto";

const own=(o,keys)=>o!==null&&typeof o==="object"&&!Array.isArray(o)&&
 Object.getPrototypeOf(o)===Object.prototype&&
 Object.keys(o).length===keys.length&&keys.every(k=>Object.hasOwn(o,k));
const sha40=x=>typeof x==="string"&&/^[a-f0-9]{40}$/.test(x);
const digest=x=>typeof x==="string"&&/^sha256:[a-f0-9]{64}$/.test(x);
const hex32=x=>typeof x==="string"&&/^[a-f0-9]{32}$/.test(x);
const textRef=x=>typeof x==="string"&&/^[a-zA-Z0-9][a-zA-Z0-9._:-]{2,79}$/.test(x);
const utc=x=>typeof x==="string"&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(x)&&
 Number.isFinite(Date.parse(x))&&new Date(Date.parse(x)).toISOString()===x;
const sha=b=>createHash("sha256").update(b).digest("hex");
const roles=["owner","independent-security-reviewer"];
const reviewEvidence=["penetrationTest","legalPrivacy","deviceAccessibility","recoveryOperations","ipLicensing"];
const requestKeys=["schema","repository","commitSha","apiImageDigest","protectedImageDigest",
 "sourceDossierDigest","ticket","nonce","issuedAt","expiresAt","purpose","evidenceDigests","noDeployment"];
const keyFields=["role","keyId","publicKeyPem"];
const approverKeys=["format","approvers"];
const signatureKeys=["role","keyId","signature"];

function publicKey(pem){
 if(typeof pem!=="string"||pem.length>2000)throw Error("Invalid pinned public key");
 const key=createPublicKey(pem);
 if(key.asymmetricKeyType!=="ed25519")throw Error("Ed25519 public key required");
 return key;
}
function fingerprint(key){return sha(key.export({format:"der",type:"spki"}));}
function decodeSignature(s){
 if(typeof s!=="string"||!/^[A-Za-z0-9+/]{86}==$/.test(s))throw Error("Canonical Ed25519 signature required");
 const b=Buffer.from(s,"base64");
 if(b.length!==64||b.toString("base64")!==s)throw Error("Invalid signature encoding");
 return b;
}
export function loadReleaseReviewPolicy(json){
 if(!own(json,approverKeys)||json.format!=="profitpilot.b13.pinned-reviewers.v1"||
  !Array.isArray(json.approvers)||json.approvers.length!==2)throw Error("Two pinned approvers required");
 const map=new Map(),ids=new Set(),fps=new Set();
 for(const a of json.approvers){
  if(!own(a,keyFields)||!roles.includes(a.role)||!textRef(a.keyId)||map.has(a.role)||ids.has(a.keyId))
   throw Error("Invalid or duplicate reviewer role/key ID");
  const key=publicKey(a.publicKeyPem),fp=fingerprint(key);
  if(fps.has(fp))throw Error("Both reviewer roles use the same signing key");
  map.set(a.role,{id:a.keyId,key,fp});ids.add(a.keyId);fps.add(fp);
 }
 if(map.size!==2)throw Error("Both reviewer roles are required");
 return map;
}
export function releaseReviewBytes(q){
 if(!own(q,requestKeys)||q.schema!=="profitpilot.b13.review-request.v1"||
  q.repository!=="SCSoftwareVentures/Profitpilot"||!sha40(q.commitSha)||
  !digest(q.apiImageDigest)||!digest(q.protectedImageDigest)||!digest(q.sourceDossierDigest)||
  q.apiImageDigest===q.protectedImageDigest||!textRef(q.ticket)||!hex32(q.nonce)||
  !utc(q.issuedAt)||!utc(q.expiresAt)||
  q.purpose!=="source-candidate-independent-review"||q.noDeployment!==true||
  !own(q.evidenceDigests,reviewEvidence)||
  reviewEvidence.some(k=>!digest(q.evidenceDigests[k])))
  throw Error("Invalid or incomplete release review request");
 return Buffer.from(JSON.stringify(["ProfitPilot/B13/release-review/v1",
  ...requestKeys.slice(0,-2).map(k=>q[k]),
  q.purpose,reviewEvidence.map(k=>q.evidenceDigests[k]),q.noDeployment]),"utf8");
}
export function verifyReleaseReview(bundle,policy,expected,now=Date.now()){
 if(!own(bundle,["request","signatures"])||!Array.isArray(bundle.signatures)||
   bundle.signatures.length!==2||!(policy instanceof Map)||!expected||
   !Number.isFinite(now))throw Error("Invalid release review bundle");
 const q=bundle.request,body=releaseReviewBytes(q);
 for(const field of ["repository","commitSha","apiImageDigest","protectedImageDigest","sourceDossierDigest","ticket"])
  if(q[field]!==expected[field])throw Error("Release review is not bound to requested "+field);
 const start=Date.parse(q.issuedAt),end=Date.parse(q.expiresAt);
 if(start>now+30000||now-start>3600000||end<=now||end<=start||end-start>3600000)
  throw Error("Release review expired or outside short-lived window");
 const used=new Set(),keys=new Set(),proof=[];
 for(const item of bundle.signatures){
  if(!own(item,signatureKeys)||!roles.includes(item.role)||used.has(item.role))
   throw Error("Invalid or duplicated review signature role");
  const p=policy.get(item.role);
  if(!p||p.id!==item.keyId||keys.has(p.fp)||!verify(null,body,p.key,decodeSignature(item.signature)))
   throw Error("Unknown reviewer key or invalid signature");
  used.add(item.role);keys.add(p.fp);
  proof.push({role:item.role,keyId:p.id,publicKeyFingerprint:p.fp});
 }
 if(used.size!==2)throw Error("Both reviewer signatures required");
 return Object.freeze({
  schema:"profitpilot.b13.verified-review.v1",
  repository:q.repository,sourceCommit:q.commitSha,ticket:q.ticket,
  signedEvidenceDigests:{...q.evidenceDigests},
  signedProofDigest:sha(Buffer.from(JSON.stringify([sha(body),
   proof.sort((a,b)=>a.role.localeCompare(b.role))]),"utf8")),
  signers:proof,
  cryptographicSignaturesVerified:true,
  independentHumanIdentityVerified:false,
  externalEvidenceIndependentlyAssessed:false,
  productionReleaseApproved:false,
  deploymentAuthorized:false,
  actualBuyerDemandVerified:false
 });
}

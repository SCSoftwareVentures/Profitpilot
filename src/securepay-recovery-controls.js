// S11.3 synthetic-only offline recovery authorisation and signed audit receipts.
// Signatures prove possession of configured keys, NOT human identity, legal authority or hold clearance.
import {createHash,createPublicKey,createPrivateKey,sign,verify} from "node:crypto";
const uuid=x=>typeof x==="string"&&/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(x);
const keyId=x=>typeof x==="string"&&/^[a-zA-Z0-9][a-zA-Z0-9._:-]{2,63}$/.test(x);
const ticket=x=>typeof x==="string"&&/^[a-zA-Z0-9][a-zA-Z0-9._:-]{2,79}$/.test(x);
const hex64=x=>typeof x==="string"&&/^[a-f0-9]{64}$/.test(x);
const sha=x=>createHash("sha256").update(x).digest("hex");
const shape=(obj,keys)=>obj!==null&&typeof obj==="object"&&!Array.isArray(obj)&&
 Object.keys(obj).length===keys.length&&keys.every(x=>Object.hasOwn(obj,x));
const expectedRequest=["version","tenantId","operatorId","ticketRef","requestId","issuedAt","expiresAt",
 "purpose","legalHoldState","retentionStatus","syntheticOnly"];
const expectedEvent=["schema","sequence","recordedAt","tenantId","operatorReportedId","operatorReportedTicket",
 "approvalRequestId","approvalProofDigest","approvalKeyIds","legalHoldState",
 "operatorIdentityIndependentlyVerified","approverIdentityIndependentlyVerified","externallyWitnessed",
 "primaryDbMutated","plaintextExported","outcome","reason","recovery"];
const roles=["custodian","privacy-reviewer"];

function publicKeyObject(pem){
 const key=pem?.type==="public"?pem:createPublicKey(pem);
 if(key.asymmetricKeyType!=="ed25519")throw Error("Ed25519 public key required");
 return key;
}
const fingerprint=k=>sha(publicKeyObject(k).export({type:"spki",format:"der"}));
function signatureBytes(value){
 if(typeof value!=="string"||!/^[A-Za-z0-9+/]{86}==$/.test(value))
  throw Error("Canonical Ed25519 signature required");
 const decoded=Buffer.from(value,"base64");
 if(decoded.length!==64||decoded.toString("base64")!==value)throw Error("Malformed signature");
 return decoded;
}
export function loadRecoveryApproverPolicy(data){
 if(!shape(data,["format","approvers"])||data.format!=="profitpilot.s11.3.approvers.v1"||
  !Array.isArray(data.approvers)||data.approvers.length!==2)
  throw Error("Two pinned recovery approvers required");
 const result=new Map(),fingerprints=new Set();
 for(const a of data.approvers){
  if(!shape(a,["role","keyId","publicKeyPem"])||!roles.includes(a.role)||!keyId(a.keyId)||
   typeof a.publicKeyPem!=="string"||a.publicKeyPem.length>2000||result.has(a.role))
   throw Error("Invalid or duplicate recovery approval role");
  const key=publicKeyObject(a.publicKeyPem),fp=fingerprint(key);
  if(fingerprints.has(fp))throw Error("Same signing key cannot approve both roles");
  fingerprints.add(fp);result.set(a.role,{keyId:a.keyId,key});
 }
 if(result.size!==2||result.get("custodian").keyId===result.get("privacy-reviewer").keyId)
  throw Error("Distinct custody and privacy reviewer keys required");
 return result;
}
export function recoveryApprovalBytes(req){
 if(!shape(req,expectedRequest)||req.version!=="profitpilot.s11.3.request.v1"||
  !uuid(req.tenantId)||!uuid(req.operatorId)||!uuid(req.requestId)||!ticket(req.ticketRef)||
  req.purpose!=="synthetic-offline-integrity-rehearsal"||
  !["no_declared_hold","active_hold","unknown"].includes(req.legalHoldState)||
  req.retentionStatus!=="unverified_review_only"||req.syntheticOnly!==true||
  typeof req.issuedAt!=="string"||typeof req.expiresAt!=="string"||
  !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(req.issuedAt)||
  !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(req.expiresAt)||
  !Number.isFinite(Date.parse(req.issuedAt))||!Number.isFinite(Date.parse(req.expiresAt)))
  throw Error("Invalid synthetic recovery request");
 return Buffer.from(JSON.stringify(["ProfitPilot/S11.3/approval/v1",
  ...expectedRequest.map(field=>req[field])]),"utf8");
}
// Signing helper is test/tooling only: no private key accepted over an HTTP API.
export function signRecoveryApprovalRequest(request,privateKey){
 const key=privateKey?.type==="private"?privateKey:createPrivateKey(privateKey);
 if(key.asymmetricKeyType!=="ed25519")throw Error("Ed25519 signing key required");
 return sign(null,recoveryApprovalBytes(request),key).toString("base64");
}
export function verifyRecoveryApproval(bundle,policy,scope,now=Date.now()){
 if(!shape(bundle,["request","signatures"])||!Array.isArray(bundle.signatures)||
  bundle.signatures.length!==2||!(policy instanceof Map)||!scope||
  !Number.isFinite(now))throw Error("Invalid approval bundle");
 const q=bundle.request,body=recoveryApprovalBytes(q);
 if(q.tenantId!==scope.tenantId||q.operatorId!==scope.operatorId||
  q.ticketRef!==scope.ticketRef||q.legalHoldState!=="no_declared_hold")
  throw Error("Recovery scope or declared legal hold blocks approval");
 const start=Date.parse(q.issuedAt),end=Date.parse(q.expiresAt);
 if(start>now+30000||end<=now||end<=start||end-start>3600000||
  now-start>3600000)throw Error("Approval expired, premature or overbroad");
 const used=new Set(),usedKeys=new Set(),signerIds=[];
 for(const entry of bundle.signatures){
  if(!shape(entry,["role","keyId","signature"])||!roles.includes(entry.role)||used.has(entry.role))
   throw Error("Duplicate or invalid approval role");
  const pinned=policy.get(entry.role);
  if(!pinned||pinned.keyId!==entry.keyId||usedKeys.has(entry.keyId)||
   !verify(null,body,pinned.key,signatureBytes(entry.signature)))
   throw Error("Untrusted or invalid approval signature");
  used.add(entry.role);usedKeys.add(entry.keyId);signerIds.push(entry.keyId);
 }
 if(used.size!==2)throw Error("Both independently keyed approval roles required");
 return {requestId:q.requestId,proofDigest:sha(Buffer.from(JSON.stringify([
  "ProfitPilot/S11.3/approval-proof/v1",sha(body),
  [...bundle.signatures].sort((a,b)=>a.role.localeCompare(b.role))
 ]))),signerIds:signerIds.sort(),legalHoldState:q.legalHoldState};
}
const validSummary=x=>shape(x,["schema","tenantId","receivedEncryptedCount","verifiedCount",
 "aggregateSha256","plaintextExposed","operatorScanIndependent","storageOriginIndependent",
 "legalRetentionVerified","paymentAuthority","decisionAuthority"])&&
 x.schema==="profitpilot.s11.2.synthetic.restore.v1"&&uuid(x.tenantId)&&
 Number.isSafeInteger(x.receivedEncryptedCount)&&x.receivedEncryptedCount>=1&&
 x.receivedEncryptedCount<=64&&x.verifiedCount===x.receivedEncryptedCount&&
 hex64(x.aggregateSha256)&&["plaintextExposed","operatorScanIndependent","storageOriginIndependent",
 "legalRetentionVerified","paymentAuthority","decisionAuthority"].every(field=>x[field]===false);
const auditBody=(event,prevDigest)=>{
 if(!shape(event,expectedEvent)||event.schema!=="profitpilot.s11.3.restore-audit.v1"||
  !Number.isSafeInteger(event.sequence)||event.sequence<1||
  !Number.isFinite(Date.parse(event.recordedAt))||
  !uuid(event.tenantId)||!uuid(event.operatorReportedId)||!ticket(event.operatorReportedTicket)||
  (event.approvalRequestId!==null&&!uuid(event.approvalRequestId))||
  (event.approvalProofDigest!==null&&!hex64(event.approvalProofDigest))||
  !Array.isArray(event.approvalKeyIds)||event.approvalKeyIds.length>2||
  event.approvalKeyIds.some(x=>!keyId(x))||
  !["no_declared_hold","active_hold","unknown",null].includes(event.legalHoldState)||
  ["operatorIdentityIndependentlyVerified","approverIdentityIndependentlyVerified","externallyWitnessed",
   "primaryDbMutated","plaintextExported"].some(k=>event[k]!==false)||
  !["rejected","verified_synthetic_recovery"].includes(event.outcome)||
  !["offline_rehearsal_denied",null].includes(event.reason)||
  (event.outcome==="rejected"&&(event.reason===null||event.recovery!==null))||
  (event.outcome==="verified_synthetic_recovery"&&(
   event.reason!==null||!validSummary(event.recovery)||event.recovery.tenantId!==event.tenantId||
   event.approvalKeyIds.length!==2||event.legalHoldState!=="no_declared_hold"||
   !hex64(event.approvalProofDigest)||!uuid(event.approvalRequestId)))||
  (prevDigest!==null&&!hex64(prevDigest)))
  throw Error("Invalid synthetic recovery audit shape");
 return Buffer.from(JSON.stringify(["ProfitPilot/S11.3/audit/v1",prevDigest,
  expectedEvent.map(k=>event[k])]),"utf8");
}
export function signRecoveryAudit(event,prevDigest,signingKey){
 const key=signingKey?.type==="private"?signingKey:createPrivateKey(signingKey);
 if(key.asymmetricKeyType!=="ed25519")throw Error("Ed25519 audit key required");
 const bytes=auditBody(event,prevDigest);
 return {event,previousDigest:prevDigest,bodyDigest:sha(bytes),
  signerPublicKeySha256:fingerprint(createPublicKey(key)),
  signature:sign(null,bytes,key).toString("base64")};
}
export function verifyRecoveryAudit(bundle,publicKey,expectedPreviousDigest){
 if(!shape(bundle,["event","previousDigest","bodyDigest","signerPublicKeySha256","signature"]))
  throw Error("Invalid audit receipt envelope");
 const publicKeyObj=publicKeyObject(publicKey),bytes=auditBody(bundle.event,bundle.previousDigest);
 if(bundle.previousDigest!==expectedPreviousDigest||bundle.bodyDigest!==sha(bytes)||
  bundle.signerPublicKeySha256!==fingerprint(publicKeyObj)||
  !verify(null,bytes,publicKeyObj,signatureBytes(bundle.signature)))
  throw Error("Audit continuity or signature invalid");
 return sha(Buffer.from(JSON.stringify(bundle),"utf8"));
}

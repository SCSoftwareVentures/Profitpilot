// Offline, bounded signed acknowledgement. No transport or actual delivery claim.
// Expected release and signing-key pins MUST come from independent trusted custody.
import {createHash,createPublicKey,randomBytes,sign,verify} from "node:crypto";
import {openPrivacyResponse,privacyKeyFingerprint} from "./privacy-response-envelope.js";
const F="profitpilot-privacy-receipt-challenge-v1",R="profitpilot-privacy-receipt-v1";
const B=["tenantId","caseId","orderId","scopeSha256","envelopeSha256","responseSha256","recipientKeySha256","senderKeySha256","recipientSigningKeySha256","authorizedAt"];
const C=[...B,"nonce","issuedAt","expiresAt"];
const exact=(x,k)=>x!==null&&typeof x==="object"&&!Array.isArray(x)&&Object.keys(x).length===k.length&&k.every(y=>Object.hasOwn(x,y));
const hex=x=>typeof x==="string"&&/^[a-f0-9]{64}$/.test(x)&&!/^0+$/.test(x);
const uuid=x=>typeof x==="string"&&/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(x);
const iso=x=>typeof x==="string"&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(x)&&Number.isFinite(Date.parse(x))&&new Date(x).toISOString()===x;
const bytes=x=>Buffer.from(JSON.stringify(x),"utf8");
const hash=x=>createHash("sha256").update(x).digest("hex");
const deny=()=>{throw Error("Privacy receipt evidence denied");};
const validNow=n=>Number.isSafeInteger(n)&&n>0&&n<8640000000000000;
function binding(x){
 if(!exact(x,B)||![x.tenantId,x.caseId,x.orderId].every(uuid)||!B.slice(3,-1).every(k=>hex(x[k]))||!iso(x.authorizedAt)||new Set([x.recipientKeySha256,x.senderKeySha256,x.recipientSigningKeySha256]).size!==3)deny();
}
function key(k,fingerprint){
 if(k?.type!=="public"||k.asymmetricKeyType!=="ed25519"||privacyKeyFingerprint(k)!==fingerprint)deny();
 return k;
}
function sig(s){
 if(typeof s!=="string"||!/^[A-Za-z0-9+/]{86}==$/.test(s))deny();
 const b=Buffer.from(s,"base64");if(b.length!==64||b.toString("base64")!==s)deny();return b;
}
function challengeBytes(c){return bytes([F,...C.map(k=>c[k])]);}
function inspectChallenge(challenge,expected,sender,now){
 binding(expected);
 if(!validNow(now)||!exact(challenge,["record","signature"])||!exact(challenge.record,C))deny();
 const c=challenge.record;
 if(B.some(k=>c[k]!==expected[k])||!hex(c.nonce)||!iso(c.issuedAt)||!iso(c.expiresAt))deny();
 const start=Date.parse(c.authorizedAt),issued=Date.parse(c.issuedAt),expires=Date.parse(c.expiresAt);
 if(issued<start||issued-start>900000||issued>now||expires<=issued||expires-issued>900000||now>expires+86400000)deny();
 if(!verify(null,challengeBytes(c),key(sender,expected.senderKeySha256),sig(challenge.signature)))deny();
 return {digest:hash(bytes([F,...C.map(k=>c[k]),challenge.signature])),issued,expires};
}
export function issuePrivacyReceiptChallenge(expected,senderPrivateKey,now=Date.now()){
 binding(expected);
 if(!validNow(now)||senderPrivateKey?.type!=="private"||senderPrivateKey.asymmetricKeyType!=="ed25519")deny();
 key(createPublicKey(senderPrivateKey),expected.senderKeySha256);
 const authorized=Date.parse(expected.authorizedAt);
 if(now<authorized||now-authorized>900000)deny();
 const record={...expected,nonce:randomBytes(32).toString("hex"),issuedAt:new Date(now).toISOString(),expiresAt:new Date(now+900000).toISOString()};
 return {record,signature:sign(null,challengeBytes(record),senderPrivateKey).toString("base64")};
}
function receiptBytes(r){return bytes([R,r.challengeSha256,r.acknowledgedAt]);}
// Helper only signs after successful authenticated decryption. A signature
// obtained elsewhere is a statement by the signer, not independent proof of reading.
export function openAndAcknowledgePrivacyResponse({challenge,expected,envelope,recipientPrivateKey,recipientSigningPrivateKey,senderPublicKey,now=Date.now()}){
 const c=inspectChallenge(challenge,expected,senderPublicKey,now);
 if(now>=c.expires||recipientSigningPrivateKey?.type!=="private"||recipientSigningPrivateKey.asymmetricKeyType!=="ed25519")deny();
 key(createPublicKey(recipientSigningPrivateKey),expected.recipientSigningKeySha256);
 const ctx=Object.fromEntries(["tenantId","caseId","orderId","recipientKeySha256","senderKeySha256","responseSha256"].map(k=>[k,expected[k]]));
 const response=openPrivacyResponse(envelope,ctx,expected.envelopeSha256,recipientPrivateKey,senderPublicKey);
 try{
  const record={challengeSha256:c.digest,acknowledgedAt:new Date(now).toISOString()};
  return {record,signature:sign(null,receiptBytes(record),recipientSigningPrivateKey).toString("base64")};
 }finally{response.fill(0);}
}
export function verifyPrivacyReceipt({challenge,receipt,expected,senderPublicKey,recipientSigningPublicKey,now=Date.now()}){
 const c=inspectChallenge(challenge,expected,senderPublicKey,now);
 if(!exact(receipt,["record","signature"])||!exact(receipt.record,["challengeSha256","acknowledgedAt"]))deny();
 const r=receipt.record;
 if(r.challengeSha256!==c.digest||!iso(r.acknowledgedAt))deny();
 const at=Date.parse(r.acknowledgedAt);
 if(at<c.issued||at>=c.expires||at>now||now-at>86400000)deny();
 if(!verify(null,receiptBytes(r),key(recipientSigningPublicKey,expected.recipientSigningKeySha256),sig(receipt.signature)))deny();
 return Object.freeze({status:"recipient-signature-verified",challengeDigest:c.digest,receiptDigest:hash(bytes([R,r.challengeSha256,r.acknowledgedAt,receipt.signature])),receiptKeyDigest:expected.recipientSigningKeySha256,deliveryVerified:false});
}

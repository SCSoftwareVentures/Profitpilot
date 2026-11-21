import {createHash,createPublicKey,verify as cryptoVerify} from "node:crypto";
// Ed25519 verifies control of a SELF-SUPPLIED key. No trust anchor or party identity.
const uuid=x=>typeof x==="string"&&/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(x);
const ref=x=>typeof x==="string"&&/^[A-Za-z0-9][A-Za-z0-9._:-]{2,119}$/.test(x);
const hex=x=>typeof x==="string"&&/^[a-f0-9]{64}$/.test(x);
const b64=x=>typeof x==="string"&&/^[A-Za-z0-9_-]+$/.test(x);
const prefix=Buffer.from("302a300506032b6570032100","hex");
const fields=["clientRequestId","provenanceReceiptId","claimedPartyRole","keySpki",
 "nonce","claimedContentSha256","signature"];
const statementKeys=["tenantId","caseId","evidenceId","provenanceReceiptId",
 "provenanceMetadataSha256","jobReference","evidenceType","evidenceReference",
 "claimedPartyRole","claimedContentSha256","nonce"];
export function validSignedPartyClaim(b){
 return b!==null&&typeof b==="object"&&!Array.isArray(b)&&
 Object.keys(b).length===fields.length&&fields.every(k=>Object.hasOwn(b,k))&&
 uuid(b.clientRequestId)&&uuid(b.provenanceReceiptId)&&uuid(b.nonce)&&
 ["customer","tradesperson"].includes(b.claimedPartyRole)&&
 b64(b.keySpki)&&b.keySpki.length===59&&b64(b.signature)&&b.signature.length===86&&
 hex(b.claimedContentSha256);
}
export function signedPartyStatement(o){
 if(!o||!statementKeys.every(k=>typeof o[k]==="string")||
 !["tenantId","caseId","evidenceId","provenanceReceiptId","nonce"].every(k=>uuid(o[k]))||
 !hex(o.provenanceMetadataSha256)||!hex(o.claimedContentSha256)||
 !ref(o.jobReference)||!ref(o.evidenceReference)||
 !["claim_reported","business_response_reported"].includes(o.evidenceType)||
 !["customer","tradesperson"].includes(o.claimedPartyRole)||
 (o.claimedPartyRole==="customer"&&o.evidenceType!=="claim_reported")||
 (o.claimedPartyRole==="tradesperson"&&o.evidenceType!=="business_response_reported"))
  throw new TypeError("Invalid synthetic signed party statement");
 return Buffer.from(JSON.stringify(["securepay-s6-party-job-claim-v1",...statementKeys.map(k=>o[k])]),"utf8");
}
export function checkSignedPartyClaim(o,keySpki,signature){
 const statement=signedPartyStatement(o);
 if(!b64(keySpki)||keySpki.length!==59||!b64(signature)||signature.length!==86)
  throw new TypeError("Invalid Ed25519 encoded key or signature");
 const der=Buffer.from(keySpki,"base64url"),sig=Buffer.from(signature,"base64url");
 if(der.length!==44||!der.subarray(0,prefix.length).equals(prefix)||sig.length!==64||
 der.toString("base64url")!==keySpki||sig.toString("base64url")!==signature)
  throw new TypeError("Noncanonical Ed25519 key or signature");
 const key=createPublicKey({key:der,format:"der",type:"spki"});
 if(key.asymmetricKeyType!=="ed25519")throw new TypeError("Ed25519 key required");
 return {signatureValid:cryptoVerify(null,statement,key,sig),
  keySpkiSha256:createHash("sha256").update(der).digest("hex"),
  statementSha256:createHash("sha256").update(statement).digest("hex"),
  trustedIssuerVerified:false,partyIdentityVerified:false,partyToJobVerified:false,
  contentBytesVerified:false,decisionAuthority:false,paymentAuthority:false};
}
export function sameSignedClaim(row,b){
 return row?.provenance_receipt_id===b.provenanceReceiptId&&
  row?.claimed_party_role===b.claimedPartyRole&&row?.key_spki===b.keySpki&&
  row?.claim_nonce===b.nonce&&row?.claimed_content_sha256===b.claimedContentSha256&&
  row?.signature===b.signature;
}

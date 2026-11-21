// SP-S7: revocation terminates an OPERATOR-RECORDED synthetic claim.
// These labels do not claim authentication of the customer's real identity.
const uuid=x=>typeof x==="string"&&/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(x);
const ref=x=>typeof x==="string"&&/^[A-Za-z0-9][A-Za-z0-9._:-]{2,119}$/.test(x);
export const REVOCATION_REASONS=Object.freeze(["operator_withdrawal","suspected_key_compromise","provenance_disputed","administrative_hold"]);
export function validClaimRevocation(body){
 return body!==null&&typeof body==="object"&&!Array.isArray(body)&&
 Object.keys(body).length===3&&
 ["clientRequestId","reasonCode","revocationReference"].every(x=>Object.hasOwn(body,x))&&
 uuid(body.clientRequestId)&&REVOCATION_REASONS.includes(body.reasonCode)&&ref(body.revocationReference);
}
export function sameClaimRevocation(r,b,actor){
 return r?.client_request_id===b.clientRequestId&&r?.revoked_by===actor&&
 r?.reason_code===b.reasonCode&&r?.revocation_reference===b.revocationReference;
}
export function claimTrustStatus({revoked,signatureValid}){
 if(typeof revoked!=="boolean"||typeof signatureValid!=="boolean")
  throw new TypeError("Explicit revocation and signature statuses required");
 return {status:revoked?"revoked":signatureValid?"untrusted_unverified":"invalid_signature",
  revoked,cryptographicSignatureValid:signatureValid,operationallyUsable:false,
  partyIdentityVerified:false,partyToJobVerified:false,contentBytesVerified:false,
  issuerTrusted:false,decisionAuthority:false,paymentAuthority:false,
  blockingGates:[
   ...(revoked?["synthetic_claim_revoked"]:[]),
   ...(!signatureValid?["cryptographic_signature_invalid"]:[]),
   "signer_key_not_anchored_to_verified_identity","party_job_authority_unverified",
   "content_bytes_unverified","independent_custody_unverified",
   "provider_and_legal_clearance_unverified"
  ]};
}

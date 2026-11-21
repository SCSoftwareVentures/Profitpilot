import test from "node:test";
import assert from "node:assert/strict";
import {validClaimRevocation,sameClaimRevocation,claimTrustStatus} from "../src/securepay-claim-revocation.js";
const id="11111111-1111-4111-8111-111111111111";
const b={clientRequestId:id,reasonCode:"suspected_key_compromise",revocationReference:"revocation.s7.001"};
test("revocation input is exact and cannot claim verified authority",()=>{
 assert.equal(validClaimRevocation(b),true);
 for(const bad of [{...b,paymentApproved:true},{...b,identityVerified:true},{...b,clientRequestId:"not-uuid"},
  {...b,reasonCode:"restore"},{...b,revocationReference:"invalid ref with space"},null,[],{}])
  assert.equal(validClaimRevocation(bad),false);
});
test("idempotent replay matches actor, reason and the original request UUID",()=>{
 const row={client_request_id:b.clientRequestId,revoked_by:id,
 reason_code:b.reasonCode,revocation_reference:b.revocationReference};
 assert.equal(sameClaimRevocation(row,b,id),true);
 assert.equal(sameClaimRevocation(row,{...b,reasonCode:"administrative_hold"},id),false);
 assert.equal(sameClaimRevocation(row,b,"22222222-2222-4222-8222-222222222222"),false);
});
test("revocation blocks use without rewriting cryptographic verification truth",()=>{
 const active=claimTrustStatus({revoked:false,signatureValid:true});
 assert.equal(active.status,"untrusted_unverified");
 assert.equal(active.operationallyUsable,false);
 const revoked=claimTrustStatus({revoked:true,signatureValid:true});
 assert.equal(revoked.status,"revoked");
 assert.equal(revoked.cryptographicSignatureValid,true);
 assert.equal(revoked.operationallyUsable,false);
 assert.ok(revoked.blockingGates.includes("synthetic_claim_revoked"));
 const damaged=claimTrustStatus({revoked:false,signatureValid:false});
 assert.equal(damaged.status,"invalid_signature");
 assert.throws(()=>claimTrustStatus({revoked:"no",signatureValid:true}),TypeError);
});

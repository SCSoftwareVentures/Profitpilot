import test from "node:test";
import assert from "node:assert/strict";
import {createHash,generateKeyPairSync,sign} from "node:crypto";
import {validSignedPartyClaim,signedPartyStatement,checkSignedPartyClaim,sameSignedClaim} from "../src/securepay-signed-party.js";
const {publicKey,privateKey}=generateKeyPairSync("ed25519");
const keySpki=publicKey.export({format:"der",type:"spki"}).toString("base64url");
const scope={tenantId:"11111111-1111-4111-8111-111111111111",caseId:"22222222-2222-4222-8222-222222222222",
 evidenceId:"33333333-3333-4333-8333-333333333333",provenanceReceiptId:"44444444-4444-4444-8444-444444444444",
 provenanceMetadataSha256:"a".repeat(64),jobReference:"job.s6.001",evidenceType:"claim_reported",
 evidenceReference:"claim.s6.001",claimedPartyRole:"customer",claimedContentSha256:createHash("sha256").update("unverified content").digest("hex"),
 nonce:"55555555-5555-4555-8555-555555555555"};
const signature=sign(null,signedPartyStatement(scope),privateKey).toString("base64url");
const request={clientRequestId:"66666666-6666-4666-8666-666666666666",provenanceReceiptId:scope.provenanceReceiptId,
 claimedPartyRole:"customer",keySpki,nonce:scope.nonce,claimedContentSha256:scope.claimedContentSha256,signature};
test("Ed25519 signature proves key possession but no real-world authority",()=>{
 assert.equal(validSignedPartyClaim(request),true);
 const r=checkSignedPartyClaim(scope,keySpki,signature);
 assert.equal(r.signatureValid,true);assert.match(r.statementSha256,/^[a-f0-9]{64}$/);
 assert.equal(r.partyIdentityVerified,false);assert.equal(r.partyToJobVerified,false);
 assert.equal(r.trustedIssuerVerified,false);assert.equal(r.contentBytesVerified,false);
 assert.equal(r.paymentAuthority,false);assert.equal(r.decisionAuthority,false);
});
test("signature fails when party role, job, provenance, content or tenant changes",()=>{
 for(const delta of [
  {tenantId:"77777777-7777-4777-8777-777777777777"},
  {jobReference:"another.job"},
  {provenanceMetadataSha256:"b".repeat(64)},
  {claimedContentSha256:"b".repeat(64)},
  {nonce:"88888888-8888-4888-8888-888888888888"},
  {evidenceReference:"another.evidence"}
 ]){
  assert.equal(checkSignedPartyClaim({...scope,...delta},keySpki,signature).signatureValid,false);
 }
 assert.throws(()=>signedPartyStatement({...scope,claimedPartyRole:"tradesperson"}),TypeError);
});
test("overspecified payload, invalid key encoding and replay mutation fail closed",()=>{
 for(const bad of [{...request,issuerTrusted:true},{...request,keySpki:"fake"},
  {...request,signature:"x".repeat(86)+"!"},{...request,claimedPartyRole:"verified_customer"},{...request,claimedContentSha256:"NOT_HASH"}])
  assert.equal(validSignedPartyClaim(bad),false);
 assert.throws(()=>checkSignedPartyClaim(scope,"A".repeat(59),signature),TypeError);
 const row={provenance_receipt_id:scope.provenanceReceiptId,claimed_party_role:"customer",
  key_spki:keySpki,claim_nonce:scope.nonce,claimed_content_sha256:scope.claimedContentSha256,signature};
 assert.equal(sameSignedClaim(row,request),true);
 assert.equal(sameSignedClaim(row,{...request,nonce:"99999999-9999-4999-8999-999999999999"}),false);
});

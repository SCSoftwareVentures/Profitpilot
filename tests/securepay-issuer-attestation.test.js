import test from "node:test";
import assert from "node:assert/strict";
import {issuerSettings,validateIssuerScope,validIssuerRequest} from "../src/securepay-issuer-attestation.js";
const now=Math.floor(Date.now()/1000);
const scope={tenantId:"11111111-1111-4111-8111-111111111111",caseId:"22222222-2222-4222-8222-222222222222",
 evidenceId:"33333333-3333-4333-8333-333333333333",claimId:"44444444-4444-4444-8444-444444444444",
 jobReference:"job.s8",claimedPartyRole:"customer",keySpkiSha256:"a".repeat(64)};
const token={...scope,iss:"https://issuer.invalid/",aud:"securepay-ci",sub:"opaque.subject.001",
 jti:"55555555-5555-4555-8555-555555555555",iat:now,nbf:now,exp:now+300,permission:"synthetic_job_claim_review_only"};
test("S8 issuer configuration must be independently pinned and safe",()=>{
 assert.throws(()=>issuerSettings({}),/not configured/);
 assert.throws(()=>issuerSettings({SECUREPAY_AUTHORITY_ISSUER:"https://issuer.invalid/",SECUREPAY_AUTHORITY_AUDIENCE:"securepay-ci",
 SECUREPAY_AUTHORITY_JWKS_URL:"http://public.invalid/jwks"}),/unsafe/);
 assert.throws(()=>issuerSettings({AUTH_ISSUER:"https://issuer.invalid/",SECUREPAY_AUTHORITY_ISSUER:"https://issuer.invalid/",
 SECUREPAY_AUTHORITY_AUDIENCE:"securepay-ci",SECUREPAY_AUTHORITY_JWKS_URL:"https://issuer.invalid/jwks"}),/unsafe/);
});
test("S8 strict claims reject wrong job, tenant, role, duration and extra PII",()=>{
 assert.equal(validateIssuerScope(token,scope,now),true);
 for(const bad of [{...token,tenantId:"66666666-6666-4666-8666-666666666666"}, {...token,jobReference:"forged.job"},
 {...token,claimedPartyRole:"tradesperson"},{...token,keySpkiSha256:"b".repeat(64)},
 {...token,email:"private@invalid"}, {...token,exp:now+601}, {...token,exp:now-1},
 {...token,permission:"release_payment"},{...token,sub:"with whitespace"}])
  assert.equal(validateIssuerScope(bad,scope,now),false);
});
test("S8 request cannot submit verified flags or malformed JWT",()=>{
 assert.equal(validIssuerRequest({clientRequestId:"77777777-7777-4777-8777-777777777777",attestationJwt:"abc.def.ghi"}),false);
 assert.equal(validIssuerRequest({clientRequestId:"77777777-7777-4777-8777-777777777777",attestationJwt:"a".repeat(100),verified:true}),false);
});

import test from "node:test";
import assert from "node:assert/strict";
import {assessSecurepayDecisionPreflight} from "../src/securepay-readiness.js";

const c={id:"11111111-1111-4111-8111-111111111111",status:"evidence_pending",
 synthetic:true,funds_moved:false,opened_by_requester:false};
const counts={total:0,claim_reports:0,business_reports:0,review_notes:0,externally_verified:0};

test("missing reports block preflight and never enable payment authority",()=>{
 const a=assessSecurepayDecisionPreflight(c,counts);
 assert.equal(a.decisionReadiness,"blocked");
 assert.equal(a.paymentAuthority,false);
 assert.equal(a.partyIdentityVerified,false);
 assert.ok(a.blockingGates.includes("matching_claim_report_missing"));
 assert.ok(a.blockingGates.includes("business_response_report_missing"));
});
test("all reported references remain unverified and cannot authorise a decision",()=>{
 const a=assessSecurepayDecisionPreflight(c,{total:3,claim_reports:1,business_reports:1,
  review_notes:1,externally_verified:0});
 assert.deepEqual(a.evidence,{totalOperatorReports:3,matchingClaimReported:true,
  businessResponseReported:true,operatorReviewNoteReported:true,externallyVerifiedCount:0});
 assert.equal(a.decisionReadiness,"blocked");
 assert.equal(a.decisionAuthority,false);
 assert.equal(a.fundsMoved,false);
 assert.ok(a.blockingGates.includes("customer_identity_unverified"));
 assert.ok(a.blockingGates.includes("independent_reviewer_unverified"));
});
test("case opener is not independently verified as a reviewer",()=>{
 const a=assessSecurepayDecisionPreflight({...c,opened_by_requester:true},counts);
 assert.equal(a.requesterOpenedCase,true);
 assert.ok(a.blockingGates.includes("requester_must_not_self_review"));
});
test("malformed or misleading case and counts fail closed",()=>{
 for(const bad of [{...c,synthetic:false},{...c,funds_moved:true},{...c,status:"decided"},
  {...c,opened_by_requester:"true"}])
  assert.throws(()=>assessSecurepayDecisionPreflight(bad,counts),TypeError);
 for(const bad of [{...counts,total:-1},{...counts,total:1,claim_reports:2},
  {...counts,externally_verified:1},{...counts,business_reports:"2"}])
  assert.throws(()=>assessSecurepayDecisionPreflight(c,bad),TypeError);
});

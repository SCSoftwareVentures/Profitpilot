import test from "node:test";
import assert from "node:assert/strict";
import {assessLeakCandidate} from "../src/profit-leak-radar.js";

const valid={id:"leak-001",kind:"unmatched_invoice",amount:"1850.00",currency:"AUD",taxBasis:"gst_exclusive",periodStart:"2026-11-01",periodEnd:"2026-11-30",sourceCoverage:"complete",evidenceRefs:["invoice-line-204"],summary:"Customer invoice line has no confirmed contract match",nextAction:"Review contract and service-period evidence"};

test("complete declared evidence produces a review candidate, never a verified loss",()=>{
  const result=assessLeakCandidate(valid);
  assert.equal(result.status,"candidate_for_human_review");
  assert.equal(result.candidateAmount,"1850.00");
  assert.equal(result.currency,"AUD");
  assert.equal(result.verifiedLoss,null);
  assert.equal(result.recoveredValue,null);
  assert.equal(result.humanReviewRequired,true);
});

test("partial or unknown source coverage withholds monetary exposure",()=>{
  for(const sourceCoverage of ["partial","unknown",undefined]){
    const result=assessLeakCandidate({...valid,sourceCoverage});
    assert.equal(result.status,"unverified");
    assert.equal(result.candidateAmount,null);
    assert.equal(result.currency,null);
    assert.equal(result.checks.sourceCoverage,false);
  }
});

test("missing evidence and incompatible reporting dimensions remain unverified",()=>{
  const noEvidence=assessLeakCandidate({...valid,evidenceRefs:[]});
  assert.equal(noEvidence.status,"unverified");
  assert.equal(noEvidence.candidateAmount,null);
  const mixedBasis=assessLeakCandidate({...valid,taxBasis:"unknown"});
  assert.equal(mixedBasis.status,"unverified");
  assert.equal(mixedBasis.candidateAmount,null);
  const badPeriod=assessLeakCandidate({...valid,periodStart:"2026-12-01",periodEnd:"2026-11-01"});
  assert.equal(badPeriod.status,"unverified");
});

test("invalid, zero and negative monetary values are never surfaced as candidate exposure",()=>{
  for(const amount of ["not-money","0.00","-10.00","1.234",1.5]){
    const result=assessLeakCandidate({...valid,amount});
    assert.equal(result.status,"unverified",String(amount));
    assert.equal(result.candidateAmount,null,String(amount));
  }
});

test("unknown leak types are unverified and malformed top-level input is rejected",()=>{
  assert.equal(assessLeakCandidate({...valid,kind:"fraud"}).status,"unverified");
  assert.throws(()=>assessLeakCandidate(null),/observation object/);
});

test("evidence identifiers are filtered and output always disclaims recovery",()=>{
  const result=assessLeakCandidate({...valid,evidenceRefs:["invoice-1","<script>"]});
  assert.deepEqual(result.evidenceRefs,["invoice-1"]);
  assert.equal(result.recoveredValue,null);
  assert.match(result.limitations[0],/not proof/);
});

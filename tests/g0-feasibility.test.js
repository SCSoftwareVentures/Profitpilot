import test from "node:test";
import assert from "node:assert/strict";
import {evaluateG0} from "../src/g0-feasibility.js";
const sample=(id,business,overrides={})=>({
 exportSetId:"SET"+id,businessKey:"BIZ"+business,period:"2026-10",bundleKey:"BUNDLE"+id,
 authorized:true,complete:true,metrics:{
  payrollPoolCents:10000,payrollAttributableCents:8000,invoiceEligibleCents:10000,invoiceMatchedCents:8000,
  customerMinutes:120,analystMinutes:180,
  rowCountsReconciled:true,monetaryTotalsReconciled:true,taxBasisDocumented:true,roundingDocumented:true,
  allocationBasisApproved:true,matchedEvidenceMediumHigh:true,...overrides
 }
});
const competition=()=>({productsTested:5,customerStacksTested:2,independentCustomerGaps:2,buyersConfirmingWillingness:1});
test("B4 exact 80% thresholds meet declared counts but never grant G0 or G5 approval",()=>{
 const sets=[sample(1,1),sample(2,2),sample(3,3),sample(4,1),sample(5,2,{customerMinutes:121})];
 const r=evaluateG0({sets,competition:competition()});
 assert.equal(r.uniqueCompleteAuthorizedRecords,5);
 assert.equal(r.measuredThresholdPasses,4);
 assert.equal(r.distinctPseudonymousBusinesses,3);
 assert.equal(r.numericClaimsMeetAllG0Thresholds,true);
 assert.equal(r.softwareBuildAuthorized,false);
 assert.equal(r.independentlyVerified,false);
 assert.equal(r.demandValidated,false);
 assert.match(r.g0Decision,/BLOCKED/);
 assert.deepEqual(r.rows[4].failedChecks,["customer_minutes_over_120"]);
});
test("B4 treats just-below 80% and any failed reconciliation as failure",()=>{
 const sets=[sample(1,1,{payrollAttributableCents:7999}),sample(2,2,{invoiceMatchedCents:7999}),
  sample(3,3,{rowCountsReconciled:false}),sample(4,1,{allocationBasisApproved:false}),sample(5,2)];
 const r=evaluateG0({sets,competition:competition()});
 assert.equal(r.measuredThresholdPasses,1);
 assert.equal(r.atLeast80PercentOfEligibleSetsMeetEveryThreshold,false);
 assert.equal(r.numericClaimsMeetAllG0Thresholds,false);
});
test("B4 excludes all colliding export bundles, incomplete and unauthorised records",()=>{
 const a=sample(1,1),dup=sample(2,1);
 dup.bundleKey=a.bundleKey;
 const r=evaluateG0({sets:[a,dup,sample(3,2),{...sample(4,3),authorized:false},
 {...sample(5,3),complete:false},sample(6,1)],competition:competition()});
 assert.equal(r.uniqueCompleteAuthorizedRecords,2);
 assert.equal(r.excludedRecords,4);
 assert.equal(r.measuredThresholdPasses,2);
 assert.equal(r.numericClaimsMeetAllG0Thresholds,false);
 assert.ok(r.rows[0].failedChecks.includes("duplicate_or_ambiguous_set"));
 assert.ok(r.rows[1].failedChecks.includes("duplicate_or_ambiguous_set"));
 assert.throws(()=>evaluateG0({sets:[sample(1,1,{payrollAttributableCents:10001})],competition:competition()}),/exceeds source total/);
});
test("B4 missing metrics and zero denominators never imply full evidence",()=>{
 const missing={...sample(1,1),metrics:null};
 const r=evaluateG0({sets:[missing,sample(2,2,{payrollPoolCents:0,payrollAttributableCents:0}),
 sample(3,3,{invoiceEligibleCents:0,invoiceMatchedCents:0})],competition:competition()});
 assert.equal(r.measuredThresholdPasses,0);
 assert.ok(r.rows[0].failedChecks.includes("metrics_missing"));
 assert.ok(r.rows[1].failedChecks.some(x=>x.includes("zero_pool")));
 assert.ok(r.rows[2].failedChecks.some(x=>x.includes("zero_value")));
});
test("B4 separates competition evidence from arithmetic without claiming demand",()=>{
 const sets=[sample(1,1),sample(2,2),sample(3,3),sample(4,1),sample(5,2)];
 const c=competition();c.buyersConfirmingWillingness=0;
 const r=evaluateG0({sets,competition:c});
 assert.equal(r.competitiveDeclaredCountsMet,false);
 assert.equal(r.numericClaimsMeetAllG0Thresholds,false);
 assert.equal(r.demandValidated,false);
});
test("B4 rejects extraneous private fields, negative/non-finite values and excessive sets",()=>{
 const s=sample(1,1);
 assert.throws(()=>evaluateG0({sets:[{...s,employeeName:"Private"}],competition:competition()}),/unsupported/);
 assert.throws(()=>evaluateG0({sets:[sample(1,1,{staffEmail:"private@example.com"})],competition:competition()}),/unsupported/);
 assert.throws(()=>evaluateG0({sets:[sample(1,1,{customerMinutes:-1})],competition:competition()}),/nonnegative/);
 assert.throws(()=>evaluateG0({sets:[sample(1,1,{payrollPoolCents:NaN})],competition:competition()}),/nonnegative/);
 assert.throws(()=>evaluateG0({sets:[],competition:{...competition(),productsTested:1.25}}),/nonnegative/);
 assert.throws(()=>evaluateG0({sets:Array.from({length:101},(_,i)=>sample(i+1,1)),competition:competition()}),/at most 100/);
});
test("B4 duplicate exclusion is order-independent",()=>{
 const a=sample(1,1),b={...sample(2,2),exportSetId:"SET1"},c=sample(3,3);
 const one=evaluateG0({sets:[a,b,c],competition:competition()});
 const two=evaluateG0({sets:[c,b,a],competition:competition()});
 assert.equal(one.uniqueCompleteAuthorizedRecords,1);
 assert.equal(two.uniqueCompleteAuthorizedRecords,1);
 assert.equal(one.measuredThresholdPasses,1);
 assert.equal(two.measuredThresholdPasses,1);
});

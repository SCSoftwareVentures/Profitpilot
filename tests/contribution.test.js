import test from "node:test";import assert from "node:assert/strict";import {buildContribution} from "../server/contribution.js";
const fixture=()=>({baseline:{contractCount:1,versionCount:1,versionId:"v",versionNo:1,currency:"AUD"},invoiceEvidence:[{amount:"120.01",contained:true,reviewed:true,currency:"AUD",taxBasis:"gst_exclusive",confidence:"HIGH"}],payrollEvidence:[{amount:"80.00",poolId:"p",bucketType:"direct",contained:true,reviewed:true,currency:"AUD"}],pools:[{id:"p",start:"2026-02-01",end:"2026-02-14",total:"100.00",nonSite:"10.00",excluded:"0.00",unallocated:"10.00"}]});
test("partial contribution preserves exact cents and suppresses definitive margin",()=>{const f=fixture();const r=buildContribution(f);assert.equal(r.outputs.contribution,"40.01");assert.equal(r.outputs.marginPercent,null);assert.equal(r.outputs.completeness,"incomplete");assert.equal(r.outputs.poolContext.unallocated,"10.00");assert.equal(r.inputs.invoiceEvidence,f.invoiceEvidence);f.invoiceEvidence[0].amount="-0.01";assert.equal(buildContribution(f).outputs.contribution,"-80.01");});
test("report rejects ambiguous, incomplete or incompatible source evidence",()=>{for(const mutate of [f=>f.baseline.contractCount=2,f=>f.baseline.versionCount=2,f=>f.invoiceEvidence[0].contained=false,f=>f.invoiceEvidence[0].confidence="LOW",f=>f.invoiceEvidence[0].taxBasis="gst_inclusive",f=>f.payrollEvidence[0].reviewed=false,f=>f.pools=[],f=>f.invoiceEvidence=[]]){const f=fixture();mutate(f);assert.ok(buildContribution(f).error);}});
test("overlapping source payroll pools are blocked",()=>{const f=fixture();f.payrollEvidence.push({...f.payrollEvidence[0],poolId:"p2"});f.pools.push({...f.pools[0],id:"p2"});assert.match(buildContribution(f).error,/Overlapping/);});

test("confirmed attributed supplier, subcontractor and other expenses reduce contribution exactly",()=>{
 const f=fixture(); const expense={contained:true,reviewed:true,currency:"AUD",taxBasis:"gst_exclusive",confidence:"HIGH",payrollOverlapReviewed:true,duplicateExpenseReviewed:true};
 f.expenseEvidence=[{...expense,invoiceLineId:"s",costCategory:"supplier",amount:"5.01"},{...expense,invoiceLineId:"c",costCategory:"subcontractor",amount:"7.00"},{...expense,invoiceLineId:"o",costCategory:"other_delivery",amount:"3.00"},{...expense,invoiceLineId:"credit",costCategory:"supplier",amount:"-0.01"}];
 const r=buildContribution(f);
 assert.deepEqual([r.outputs.supplierCost,r.outputs.subcontractorCost,r.outputs.otherDeliveryCost,r.outputs.deliveryCost,r.outputs.contribution,r.outputs.includedCostMarginPercent,r.outputs.marginPercent],["5.00","7.00","3.00","95.00","25.01","20.84",null]);
 assert.equal(r.outputs.expenseLineCount,4);
 assert.equal(r.inputs.expenseEvidence.length,4);
});
test("expense amounts cannot be silently included without human evidence or with duplicate lines",()=>{
 const f=fixture();const e={contained:true,reviewed:true,currency:"AUD",taxBasis:"gst_exclusive",confidence:"HIGH",payrollOverlapReviewed:true,duplicateExpenseReviewed:true,costCategory:"supplier",amount:"10.00",invoiceLineId:"x"};
 assert.equal(buildContribution(f).outputs.expenseEvidenceStatus,"no_confirmed_expense_evidence");
 for(const patch of [{payrollOverlapReviewed:false},{duplicateExpenseReviewed:false},{costCategory:"overhead"},{contained:false},{taxBasis:"unknown"},{confidence:"LOW"},{currency:"USD"}]){f.expenseEvidence=[{...e,...patch}];assert.ok(buildContribution(f).error);}
 f.expenseEvidence=[e,e];assert.match(buildContribution(f).error,/Duplicate/);
});

test("observed coverage uses absolute credits, recorded unique lines and no completeness claim",()=>{
 const f=fixture();f.invoiceEvidence[0].invoiceLineId="r";
 const e={contained:true,currency:"AUD",taxBasis:"gst_exclusive"};
 f.coverageEvidence=[{...e,direction:"customer",invoiceLineId:"r",amount:"120.01"},{...e,direction:"customer",invoiceLineId:"pending",amount:"-20.00"}];
 const c=buildContribution(f).outputs.coverage;
 assert.deepEqual([c.customer.eligibleAbsoluteAmount,c.customer.confirmedAbsoluteAmount,c.customer.percentage,c.payroll.percentage,c.completeSourceCoverage],["140.01","120.01","85.72","80.00",false]);
 assert.equal(c.supplier.percentage,null);
 f.coverageEvidence[1].taxBasis="unknown";assert.equal(buildContribution(f).outputs.coverage.customer.percentage,null);
 f.coverageEvidence[1].taxBasis="gst_exclusive";f.coverageEvidence.push(f.coverageEvidence[1]);assert.equal(buildContribution(f).outputs.coverage.customer.status,"inconsistent_evidence");
});
test("site overhead is separate from delivery contribution and requires exclusive attribution",()=>{
 const f=fixture(); const e={contained:true,reviewed:true,currency:"AUD",taxBasis:"gst_exclusive",confidence:"HIGH",payrollOverlapReviewed:true,duplicateExpenseReviewed:true,costCategory:"site_overhead",amount:"8.01",invoiceLineId:"oh"};
 f.expenseEvidence=[e];assert.ok(buildContribution(f).error);
 e.siteOverheadReviewed=true;const o=buildContribution(f).outputs;
 assert.deepEqual([o.deliveryCost,o.contribution,o.siteOverheadCost,o.includedOperatingResult,o.marginPercent,o.completeness],["80.00","40.01","8.01","32.00",null,"incomplete"]);
});

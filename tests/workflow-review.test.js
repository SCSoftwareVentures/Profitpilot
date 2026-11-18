import test from "node:test";
import assert from "node:assert/strict";
import {prepareInvoiceReview, syntheticPeriodReport} from "../src/workflow-review.js";
const contract={id:"C1",site:"North",periodStart:"2026-11-01",periodEnd:"2026-11-30"};
const rows=[{invoice_id:"INV1",site:"North",date:"2026-11-04",amount:"125.50",__rowNumber:"2"}];
test("candidate requires human confirmation",()=>{
 const result=prepareInvoiceReview(rows,contract);
 assert.equal(result[0].status,"pending_review");
 assert.equal(result[0].candidate.requiresHumanConfirmation,true);
});
test("unconfirmed amount is not included",()=>{
 const report=syntheticPeriodReport({rows,decisions:[],contract});
 assert.equal(report.confirmedInvoiceAmount,0);
 assert.equal(report.contribution,null);
 assert.equal(report.completeness,"incomplete");
});
test("evidence-backed confirmation is counted, never labelled complete revenue",()=>{
 const report=syntheticPeriodReport({rows,decisions:[{rowNumber:2,status:"confirmed",reviewer:"demo",evidenceRef:"synthetic:1"}],contract});
 assert.equal(report.confirmedInvoiceAmount,125.5);
 assert.equal(report.eligibleRevenue,null);
});
test("out-of-period confirmation is denied",()=>{
 assert.throws(()=>syntheticPeriodReport({rows:[{...rows[0],date:"2026-10-01"}],decisions:[{rowNumber:2,status:"confirmed",reviewer:"demo",evidenceRef:"synthetic:1"}],contract}));
});
test("duplicate confirmations are denied",()=>{
 assert.throws(()=>syntheticPeriodReport({rows,decisions:[{rowNumber:2,status:"confirmed",reviewer:"demo",evidenceRef:"synthetic:1"},{rowNumber:2,status:"confirmed",reviewer:"demo",evidenceRef:"synthetic:2"}],contract}));
});
test("held invalid invoice cannot be confirmed",()=>{
 assert.throws(()=>syntheticPeriodReport({rows:[{...rows[0],amount:"-2"}],decisions:[{rowNumber:2,status:"confirmed",reviewer:"demo",evidenceRef:"synthetic:1"}],contract}));
});

test("duplicate source row numbers are denied",()=>{
 assert.throws(()=>syntheticPeriodReport({rows:[rows[0],{...rows[0],invoice_id:"INV2"}],decisions:[],contract}));
});
test("decisions for nonexistent source rows are denied",()=>{
 assert.throws(()=>syntheticPeriodReport({rows,decisions:[{rowNumber:99,status:"pending"}],contract}));
});

test("rejects scientific notation and excess fractional precision",()=>{
 for(const amount of ["1e3","10.001","Infinity"]) {
  const review=prepareInvoiceReview([{...rows[0],amount}],contract);
  assert.equal(review[0].status,"held");
 }
});
test("rejects unsupported currency and inverted contract period",()=>{
 assert.throws(()=>prepareInvoiceReview(rows,{...contract,currency:"USD"}));
 assert.throws(()=>prepareInvoiceReview(rows,{...contract,periodStart:"2026-12-01"}));
});

test("decimal invoice totals are exact to the cent",()=>{
 const many=Array.from({length:100},(_,i)=>({...rows[0],invoice_id:"INV"+i,__rowNumber:String(i+2),amount:"0.10"}));
 const decisions=many.map(r=>({rowNumber:Number(r.__rowNumber),status:"confirmed",reviewer:"synthetic",evidenceRef:"synthetic:"+r.invoice_id}));
 const report=syntheticPeriodReport({rows:many,decisions,contract});
 assert.equal(report.confirmedInvoiceAmount,10);
});
test("invoice aggregation fails closed on totals beyond safe cent precision",()=>{
 const large=Array.from({length:100},(_,i)=>({...rows[0],invoice_id:"L"+i,__rowNumber:String(i+2),amount:"999999999999.99"}));
 const decisions=large.map(r=>({rowNumber:Number(r.__rowNumber),status:"confirmed",reviewer:"synthetic",evidenceRef:"synthetic:"+r.invoice_id}));
 assert.throws(()=>syntheticPeriodReport({rows:large,decisions,contract}),/safe precision/);
});

test("rejects impossible or malformed contract dates",()=>{
 for(const periodStart of ["2026-02-30","2026-13-01","2026-1-01","not-a-date"]){
  assert.throws(()=>prepareInvoiceReview(rows,{...contract,periodStart}),/Invalid contract period/);
 }
 assert.throws(()=>prepareInvoiceReview(rows,{...contract,periodEnd:"2026-11-31"}),/Invalid contract period/);
});

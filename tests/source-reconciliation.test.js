import test from "node:test";
import assert from "node:assert/strict";
import {reconcileStoredSource} from "../src/source-reconciliation.js";
const batch={id:"b",source_type:"supplier_invoice",status:"accepted",start:"2026-02-01",end:"2026-02-28"};
const contract="11111111-1111-4111-8111-111111111111",site="22222222-2222-4222-8222-222222222222",rawId="33333333-3333-4333-8333-333333333333";
const payload={invoice_id:"INV-1",date:"2026-03-01",currency:"AUD",tax_basis:"gst_exclusive",description:"Private source",contract_id:contract,site_id:site,service_start:batch.start,service_end:batch.end,line_number:1,amount:"10.01"};
const fixture=()=>({batch,rows:[{id:rawId,row_number:1,payload}],manifestEvents:[{rowCount:1,manifest:[{invoiceNumber:"INV-1",total:"10.01",lineCount:1}]}],invoiceRecords:[{rawId,lineId:"l",invoiceId:"i",direction:"supplier",invoiceNumber:"INV-1",invoiceDate:payload.date,currency:"AUD",taxBasis:"gst_exclusive",invoiceTotal:"10.01",headerLineCount:1,lineNumber:1,amount:"10.01",description:payload.description,mappingDecision:"accepted",mappingTarget:"l",matchCount:1,confirmedCount:1,contractId:contract,siteId:site,serviceStart:batch.start,serviceEnd:batch.end,decision:"confirmed",reviewed:true}]});
test("reconciliation distinguishes declared source and final approvals without returning source payload",()=>{
 const f=fixture(),r=reconcileStoredSource(f);
 assert.equal(r.sourceStatus,"reconciled_declared_source");assert.equal(r.approvalStatus,"all_rows_confirmed");assert.equal(r.externallyVerified,false);assert.equal(JSON.stringify(r).includes("Private source"),false);
 f.invoiceRecords[0].decision="held";assert.equal(reconcileStoredSource(f).approvalStatus,"incomplete_match_approval");
});
test("missing manifest and tampered canonical values fail closed",()=>{
 let f=fixture();f.manifestEvents=[];assert.equal(reconcileStoredSource(f).sourceStatus,"declaration_unavailable");
 for(const patch of [{amount:"10.02"},{headerLineCount:2},{matchCount:2},{siteId:contract},{mappingTarget:"foreign"},{invoiceTotal:"9.99"}]){
  f=fixture();Object.assign(f.invoiceRecords[0],patch);assert.equal(reconcileStoredSource(f).sourceStatus,"unreconciled");
 }
});

test("payroll allocation includes explicit residual line and separately reconciles every bucket",()=>{
 const p={source_ref:"SOURCE-A",cost_component:"gross_wages",amount:"100.00",currency:"AUD",period_start:batch.start,period_end:batch.end};
 const buckets={direct:"60.00",allocated:"20.00",nonSite:"10.00",excluded:"0.00",residual:"10.00"};
 const a={...buckets,poolId:"pool",status:"confirmed",reviewed:true,lineChecks:{...buckets,lineCount:4,badSites:0,total:"100.00"}};
 const f={batch:{...batch,source_type:"payroll"},rows:[{payload:p,decision:"accepted"}],payrollPools:[{id:"pool",currency:"AUD",start:batch.start,end:batch.end,total:"100.00"}],allocations:[a]};
 assert.equal(reconcileStoredSource(f).approvalStatus,"allocation_reconciled");
 a.lineChecks={...a.lineChecks,direct:"61.00",allocated:"19.00"};assert.equal(reconcileStoredSource(f).approvalStatus,"allocation_inconsistent");
 a.lineChecks={...buckets,lineCount:3,badSites:0,total:"90.00",residual:"0.00"};assert.equal(reconcileStoredSource(f).approvalStatus,"allocation_inconsistent");
});

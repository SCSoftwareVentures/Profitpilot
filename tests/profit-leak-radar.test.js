import test from "node:test";
import assert from "node:assert/strict";
import {detectProfitLeaks} from "../src/profit-leak-radar.js";

const basis={currency:"AUD",taxBasis:"gst_exclusive",periodStart:"2026-11-01",periodEnd:"2026-11-30"};
const complete={
  reportingBasis:basis,
  contract:{amount:"1000.00",...basis,coverage:"complete",evidenceRef:"synthetic:contract"},
  variations:{approvedAmount:"100.00",...basis,coverage:"complete",evidenceRef:"synthetic:approved-variations"},
  invoices:{amount:"950.00",...basis,coverage:"complete",evidenceRef:"synthetic:invoice-total",rows:[]},
  payroll:{poolAmount:"800.00",allocatedAmount:"800.00",...basis,coverage:"complete",evidenceRef:"synthetic:payroll"}
};

test("contract-to-invoice difference is a candidate with exact decimal arithmetic",()=>{
  const result=detectProfitLeaks(complete);
  const alert=result.alerts.find(x=>x.type==="contract_invoice_variance");
  assert.equal(alert.status,"candidate");
  assert.equal(alert.amount,"150.00");
  assert.equal(alert.direction,"invoice_below_contract_plus_approved_variations");
  assert.equal(result.status,"review_required");
});

test("matching contract, approved variations and invoice totals produce no variance alert",()=>{
  const result=detectProfitLeaks({...complete,invoices:{...complete.invoices,amount:"1100.00"}});
  assert.equal(result.alerts.some(x=>x.type==="contract_invoice_variance"),false);
});

test("unlike currencies, tax bases or periods never produce a quantified variance",()=>{
  for(const invoice of [
    {...complete.invoices,currency:"USD"},
    {...complete.invoices,taxBasis:"gst_inclusive"},
    {...complete.invoices,periodStart:"2026-10-01",periodEnd:"2026-10-31"}
  ]){
    const result=detectProfitLeaks({...complete,invoices:invoice});
    const alert=result.alerts.find(x=>x.type==="contract_invoice_variance");
    assert.equal(alert.status,"unknown");
    assert.equal(alert.amount,null);
  }
});

test("partial or missing variation evidence is unknown rather than an assumed zero",()=>{
  const result=detectProfitLeaks({...complete,variations:{...complete.variations,coverage:"partial"}});
  const alert=result.alerts.find(x=>x.type==="contract_invoice_variance");
  assert.equal(alert.status,"unknown");
  assert.equal(alert.amount,null);
});

test("unallocated and over-allocated payroll residuals are exact candidates",()=>{
  const under=detectProfitLeaks({...complete,payroll:{...complete.payroll,poolAmount:"1000.00",allocatedAmount:"850.10"}});
  const a=under.alerts.find(x=>x.type==="payroll_allocation_variance");
  assert.equal(a.amount,"149.90");
  assert.equal(a.direction,"unallocated_pool");
  const over=detectProfitLeaks({...complete,payroll:{...complete.payroll,poolAmount:"1000.00",allocatedAmount:"1100.00"}});
  const b=over.alerts.find(x=>x.type==="payroll_allocation_variance");
  assert.equal(b.amount,"100.00");
  assert.equal(b.direction,"over_allocated_pool");
});

test("unmatched and duplicate invoice rows remain separate candidates, not a combined loss",()=>{
  const result=detectProfitLeaks({...complete,invoices:{...complete.invoices,rows:[
    {status:"unmatched",amount:"25.50",evidenceRef:"synthetic:row-1"},
    {status:"duplicate_candidate",amount:"25.50",evidenceRef:"synthetic:row-2"}
  ]}});
  const rows=result.alerts.filter(x=>["unmatched_invoice_row","duplicate_invoice_candidate"].includes(x.type));
  assert.equal(rows.length,2);
  assert.deepEqual(rows.map(x=>x.amount),["25.50","25.50"]);
  assert.equal(rows.every(x=>x.status==="candidate"),true);
});

test("invalid money or missing source evidence never produces a quantified alert",()=>{
  const result=detectProfitLeaks({...complete,contract:{...complete.contract,amount:1000},payroll:{...complete.payroll,evidenceRef:""}});
  assert.equal(result.alerts.find(x=>x.type==="contract_invoice_variance").status,"unknown");
  assert.equal(result.alerts.find(x=>x.type==="contract_invoice_variance").amount,null);
  assert.equal(result.alerts.find(x=>x.type==="payroll_allocation_variance").status,"unknown");
});

test("missing payroll and invoice row coverage are unknown, never zero",()=>{
  const result=detectProfitLeaks({...complete,payroll:null,invoices:{...complete.invoices,amount:"1100.00",rows:undefined}});
  assert.equal(result.alerts.find(x=>x.type==="payroll_allocation_variance").amount,null);
  assert.equal(result.alerts.find(x=>x.type==="invoice_row_exceptions").status,"unknown");
  assert.equal(result.status,"incomplete_evidence");
});

test("reporting basis must be explicit and valid",()=>{
  for(const reportingBasis of [null,{...basis,currency:"aud"},{...basis,periodStart:"2026-11-31"},{...basis,periodEnd:"2026-10-31"}]){
    assert.throws(()=>detectProfitLeaks({...complete,reportingBasis}),/valid explicit reporting basis/);
  }
});

test("all emitted monetary alerts remain candidates and disclaim verified-loss conclusions",()=>{
  const result=detectProfitLeaks({...complete,payroll:{...complete.payroll,poolAmount:"900.00",allocatedAmount:"800.00"}});
  assert.equal(result.alerts.every(x=>x.status==="candidate"||x.status==="unknown"),true);
  assert.match(result.interpretation,/No alert is a confirmed loss/);
});

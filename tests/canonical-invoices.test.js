import test from "node:test";
import assert from "node:assert/strict";
import {reconcileInvoiceRows} from "../src/canonical-invoices.js";
const period={periodStart:"2026-02-01",periodEnd:"2026-02-28"};
const p={invoice_id:"INV-1",date:"2026-03-01",currency:"AUD",tax_basis:"gst_exclusive",description:"Synthetic",contract_id:"11111111-1111-4111-8111-111111111111",site_id:"22222222-2222-4222-8222-222222222222",service_start:"2026-02-01",service_end:"2026-02-28"};
const raw=()=>[{id:"33333333-3333-4333-8333-333333333333",row_number:1,payload:{...p,line_number:1,amount:"10.01"}},{id:"44444444-4444-4444-8444-444444444444",row_number:2,payload:{...p,line_number:2,amount:"-0.01"}}];
const manifest=()=>[{invoiceNumber:"INV-1",total:"10.00",lineCount:2}];
test("exact signed cents, explicit invoice manifest and source provenance",()=>{const r=reconcileInvoiceRows(raw(),manifest(),period);assert.equal(r.groups[0].total,"10.00");assert.equal(r.groups[0].lines[1].amount,"-0.01");});
test("reject ambiguous, missing, invalid and unreconciled data",()=>{for(const patch of [{amount:"1e1"},{amount:10.01},{amount:"10.001"},{invoice_id:" inv-1"},{line_number:1},{line_number:3},{currency:"USD"},{tax_basis:"unknown"},{date:"2026-02-31"},{service_end:"2026-03-01"},{site_id:"not-an-id"},{description:""}]){const r=raw();Object.assign(r[1].payload,patch);assert.ok(reconcileInvoiceRows(r,manifest(),period).error,JSON.stringify(patch));}assert.ok(reconcileInvoiceRows(raw(),[{...manifest()[0],total:"10.01"}],period).error);assert.ok(reconcileInvoiceRows(raw(),[{...manifest()[0],lineCount:3}],period).error);assert.ok(reconcileInvoiceRows(raw(),[...manifest(),...manifest()],period).error);});

import test from "node:test";
import assert from "node:assert/strict";
import {validateInvoiceRows} from "../src/engine.js";
const row = invoice_id => ({invoice_id,site:"Demo",date:"2026-11-01",amount:"12.00"});
test("all repeated references are held without altering source evidence",()=>{
 const rows=[row("A1"),row(" A1 "),row("A2")];
 const result=validateInvoiceRows(rows);
 assert.deepEqual(result.map(x=>x.status),["held","held","pending_review"]);
 assert.equal(result[1].record.invoice_id," A1 ");
});
test("blank and non-string references are held",()=>{
 assert.deepEqual(validateInvoiceRows([row(" "),row(123),row(null)]).map(x=>x.status),["held","held","held"]);
});
test("leading zeros and case are not silently normalised",()=>{
 assert.ok(validateInvoiceRows([row("01"),row("1"),row("a"),row("A")]).every(x=>x.status==="pending_review"));
});

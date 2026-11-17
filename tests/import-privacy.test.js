import test from "node:test";
import assert from "node:assert/strict";
import {importPayloadAllowed} from "../src/import-privacy.js";
test("allow only bounded minimal financial fields; semantic review stays separate",()=>{
 const p={source_ref:"opaque-reference",cost_component:"gross_wages",amount:"1e2",currency:"AUD",period_start:"2026-02-01",period_end:"2026-02-14"};
 assert.equal(importPayloadAllowed("payroll",[p]),true);
 for(const row of [{...p,employee_name:"private"},{...p,bank_account:"private"},{...p,source_ref:{value:"private"}},{...p,source_ref:"x".repeat(121)},{...p,source_ref:"a\nb"},{...p,amount:5},JSON.parse('{"__proto__":"private"}'),{}])assert.equal(importPayloadAllowed("payroll",[row]),false);
 assert.equal(importPayloadAllowed("supplier_invoice",[{invoice_id:"INV-1",description:"Service",amount:"-1.00",line_number:1}]),true);
 assert.equal(importPayloadAllowed("customer_invoice",[{invoice_id:"INV-1",description:"x".repeat(501)}]),false);
 assert.equal(importPayloadAllowed("constructor",[{invoice_id:"INV-1"}]),false);
});

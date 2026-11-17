import test from "node:test";
import assert from "node:assert/strict";
import {parseFinancialCsv} from "../src/secure-csv.js";
const parse=s=>parseFinancialCsv(Buffer.from(s),"supplier_invoice");
test("strict CSV preserves signed decimals and original byte digest",()=>{
 const r=parse('invoice_id,line_number,description,amount\r\nINV-1,1,"A ""quoted"", value",-1.01\r\n');
 assert.deepEqual(r.rows,[{invoice_id:"INV-1",line_number:1,description:'A "quoted", value',amount:"-1.01"}]);
 assert.match(r.sha256,/^[a-f0-9]{64}$/);
});
test("reject malformed text, unexpected fields and unsafe CSV inputs",()=>{
 for(const s of ["invoice_id,invoice_id\nA,B","invoice_id,description\nA,=SUM(1)","invoice_id,description\nA,\"bad\ncell\"","invoice_id,description\nA,\"x\"junk","invoice_id,description\nA,un\"quoted","invoice_id,employee_name\nA,Private","invoice_id,description\nA,\u0000","invoice_id,description\nA,x,y","invoice_id\n","invoice_id\n"+Array(201).fill("A").join("\n"),"description\n"+"x".repeat(501)])assert.ok(parse(s).error,s.slice(0,80));
 assert.ok(parseFinancialCsv(Buffer.from([0xff,0xfe]),"payroll").error);
 assert.ok(parseFinancialCsv(Buffer.alloc(102401),"payroll").error);
});

test("CSV rejects non-buffer and forged payload types",()=>{
 for(const bad of ["invoice_id\nA",[],new Uint8Array(8),{length:8}])assert.ok(parseFinancialCsv(bad,"supplier_invoice").error);
});

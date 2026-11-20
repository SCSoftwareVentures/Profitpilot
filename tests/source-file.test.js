import test from "node:test";
import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {parseSourceFile,MAX_SOURCE_BYTES} from "../server/source-file.js";
const header="invoice_id,site,date,amount\n";
test("CSV preserves raw hash and quoted values",()=>{
 const bytes=Buffer.from(header+'X,"A, B",2026-02-01,12.30\r\n');
 const result=parseSourceFile(bytes,"customer_invoice");
 assert.equal(result.sha256,createHash("sha256").update(bytes).digest("hex"));
 assert.deepEqual(result.rows,[{invoice_id:"X",site:"A, B",date:"2026-02-01",amount:"12.30"}]);
});
test("CSV rejects malformed, executable and unexpected fields",()=>{
 for(const body of ['X,A"oops",2026-02-01,12\n','X,"A"bad,2026-02-01,12\n','X,"A,2026-02-01,12\n','X,=CMD(),2026-02-01,12\n','X,A,2026-02-01,12,extra\n','X,A,2026-02-01,12\n\n','X,\x00,2026-02-01,12\n'])assert.throws(()=>parseSourceFile(Buffer.from(header+body),"customer_invoice"));
 assert.throws(()=>parseSourceFile(Buffer.from("invoice_id,site,date,employee_name\nX,A,2026-02-01,Jane"),"customer_invoice"));
 assert.throws(()=>parseSourceFile(Buffer.from([0xff,0xfe]),"customer_invoice"));
 assert.throws(()=>parseSourceFile(Buffer.alloc(MAX_SOURCE_BYTES+1),"customer_invoice"));
 assert.throws(()=>parseSourceFile(Buffer.from(header+"X,A,2026-02-01,12\n".repeat(2001)),"customer_invoice"));
});
test("payroll source uses allowlisted schema",()=>{
 const result=parseSourceFile(Buffer.from("source_ref,amount,currency,period_start,period_end\npay:1,5.01,AUD,2026-02-01,2026-02-28"),"payroll");
 assert.equal(result.rows[0].amount,"5.01");
});

test("invoice source rejects blank and repeated IDs without conflating distinct IDs",()=>{
 for(const type of ["customer_invoice","supplier_invoice"]){
  assert.throws(()=>parseSourceFile(Buffer.from(header+"X,A,2026-02-01,12.00\nX,B,2026-02-02,13.00\n"),type),/Duplicate invoice ID/);
  assert.throws(()=>parseSourceFile(Buffer.from(header+" ,A,2026-02-01,12.00\n"),type),/Invoice ID is required/);
  const distinct=parseSourceFile(Buffer.from(header+"X,A,2026-02-01,12.00\nY,B,2026-02-02,13.00\n"),type);
  assert.equal(distinct.rows.length,2);
 }
});

test("CSV parser rejects non-Buffer inputs regardless of their length",()=>{
 for(const input of ["x",["x"],{length:1,byteLength:1},new Uint8Array([65]),null])assert.throws(()=>parseSourceFile(input,"customer_invoice"));
});

import test from "node:test";
import assert from "node:assert/strict";
import {randomUUID,randomBytes} from "node:crypto";
import {inspectInvoiceCsv,UnsafeCsvError,MAX_INVOICE_ROWS} from "../server/secure-invoice-csv.js";
import {sealQuarantine} from "../server/quarantine.js";
import {runQuarantineCycle} from "../scripts/quarantine-worker.js";

const header="invoice_id,site,date,amount";
const valid="INV-1,Site A,2026-02-28,30.50";
const bytes=s=>Buffer.from(s,"utf8");
test("strict CSV accepts bounded canonical invoice fields and discloses only row counts",()=>{
 assert.deepEqual(inspectInvoiceCsv(bytes(header+"\n"+valid+"\n")),{rowCount:1});
 assert.deepEqual(inspectInvoiceCsv(bytes("\uFEFF"+header+"\r\n"+valid+"\r\n")),{rowCount:1});
 assert.deepEqual(inspectInvoiceCsv(bytes(header+"\n"+'INV-2,"Site A",2026-02-28,-1.00')),{rowCount:1});
 assert.deepEqual(inspectInvoiceCsv(bytes(header+",contract_id,currency,tax_basis\n"+valid+",33333333-3333-4333-8333-333333333333,AUD,gst_exclusive")),{rowCount:1});
 assert.deepEqual(inspectInvoiceCsv(bytes(header+"\n"+Array(MAX_INVOICE_ROWS).fill(valid).join("\n"))),{rowCount:MAX_INVOICE_ROWS});
});
test("rejects unsafe, ambiguous, oversized and formula-bearing data without echoing it",()=>{
 for(const input of [
  header,header+"\n",header+"\n\n"+valid,
  header+"\n"+valid+"\n\n",header+"\n"+valid+"\n"+Array(MAX_INVOICE_ROWS).fill(valid).join("\n"),
  header+",note\n"+valid+",SYNTHETIC_PRIVATE_VALUE",
  header+",site\n"+valid+",Site B",
  "__proto__,site,date,amount\n"+valid,
  header+"\n"+'INV-2,"Site\nA",2026-02-28,1.00',
  header+"\n"+'INV-2,"Site A" ,2026-02-28,1.00',
  header+"\n"+'INV-2,"Site A,2026-02-28,1.00',
  header+"\n"+'INV-2,Site A,2026-02-30,1.00',
  header+"\n"+'INV-2,Site A,2026-02-28,=1+2',
  header+"\n"+'INV-2,+Site A,2026-02-28,1.00',
  header+"\n"+'INV-2,＠Site A,2026-02-28,1.00',
  header+"\n"+'INV-2,Site\tA,2026-02-28,1.00',
  header+"\n"+'INV-2,Site\u200bA,2026-02-28,1.00',
  header+"\n"+'INV-2,site@example.invalid,2026-02-28,1.00',
  header+"\n"+'INV-2,999999999,2026-02-28,1.00',
  header+"\n"+'INV-2,passport,2026-02-28,1.00',
  header+"\n"+'INV-2,'+"A".repeat(513)+',2026-02-28,1.00',
  header+",service_period_start,service_period_end\n"+valid+",2026-03-01,2026-02-28",
  "A".repeat(65537)
 ]){
  assert.throws(()=>inspectInvoiceCsv(bytes(input)),e=>e instanceof UnsafeCsvError&&!e.message.includes("SYNTHETIC_PRIVATE_VALUE"));
 }
 assert.throws(()=>inspectInvoiceCsv(Buffer.from([255])),UnsafeCsvError);
});
test("worker distinguishes malware verdict from content rejection and clears plaintext buffers",async()=>{
 const tenant=randomUUID(),keyId="ci-key",secret=randomBytes(32).toString("hex");
 for(const [text,malware,expected] of [
  [header+"\n"+valid,"clean",["clean","validated"]],
  [header+"\n"+'INV-2,=FORMULA,2026-02-28,1.00',"clean",["clean","rejected"]],
  [header+"\n"+valid,"infected",["infected","not_checked"]]
 ]){
  const batch=randomUUID(),e=sealQuarantine(bytes(text),tenant,batch,{id:keyId,secret});
  const row={tenant_id:tenant,batch_id:batch,file_sha256:e.sha,key_id:keyId,nonce:e.nonce,auth_tag:e.tag,ciphertext:e.ciphertext,lease_id:randomUUID()};
  let claims=0,recorded,plaintext;
  const db={query:async(sql,args)=>{
   if(sql.includes("claim"))return {rows:claims++===0?[row]:[]};
   assert.match(sql,/finish_quarantine_manifest/);
   recorded=args.slice(3,5);
   if(args[4]==="validated")assert.deepEqual(JSON.parse(args[5]),[{invoice_id:"INV-1",site:"Site A",date:"2026-02-28",amount:"30.50"}]);else assert.equal(args[5],null);
   return {rows:[{recorded:true}]};
  }};
  await runQuarantineCycle(db,{keyId,secret,scan:async plain=>{plaintext=plain;return malware;}});
  assert.deepEqual(recorded,expected);
  assert.ok(plaintext.every(b=>b===0));
 }
});

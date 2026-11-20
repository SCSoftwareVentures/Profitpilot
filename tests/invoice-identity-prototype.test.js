import test from "node:test";
import assert from "node:assert/strict";
import {classifyInvoiceIdentity} from "../src/invoice-identity.js";
const row=(issuerKey,invoiceReference,direction="supplier")=>({issuerKey,invoiceReference,direction});
test("issuer-aware candidates never auto-confirm and every conflicting member is held",()=>{
 const input=[row("A","001"),row("A","001"),row("B","001"),row("","001"),row("A","1"),row("A","001","customer"),row("A","001"),row("A","ABC"),row("A","abc")];
 const original=structuredClone(input);
 const result=classifyInvoiceIdentity(input);
 assert.deepEqual(result.map(x=>x.status),["held","held","candidate","held","held","candidate","held","held","held"]);
 assert.deepEqual(input,original);
 assert.deepEqual(classifyInvoiceIdentity([...input].reverse()).reverse(),result);
});
test("malformed references, rows and directions are held",()=>{
 assert.ok(classifyInvoiceIdentity([null,undefined,[],42,row("A",1),row("A"," "),row("A","1","other")]).every(x=>x.status==="held"));
 assert.throws(()=>classifyInvoiceIdentity(null),TypeError);
});
test("aliases hold every member without canonicalising original references",()=>{
 const input=[row(" A "," 001 "),row("A","1"),row("A","001"),row("A","ABC"),row("A","abc"),row("a","001")];
 const original=structuredClone(input);
 assert.deepEqual(classifyInvoiceIdentity(input).map(x=>x.status),["held","held","held","held","held","candidate"]);
 assert.deepEqual(input,original);
});
test("distinct direction and issuer namespaces remain separate",()=>{
 assert.ok(classifyInvoiceIdentity([row("A","001"),row("B","001"),row("A","001","customer")]).every(x=>x.status==="candidate"));
});

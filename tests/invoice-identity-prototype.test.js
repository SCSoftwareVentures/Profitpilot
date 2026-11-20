import test from "node:test";
import assert from "node:assert/strict";
import {classifyInvoiceIdentity} from "../src/invoice-identity.js";
const row=(issuerKey,invoiceReference,direction="supplier")=>({issuerKey,invoiceReference,direction});
test("issuer-aware candidates never auto-confirm",()=>{
 const input=[row("A","001"),row("A","001"),row("B","001"),row("","001"),row("A","1"),row("A","001","customer"),row("A","001"),row("A","ABC"),row("A","abc")];
 assert.deepEqual(classifyInvoiceIdentity(input).map(x=>x.status),["candidate","held","candidate","held","held","candidate","held","candidate","held"]);
 assert.equal(input[0].invoiceReference,"001");
});
test("malformed references and directions are held",()=>{
 assert.ok(classifyInvoiceIdentity([row("A",1),row("A"," "),row("A","1","other")]).every(x=>x.status==="held"));
});

import test from "node:test";
import assert from "node:assert/strict";
import {reconcileSharedOverhead} from "../src/shared-overhead.js";
const a="11111111-1111-4111-8111-111111111111",b="22222222-2222-4222-8222-222222222222";
const ok=[{siteId:a,amount:"7.01"},{siteId:b,amount:"5.00"}];
test("reconcile signed source exactly once across different sites",()=>{
 assert.deepEqual(reconcileSharedOverhead("12.01",ok,{anchorSiteId:a}).shares,ok);
 const credit=ok.map(l=>({...l,amount:"-"+l.amount}));
 assert.deepEqual(reconcileSharedOverhead("-12.01",credit,{anchorSiteId:b}).shares,credit);
});
test("reject excess, shortage, offsetting signs, duplicate sites, zero and invalid decimal",()=>{
 for(const lines of [[ok[0],{...ok[1],amount:"5.01"}],[ok[0],{...ok[1],amount:"4.99"}],[ok[0],{...ok[1],amount:"-5.00"}],[ok[0],{...ok[1],siteId:a}],[ok[0],{...ok[1],amount:"0.00"}],[ok[0],{...ok[1],amount:5}],[ok[0]]])assert.ok(reconcileSharedOverhead("12.01",lines,{anchorSiteId:a}).error);
 assert.ok(reconcileSharedOverhead("12.01",ok,{anchorSiteId:"33333333-3333-4333-8333-333333333333"}).error);
});

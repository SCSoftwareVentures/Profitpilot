import test from "node:test";
import assert from "node:assert/strict";
import {randomUUID,randomBytes} from "node:crypto";
import {makePayerService} from "./payer-service.mjs";
let calls=0;
const keys={signingKey:randomBytes(32),pepper:randomBytes(32)};
const pool={connect:async()=>{calls++;throw Error("fixture connection");}};
const service=makePayerService({pool,...keys});
const base={identity:{subject:"verified-payer",authTime:Math.floor(Date.now()/1000)},tenantId:randomUUID(),milestoneId:randomUUID(),body:{pin:"012345",expectedAmountCents:5000,idempotencyKey:randomUUID()}};
test("request payload cannot provide customer identity, payment status, or amount overrides",async()=>{
 for(const extra of [{customerId:randomUUID()},{subject:"forged"},{status:"released"},{amountCents:1}]){
  await assert.rejects(service.reserve({...base,body:{...base.body,...extra}}),e=>e.status===400);
 }
 assert.equal(calls,0);
});
test("requires verified identity and strict identifiers and cents before database access",async()=>{
 await assert.rejects(service.reserve({...base,identity:null}),e=>e.status===401);
 await assert.rejects(service.reserve({...base,identity:{subject:"verified-payer"}}),e=>e.status===401);
 await assert.rejects(service.reserve({...base,identity:{...base.identity,authTime:0}}),e=>e.status===401);
 await assert.rejects(service.reserve({...base,tenantId:"bad"}),e=>e.status===400);
 await assert.rejects(service.reserve({...base,body:{...base.body,expectedAmountCents:1.5}}),e=>e.status===400);
 assert.equal(calls,0);
});
test("PIN changes cannot supply administrator override or customer ID",async()=>{
 await assert.rejects(service.setPin({...base,body:{pin:"123456",purpose:"recover",grantRef:randomUUID(),admin:true}}),e=>e.status===400);
 assert.equal(calls,0);
});
test("separate signing and PIN keys are required",()=>{
 assert.throws(()=>makePayerService({pool,signingKey:keys.pepper,pepper:keys.pepper}),/unavailable/);
});

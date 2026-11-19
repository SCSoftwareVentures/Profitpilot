import test from "node:test";
import assert from "node:assert/strict";
import {authorizeMilestoneRelease} from "./release-authorization.mjs";
const base={milestone:{id:"m1",amountCents:5000,status:"approved"},customerId:"c1",authorizationRef:"a1",requestId:"req1"};
test("fails closed without server-side verifier",async()=>{
 await assert.rejects(authorizeMilestoneRelease(base),/unavailable/);
});
test("rejects failed authorization",async()=>{
 await assert.rejects(authorizeMilestoneRelease({...base,verifyAndConsume:async()=>false}),/rejected/);
});
test("rejects milestones not approved",async()=>{
 await assert.rejects(authorizeMilestoneRelease({...base,milestone:{...base.milestone,status:"disputed"},verifyAndConsume:async()=>true}),/not approved/);
});
test("passes exact customer, amount and milestone to verifier",async()=>{
 let received;
 const candidate=await authorizeMilestoneRelease({...base,verifyAndConsume:async v=>{received=v;return true;}});
 assert.deepEqual(received,{authorizationRef:"a1",customerId:"c1",milestoneId:"m1",amountCents:5000,requestId:"req1"});
 assert.equal(candidate.idempotencyKey,"req1");
 assert.equal(candidate.amountCents,5000);
 assert.equal(Object.isFrozen(candidate),true);
});

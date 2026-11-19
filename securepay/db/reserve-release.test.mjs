import test from "node:test";
import assert from "node:assert/strict";
import {reserveRelease} from "./reserve-release.mjs";
const args={tenantId:"t1",milestoneId:"m1",customerId:"c1",authorizationRef:"auth1",idempotencyKey:"idem1",requestId:"r1"};
const client=(status="approved")=>({calls:[],async query(sql,params){this.calls.push({sql,params});if(sql.startsWith("SELECT"))return {rows:[{id:"m1",amount_cents:5000,status}]};if(sql.startsWith("INSERT"))return {rows:[{id:"r1"}]};return {rows:[]};}});
test("denies missing verifier",async()=>{await assert.rejects(reserveRelease(client(),args),/unavailable/);});
test("rejects disputed milestone before consuming proof",async()=>{
 let invoked=false;const c=client("disputed");
 await assert.rejects(reserveRelease(c,{...args,verifyAndConsume:async()=>{invoked=true;return true;}}),/not eligible/);
 assert.equal(invoked,false);assert.equal(c.calls.length,1);
});
test("rejects invalid PIN proof before writing",async()=>{
 const c=client();await assert.rejects(reserveRelease(c,{...args,verifyAndConsume:async()=>false}),/rejected/);
 assert.equal(c.calls.length,1);
});
test("locks row, consumes proof, inserts request then advances state",async()=>{
 const c=client();let seen;
 const r=await reserveRelease(c,{...args,verifyAndConsume:async v=>{seen=v;return true;}});
 assert.match(c.calls[0].sql,/FOR UPDATE/);
 assert.equal(seen.client,c);assert.equal(seen.amountCents,5000);
 assert.match(c.calls[1].sql,/INSERT INTO securepay_release_requests/);
 assert.match(c.calls[2].sql,/UPDATE securepay_milestones/);
 assert.equal(r.amountCents,5000);
});

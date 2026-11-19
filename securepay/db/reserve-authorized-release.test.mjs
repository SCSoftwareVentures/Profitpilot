import test from "node:test";
import assert from "node:assert/strict";
import {reserveAuthorizedRelease} from "./reserve-authorized-release.mjs";
const scope={tenantId:"t1",milestoneId:"m1",customerId:"c1",authorizationRef:"p1",idempotencyKey:"i1",requestId:"r1"};
function mock({status="approved",proof=1,failInsert=false}={}) {
 const calls=[];let released=false;
 const client={async query(sql) {
  calls.push(sql);
  if(sql.includes("FOR UPDATE"))return {rows:[{id:"m1",amount_cents:5000,status}]};
  if(sql.includes("UPDATE securepay_release_proofs"))return {rowCount:proof};
  if(sql.includes("INSERT INTO securepay_release_requests")){if(failInsert)throw Error("unique violation");return {rows:[{id:"r1"}]};}
  return {rows:[]};
 },release(){released=true;}};
 return {pool:{connect:async()=>client},calls,isReleased:()=>released};
}
test("commits reservation and one-use proof atomically",async()=>{
 const m=mock();const result=await reserveAuthorizedRelease(m.pool,scope);
 assert.equal(result.amountCents,5000);
 assert.equal(m.calls[0],"BEGIN");
 assert.ok(m.calls.some(x=>x.includes("UPDATE securepay_release_proofs")));
 assert.equal(m.calls.at(-1),"COMMIT");
 assert.equal(m.isReleased(),true);
});
test("expired or consumed proof rolls back",async()=>{
 const m=mock({proof:0});await assert.rejects(reserveAuthorizedRelease(m.pool,scope),/Authorization rejected/);
 assert.equal(m.calls.at(-1),"ROLLBACK");assert.equal(m.isReleased(),true);
});
test("insert collision rolls back consumed proof",async()=>{
 const m=mock({failInsert:true});await assert.rejects(reserveAuthorizedRelease(m.pool,scope),/unique violation/);
 assert.equal(m.calls.at(-1),"ROLLBACK");
});
test("disputed milestone cannot consume proof",async()=>{
 const m=mock({status:"disputed"});await assert.rejects(reserveAuthorizedRelease(m.pool,scope),/not eligible/);
 assert.equal(m.calls.some(x=>x.includes("UPDATE securepay_release_proofs")),false);
 assert.equal(m.calls.at(-1),"ROLLBACK");
});

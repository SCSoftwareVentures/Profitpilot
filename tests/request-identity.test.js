import test from "node:test";
import assert from "node:assert/strict";
import {withVerifiedRequestIdentity,currentRequestIdentity} from "../server/request-identity.js";
test("verified request identity cannot leak across concurrent asynchronous operations",async()=>{
 const first={subject:"synthetic-a",jti:"a".repeat(16),amr:["mfa"]},second={subject:"synthetic-b",jti:"b".repeat(16),amr:["pwd"]};
 await Promise.all([first,second].map(identity=>withVerifiedRequestIdentity(identity,async()=>{
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(currentRequestIdentity().subject,identity.subject);
  assert.equal(Object.isFrozen(currentRequestIdentity()),true);
  assert.equal(Object.isFrozen(currentRequestIdentity().amr),true);
 })));
 assert.equal(currentRequestIdentity(),undefined);
 assert.throws(()=>withVerifiedRequestIdentity({},()=>{}),/identity required/);
});

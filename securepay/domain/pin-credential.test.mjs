import test from "node:test";
import assert from "node:assert/strict";
import {randomBytes} from "node:crypto";
import {createPinCredential,verifyPinCredential} from "./pin-credential.mjs";
const scope={tenantId:"tenant-a",customerId:"customer-a",pin:"012345",pepper:randomBytes(32)};
test("PIN credentials use unique salts and verify leading-zero PINs",async()=>{
 const a=await createPinCredential(scope),b=await createPinCredential(scope);
 assert.notEqual(a.salt,b.salt);assert.notEqual(a.pinHash,b.pinHash);
 assert.match(a.pinHash,/^[0-9a-f]{64}$/);
 assert.equal(await verifyPinCredential(scope,a),true);
});
test("wrong PIN, account, tenant or pepper cannot verify",async()=>{
 const a=await createPinCredential(scope);
 for(const patch of [{pin:"012346"},{customerId:"other"},{tenantId:"other"},{pepper:randomBytes(32)}])
   assert.equal(await verifyPinCredential({...scope,...patch},a),false);
});
test("malformed PIN or credential is rejected, missing pepper fails closed",async()=>{
 await assert.rejects(createPinCredential({...scope,pin:"1234"}),/six digits/);
 assert.equal(await verifyPinCredential(scope,{salt:"bad",pinHash:"bad"}),false);
 await assert.rejects(verifyPinCredential({...scope,pepper:Buffer.alloc(1)},{}),/unavailable/);
});

import test from "node:test";
import assert from "node:assert/strict";
import {consumeReleaseProof} from "./consume-release-proof.mjs";
const scope={tenantId:"t1",milestoneId:"m1",customerId:"c1",authorizationRef:"p1",amountCents:5000,requestId:"r1"};
test("rejects incomplete proof scope without querying",async()=>{
 let calls=0;await assert.rejects(consumeReleaseProof({query:async()=>{calls++;}}, {...scope,customerId:""}),/Invalid/);
 assert.equal(calls,0);
});
test("consumes only exact scoped proof using conditional update",async()=>{
 let sql,params;const client={query:async(s,p)=>{sql=s;params=p;return {rowCount:1};}};
 assert.equal(await consumeReleaseProof(client,scope),true);
 assert.match(sql,/consumed_at IS NULL/);
 assert.match(sql,/expires_at>now\(\)/);
 assert.deepEqual(params,["t1","m1","c1","p1","5000","r1"]);
});
test("rejects expired, mismatched or already consumed proofs",async()=>{
 assert.equal(await consumeReleaseProof({query:async()=>({rowCount:0})},scope),false);
});
test("rejects malformed payment amounts",async()=>{
 await assert.rejects(consumeReleaseProof({query:async()=>({rowCount:1})},{...scope,amountCents:-1}),/Invalid/);
});

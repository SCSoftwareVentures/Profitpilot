import test from "node:test";
import assert from "node:assert/strict";
import {createReadinessGuard} from "../server/readiness-guard.js";
test("readiness coalesces concurrent checks and denies stale evidence",async()=>{
 let now=0,calls=0,mode=true;
 const guard=createReadinessGuard(async()=>{calls++;if(mode==="error")throw Error("synthetic outage");return mode;},{clock:()=>now});
 assert.deepEqual(await Promise.all(Array.from({length:16},()=>guard.check())),Array(16).fill(true));
 assert.equal(calls,1);
 now=14999;assert.equal(await guard.check(),true);assert.equal(calls,1);
 mode=false;now=15000;assert.equal(await guard.check(),false);assert.equal(calls,2);
 let dispatched=0;const res={statusCode:0,headers:{},set(k,v){this.headers[k]=v;return this;},status(v){this.statusCode=v;return this;},json(v){this.body=v;}};
 await guard.middleware({},res,()=>dispatched++);
 assert.equal(dispatched,0);assert.equal(res.statusCode,503);assert.equal(res.headers["Retry-After"],"3");
 now=18000;mode="error";assert.equal(await guard.check(),false);
 now=21000;mode=true;await guard.middleware({},res,()=>dispatched++);assert.equal(dispatched,1);
});

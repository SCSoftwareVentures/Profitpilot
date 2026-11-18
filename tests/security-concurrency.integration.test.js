import test from "node:test";
import assert from "node:assert/strict";
import {randomBytes} from "node:crypto";
import pg from "pg";
import {sharedLimiter} from "../server/shared-rate-limit.js";
function call(middleware,ip){
 let status=200,passed=false;const headers=new Map();
 const res={get:k=>headers.get(k),set:(k,v)=>headers.set(k,v),status:n=>{status=n;return res;},json:()=>res};
 return middleware({ip,socket:{}},res,()=>{passed=true;}).then(()=>({status,passed}));
}
test("concurrent replicas enforce one shared quota and recover after a locked counter",{skip:!process.env.TEST_APP_DATABASE_URL,timeout:60000},async()=>{
 const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL,max:2});
 const pools=Array.from({length:4},()=>new pg.Pool({connectionString:process.env.TEST_APP_DATABASE_URL,max:4,statement_timeout:3000}));
 const env={RATE_LIMIT_HASH_SECRET:randomBytes(32).toString("hex")};
 const global=pools.map(p=>sharedLimiter({limit:100,scope:"global"},p,env));
 const write=pools.map(p=>sharedLimiter({limit:60,scope:"write"},p,env));
 try{
  const clock=(await admin.query("SELECT (60-mod(floor(extract(epoch from clock_timestamp()))::bigint,60))::int AS remaining")).rows[0];
  if(clock.remaining<20)await new Promise(resolve=>setTimeout(resolve,(clock.remaining+1)*1000));
  const results=await Promise.all(Array.from({length:64},(_,i)=>call(write[i%4],"198.51.100.42")));
  assert.equal(results.filter(x=>x.passed).length,60);
  assert.equal(results.filter(x=>x.status===429).length,4);
  const second=await Promise.all(Array.from({length:64},(_,i)=>call(global[i%4],"198.51.100.42")));
  assert.equal(second.filter(x=>x.passed).length,64);
  const third=await Promise.all(Array.from({length:64},(_,i)=>call(global[i%4],"198.51.100.42")));
  assert.equal(third.filter(x=>x.passed).length,36);
  assert.equal(third.filter(x=>x.status===429).length,28);
  const unrelated=await Promise.all(Array.from({length:16},(_,i)=>call(write[i%4],"203.0.113."+(i+1))));
  assert.ok(unrelated.every(x=>x.passed));
  // Force a database-side lock timeout. No request may bypass a blocked
  // limiter, and the same instance must recover when the lock clears.
  const {createHmac}=await import("node:crypto");
  const digest=createHmac("sha256",Buffer.from(env.RATE_LIMIT_HASH_SECRET,"hex")).update("write\n192.0.2.123").digest("hex");
  const bucket="write:"+digest;
  assert.equal((await call(write[0],"192.0.2.123")).passed,true);
  const locker=await admin.connect();
  try{
   await locker.query("BEGIN");
   await locker.query("SELECT 1 FROM public.api_rate_limits WHERE bucket_key=$1 FOR UPDATE",[bucket]);
   const denied=await call(write[1],"192.0.2.123");
   assert.equal(denied.status,503);assert.equal(denied.passed,false);
  }finally{await locker.query("ROLLBACK");locker.release();}
  assert.equal((await call(write[1],"192.0.2.123")).passed,true);
 }finally{await Promise.all([admin.end(),...pools.map(p=>p.end())]);}
});

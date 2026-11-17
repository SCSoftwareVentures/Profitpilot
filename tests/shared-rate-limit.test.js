import test from "node:test";
import assert from "node:assert/strict";
import {randomBytes} from "node:crypto";
import pg from "pg";
import {sharedLimiter} from "../server/shared-rate-limit.js";

const env={RATE_LIMIT_HASH_SECRET:"a".repeat(64)};
function invoke(middleware,ip="192.0.2.10",prior){
 const headers=new Map(prior===undefined?[]:[["RateLimit-Remaining",String(prior)]]);
 let status=200,body;
 const res={get:n=>headers.get(n),set:(n,v)=>headers.set(n,v),status:n=>{status=n;return res;},json:v=>{body=v;return res;}};
 return middleware({ip,socket:{}},res,()=>{}).then(()=>({status,body,headers}));
}
test("shared limiter rejects invalid scope, limit and window",()=>{
 for(const options of [{limit:0,scope:"global"},{limit:60,scope:""},{limit:100,scope:"global",windowMs:100},{limit:60,scope:"toString"},{limit:60,scope:"global"}])assert.throws(()=>sharedLimiter(options));
});
test("limiter denies database failures, missing key and malformed counters",async()=>{
 const good={query:async()=>({rows:[{total_hits:1,retry_after:50}]})};
 for(const [db,e] of [[{query:async()=>{throw Error("private db detail");}},env],[good,{}],[{query:async()=>({rows:[{total_hits:0,retry_after:30}]})},env]]){
  const response=await invoke(sharedLimiter({limit:100,scope:"global"},db,e));
  assert.equal(response.status,503);
  assert.equal(response.headers.get("Retry-After"),"5");
  assert.doesNotMatch(JSON.stringify(response.body),/private db detail/);
 }
});
test("hashes addresses canonically, separates scopes and preserves stricter remaining budget",async()=>{
 const keys=[];
 const db={query:async(sql,args)=>{keys.push(args[0]);return {rows:[{total_hits:1,retry_after:30}]};}};
 const global=sharedLimiter({limit:100,scope:"global"},db,env);
 const write=sharedLimiter({limit:60,scope:"write"},db,env);
 for(const ip of ["192.0.2.10","::ffff:192.0.2.10","::ffff:c000:20a","2001:db8::1","2001:0db8:0:0::1234","2001:db8:0:1::1"])assert.equal((await invoke(global,ip)).status,200);
 assert.equal(keys[0],keys[1]);assert.equal(keys[0],keys[2]);
 assert.equal(keys[3],keys[4]);assert.notEqual(keys[3],keys[5]);
 const response=await invoke(write,"192.0.2.10",3);
 assert.equal(response.headers.get("RateLimit-Remaining"),"3");
 assert.notEqual(keys[0],keys[6]);assert.match(keys[6],/^write:[0-9a-f]{64}$/);
});
test("local backpressure rejects overflow without sending more DB queries",async()=>{
 let release,calls=0;
 const blocked=new Promise(resolve=>{release=resolve;});
 const db={query:async()=>{calls++;await blocked;return {rows:[{total_hits:1,retry_after:30}]};}};
 const middleware=sharedLimiter({limit:100,scope:"global"},db,env);
 const first=Array.from({length:20},()=>invoke(middleware));
 try{assert.equal((await invoke(middleware)).status,503);assert.equal(calls,20);}
 finally{release();await Promise.all(first);}
 assert.equal((await invoke(middleware)).status,200);
});

test("real PostgreSQL: separate API instances share quota, runtime cannot reset counters, retention preserves active windows",{skip:!process.env.TEST_APP_DATABASE_URL,timeout:45000},async()=>{
 const a=new pg.Pool({connectionString:process.env.TEST_APP_DATABASE_URL,max:5,statement_timeout:3000});
 const b=new pg.Pool({connectionString:process.env.TEST_APP_DATABASE_URL,max:5,statement_timeout:3000});
 const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
 const key={RATE_LIMIT_HASH_SECRET:randomBytes(32).toString("hex")};
 const old="global:"+randomBytes(32).toString("hex");
 try{
  assert.ok(process.env.TEST_ADMIN_DATABASE_URL,"integration requires admin fixture URL");
  // Start with enough time left in the database's current minute.
  const clock=await admin.query("SELECT (60-mod(floor(extract(epoch from clock_timestamp()))::bigint,60))::int AS remaining");
  if(clock.rows[0].remaining<15)await new Promise(resolve=>setTimeout(resolve,(clock.rows[0].remaining+1)*1000));
  const first=sharedLimiter({limit:60,scope:"write"},a,key);
  const second=sharedLimiter({limit:60,scope:"write"},b,key);
  const responses=[];
  for(let n=0;n<70;n+=10)responses.push(...await Promise.all(Array.from({length:10},(_,i)=>invoke(i%2?first:second))));
  assert.equal(responses.filter(x=>x.status===200).length,60);
  assert.equal(responses.filter(x=>x.status===429).length,10);
  assert.ok(responses.filter(x=>x.status===429).every(x=>Number(x.headers.get("Retry-After"))>=1));
  await assert.rejects(()=>a.query("DELETE FROM public.api_rate_limits"),/permission denied/i);
  await assert.rejects(()=>a.query("UPDATE public.api_rate_limits SET request_count=1"),/permission denied/i);
  await assert.rejects(()=>a.query("SELECT * FROM public.api_rate_limits"),/permission denied/i);
  await assert.rejects(()=>a.query("SELECT * FROM public.consume_api_rate_limit('raw-ip')"),/Invalid rate-limit bucket/);
  await admin.query("INSERT INTO public.api_rate_limits(bucket_key,window_start,request_count) VALUES($1, floor(extract(epoch from clock_timestamp())/60)::bigint-10,1)",[old]);
  const purge=await a.query("SELECT public.purge_api_rate_limits() AS removed");
  assert.ok(purge.rows[0].removed>=1);
  assert.equal((await admin.query("SELECT 1 FROM public.api_rate_limits WHERE bucket_key=$1",[old])).rowCount,0);
  assert.equal((await invoke(second)).status,429);
 }finally{await Promise.all([a.end(),b.end(),admin.end()]);}
});

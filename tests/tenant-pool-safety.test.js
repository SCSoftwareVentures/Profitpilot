import test from "node:test";
import assert from "node:assert/strict";
import {createHmac} from "node:crypto";
import {withTenantUsingPool} from "../server/db.js";

const env={NODE_ENV:"test",PROFITPILOT_PROFILE:"prototype",
 TENANT_CONTEXT_HMAC_SECRET:"a".repeat(64),TENANT_CONTEXT_HMAC_KEY_ID:"tenant-test-key"};
const tenant="11111111-1111-4111-8111-111111111111";
const subject="synthetic-provider|test-subject";
function harness(failAt=[]){
 const events=[],client={
  releaseCount:0,releaseError:null,
  async query(sql,params){
   events.push({sql,params});
   if(failAt.some(v=>sql===v))throw Error("synthetic connection failure at "+sql);
   return {rowCount:1,rows:[{ok:1}]};
  },
  release(err){
   this.releaseCount++;
   this.releaseError=err;
  }
 };
 let connections=0;
 return {client,events,pool:{async connect(){connections++;return client;}},
  get connections(){return connections;}};
}

test("B15 tenant transaction sets scoped LOCAL context, commits and releases clean connection",async()=>{
 const h=harness();
 const result=await withTenantUsingPool(h.pool,tenant,subject,
  async client=>{await client.query("SELECT 42");return "ok";},
  {repeatableRead:true,env});
 assert.equal(result,"ok");
 assert.equal(h.events[0].sql,"BEGIN ISOLATION LEVEL REPEATABLE READ");
 assert.equal(h.events[1].sql.includes("statement_timeout"),true);
 assert.match(h.events[2].sql,/set_config\('app.tenant_id'/);
 assert.deepEqual(h.events[2].params.slice(0,2),[tenant,subject]);
 assert.match(h.events[2].params[5],/^[a-f0-9]{64}$/);
 assert.equal(h.events.at(-1).sql,"COMMIT");
 assert.equal(h.client.releaseCount,1);
 assert.equal(h.client.releaseError,undefined);
});

test("B15 callback failure with successful rollback preserves original error and safely returns connection",async()=>{
 const h=harness(),original=Error("synthetic business failure");
 await assert.rejects(()=>withTenantUsingPool(h.pool,tenant,subject,async()=>{
  throw original;
 },{env}),e=>e===original);
 assert.equal(h.events.at(-1).sql,"ROLLBACK");
 assert.equal(h.client.releaseCount,1);
 assert.equal(h.client.releaseError,undefined);
});

test("B15 failed rollback destroys potentially contaminated tenant connection",async()=>{
 const h=harness(["ROLLBACK"]);
 await assert.rejects(()=>withTenantUsingPool(h.pool,tenant,subject,async()=>{
  throw Error("application callback failed");
 },{env}),e=>{
  assert.ok(e instanceof AggregateError);
  assert.equal(e.errors.length,2);
  assert.match(e.errors[0].message,/callback failed/);
  assert.match(e.errors[1].message,/connection failure at ROLLBACK/);
  return true;
 });
 assert.equal(h.client.releaseCount,1);
 assert.ok(h.client.releaseError instanceof Error);
 assert.match(h.client.releaseError.message,/Unsafe tenant session/);
});

test("B15 COMMIT uncertainty plus failed ROLLBACK also discards the connection",async()=>{
 const h=harness(["COMMIT","ROLLBACK"]);
 await assert.rejects(()=>withTenantUsingPool(h.pool,tenant,subject,
  async client=>{await client.query("SELECT 42");return "never";},{env}),AggregateError);
 assert.equal(h.events.at(-2).sql,"COMMIT");
 assert.equal(h.events.at(-1).sql,"ROLLBACK");
 assert.ok(h.client.releaseError instanceof Error);
 assert.equal(h.client.releaseCount,1);
});

test("B15 refuses unverified actor or signing key before borrowing any connection",async()=>{
 const h=harness();
 await assert.rejects(()=>withTenantUsingPool(h.pool,tenant,"\n",()=>{}, {env}),
  /Verified identity/);
 await assert.rejects(()=>withTenantUsingPool(h.pool,tenant,subject,()=>{},
  {env:{...env,TENANT_CONTEXT_HMAC_SECRET:"short"}}),/at least 32 bytes/);
 assert.equal(h.connections,0);
});


test("B21 ambiguous COMMIT after successful callback discards connection even when ROLLBACK succeeds",async()=>{
 const h=harness(["COMMIT"]);
 let callbacks=0;
 await assert.rejects(()=>withTenantUsingPool(h.pool,tenant,subject,
  async client=>{callbacks++;await client.query("SELECT 42");return "not safely acknowledged";},{env}),error=>{
   assert.equal(error instanceof AggregateError,false);
   assert.match(error.message,/synthetic connection failure at COMMIT/);
   return true;
  });
 assert.equal(callbacks,1,"commit uncertainty must never auto-retry business writes");
 assert.deepEqual(h.events.slice(-2).map(x=>x.sql),["COMMIT","ROLLBACK"]);
 assert.equal(h.client.releaseCount,1);
 assert.ok(h.client.releaseError instanceof Error,"a successful rollback must not return the uncertain connection");
 assert.match(h.client.releaseError.message,/Unsafe tenant session after uncertain commit/);
});

test("B21 signed tenant context accepts uppercase UUID but always signs PostgreSQL canonical lowercase UUID",async()=>{
 const h=harness();
 const result=await withTenantUsingPool(h.pool,tenant.toUpperCase(),subject,
  async()=>42,{env:{...env,TENANT_CONTEXT_HMAC_KEY_ID:"rotated-key_2026:11"}});
 assert.equal(result,42);
 const [id,actor,expires,nonce,keyId,signature]=h.events[2].params;
 assert.equal(id,tenant);
 assert.equal(actor,subject);
 assert.equal(keyId,"rotated-key_2026:11");
 const computed=createHmac("sha256",Buffer.from(env.TENANT_CONTEXT_HMAC_SECRET,"hex"))
  .update([id,actor,expires,nonce,keyId].join("\n")).digest("hex");
 assert.equal(signature,computed);
 assert.equal(h.client.releaseCount,1);
 assert.equal(h.client.releaseError,undefined);
});

test("B21 rejects malformed or injection-shaped tenant identifiers before borrowing pooled connections",async()=>{
 const h=harness();
 const valid=async id=>withTenantUsingPool(h.pool,id,subject,async()=>null,{env});
 for(const invalid of [
  "","1","00000000-0000-0000-0000-000000000000",tenant+"\nother",
  tenant+"  "," "+tenant,"non-uuid","8".repeat(1024),null,{},0,
  "11111111-1111-4111-7111-111111111111"
 ])await assert.rejects(()=>valid(invalid),/Validated tenant UUID/);
 assert.equal(h.connections,0,"no database session should be borrowed for invalid tenant IDs");
});

test("B21 fails closed on malformed signing key identifiers before reading secret or borrowing pool",async()=>{
 const h=harness();
 for(const keyId of [""," "," key","key\nother","key/other",
   "../primary","x".repeat(65),0,{},null]){
  if(keyId===null)continue; // null chooses the documented default via nullish fallback
  await assert.rejects(()=>withTenantUsingPool(h.pool,tenant,subject,()=>null,
   {env:{...env,TENANT_CONTEXT_HMAC_KEY_ID:keyId}}),/Valid bounded tenant signing key ID/);
 }
 assert.equal(h.connections,0);
 const h2=harness();
 await withTenantUsingPool(h2.pool,tenant,subject,async()=>true,
  {env:{...env,TENANT_CONTEXT_HMAC_KEY_ID:undefined}});
 assert.equal(h2.events[2].params[4],"primary");
});

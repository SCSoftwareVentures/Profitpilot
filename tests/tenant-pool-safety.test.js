import test from "node:test";
import assert from "node:assert/strict";
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

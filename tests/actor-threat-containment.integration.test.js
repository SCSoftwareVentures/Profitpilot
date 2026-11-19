import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";

test("actor containment is atomic, scoped, time-limited and auditable",{skip:!process.env.TEST_APP_DATABASE_URL,timeout:45000},async()=>{
 const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
 process.env.NODE_ENV="test";process.env.DATABASE_URL=process.env.TEST_APP_DATABASE_URL;
 const {pool,withTenant}=await import("../server/db.js");
 const tenant="33333333-3333-4333-8333-333333333333",actor="55555555-5555-4555-8555-555555555555",other="44444444-4444-4444-8444-444444444444",subject="isolation-tenant-c";
 const admit=(t=tenant,s=subject)=>withTenant(t,s,async c=>(await c.query("SELECT private.admit_actor_request($1) AS retry",[t])).rows[0].retry);
 const state=async()=>(await admin.query("SELECT used,blocked_until FROM private.actor_request_security WHERE tenant_id=$1 AND actor_id=$2",[tenant,actor])).rows[0];
 const eventCount=async()=>(await admin.query("SELECT count(*)::int AS n FROM public.audit_events WHERE tenant_id=$1 AND actor_user_id=$2 AND action='actor_burst_containment'",[tenant,actor])).rows[0].n;
 try{
  await admin.query("INSERT INTO private.actor_request_security(tenant_id,actor_id,window_start,used) VALUES($1,$2,clock_timestamp(),119) ON CONFLICT(tenant_id,actor_id) DO UPDATE SET window_start=clock_timestamp(),used=119,blocked_until=NULL",[tenant,actor]);
  const before=await eventCount();
  const results=await Promise.all(Array.from({length:8},()=>admit()));
  assert.equal(results.filter(x=>x===0).length,1);
  assert.equal(results.filter(x=>x>0&&x<=300).length,7);
  const blocked=await state();assert.equal(blocked.used,120);assert.ok(blocked.blocked_until>Date.now());
  assert.equal(await eventCount(),before+1,"only one containment transition is audited");
  assert.ok(await admit()>0);
  assert.equal(+((await state()).blocked_until),+blocked.blocked_until,"denials never extend containment");
  assert.equal(await admit(tenant,"isolation-reviewer-c"),0);
  assert.equal(await admit(other,"isolation-tenant-d"),0);
  await assert.rejects(()=>withTenant(tenant,subject,c=>c.query("SELECT private.admit_actor_request($1)",[other])),e=>e.code==="42501");
  await assert.rejects(()=>pool.query("SELECT private.admit_actor_request($1)",[tenant]),e=>e.code==="42501");
  await assert.rejects(()=>pool.query("UPDATE private.actor_request_security SET blocked_until=NULL"),e=>e.code==="42501");
  await assert.rejects(()=>pool.query("SELECT * FROM private.actor_request_security"),e=>e.code==="42501");
  await admin.query("UPDATE private.actor_request_security SET blocked_until=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND actor_id=$2",[tenant,actor]);
  assert.equal(await admit(),0);
  const recovered=await state();assert.equal(recovered.used,1);assert.equal(recovered.blocked_until,null);
  assert.equal((await admin.query("SELECT private.verify_audit_chain($1) AS ok",[tenant])).rows[0].ok,true);
 }finally{
  await admin.query("DELETE FROM private.actor_request_security WHERE tenant_id IN ($1,$2)",[tenant,other]);
  await Promise.all([admin.end(),pool.end()]);
 }
});

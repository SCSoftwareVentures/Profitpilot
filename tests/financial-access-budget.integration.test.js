import test from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import pg from "pg";

test("financial access budgets serialize concurrent readers, isolate tenants and audit successful access",{skip:!process.env.TEST_APP_DATABASE_URL,timeout:45000},async()=>{
 const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
 process.env.NODE_ENV="test";process.env.DATABASE_URL=process.env.TEST_APP_DATABASE_URL;
 const {pool,withTenant}=await import("../server/db.js");
 const tenant="33333333-3333-4333-8333-333333333333",other="44444444-4444-4444-8444-444444444444",actor="55555555-5555-4555-8555-555555555555",read="isolation-tenant-c",reviewer="isolation-reviewer-c",run="28282828-2828-4828-8828-282828282828",otherRun="29292929-2929-4929-8929-292929292929";
 const get=(subject=read,id=run,t=tenant)=>withTenant(t,subject,async c=>(await c.query("SELECT private.read_calculation_summary($1,$2) AS result",[t,id])).rows[0].result);
 const tenantUsed=async()=>(await admin.query("SELECT used FROM private.financial_tenant_budgets WHERE tenant_id=$1 AND scope='calculation_read'",[tenant])).rows[0].used;
 const actorUsed=async()=>(await admin.query("SELECT used FROM private.financial_actor_budgets WHERE tenant_id=$1 AND actor_id=$2 AND scope='calculation_read'",[tenant,actor])).rows[0].used;
 try{
  await admin.query("INSERT INTO private.financial_tenant_budgets VALUES($1,'calculation_read',clock_timestamp(),1) ON CONFLICT(tenant_id,scope) DO UPDATE SET used=1,window_start=clock_timestamp()",[tenant]);
  await admin.query("INSERT INTO private.financial_actor_budgets VALUES($1,$2,'calculation_read',clock_timestamp(),119) ON CONFLICT(tenant_id,actor_id,scope) DO UPDATE SET used=119,window_start=clock_timestamp()",[tenant,actor]);
  const races=await Promise.allSettled([get(),get()]);
  assert.equal(races.filter(x=>x.status==="fulfilled").length,1);
  assert.equal(races.find(x=>x.status==="rejected").reason.code,"P4501");
  assert.equal(await actorUsed(),120);assert.equal(await tenantUsed(),2);
  await assert.rejects(()=>get(),e=>e.code==="P4501");
  assert.equal(await tenantUsed(),2,"actor denial must roll back tenant quota consumption");
  assert.equal((await get(reviewer)).id,run,"another actor retains access");
  await admin.query("UPDATE private.financial_tenant_budgets SET used=600 WHERE tenant_id=$1 AND scope='calculation_read'",[tenant]);
  await assert.rejects(()=>get(reviewer),e=>e.code==="P4501");
  assert.equal((await get("isolation-tenant-d",otherRun,other)).id,otherRun,"tenant quotas must not affect another tenant");
  await admin.query("UPDATE private.financial_tenant_budgets SET window_start=clock_timestamp()-interval '2 hours' WHERE tenant_id=$1 AND scope='calculation_read'",[tenant]);
  await admin.query("UPDATE private.financial_actor_budgets SET window_start=clock_timestamp()-interval '2 hours' WHERE tenant_id=$1 AND actor_id=$2 AND scope='calculation_read'",[tenant,actor]);
  assert.equal(await get(read,randomUUID()),null,"missing record still consumes an access attempt");
  assert.equal(await tenantUsed(),1);assert.equal(await actorUsed(),1);
  assert.equal((await get()).id,run);
  assert.equal(await actorUsed(),2);
  await assert.rejects(()=>withTenant(tenant,read,c=>c.query("SELECT private.consume_financial_access_budget($1,'calculation_read')",[tenant])),/permission denied/i);
  await assert.rejects(()=>pool.query("UPDATE private.financial_actor_budgets SET used=1"),/permission denied/i);
  const events=await admin.query("SELECT count(*)::int AS n FROM public.audit_events WHERE tenant_id=$1 AND action='calculation_summary_read' AND object_id=$2",[tenant,run]);
  assert.ok(events.rows[0].n>=3);
  assert.equal((await admin.query("SELECT private.verify_audit_chain($1) AS ok",[tenant])).rows[0].ok,true);
 }finally{
  await admin.query("UPDATE private.financial_tenant_budgets SET window_start=clock_timestamp()-interval '2 hours' WHERE tenant_id IN ($1,$2)",[tenant,other]);
  await admin.query("UPDATE private.financial_actor_budgets SET window_start=clock_timestamp()-interval '2 hours' WHERE tenant_id IN ($1,$2)",[tenant,other]);
  await Promise.all([admin.end(),pool.end()]);
 }
});

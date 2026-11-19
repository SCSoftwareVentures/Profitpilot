import test from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import {setTimeout as wait} from "node:timers/promises";
import pg from "pg";
test("concurrent emergency activation fences in-flight tenant transactions; failed authorization cannot leave pooled authority",{skip:!process.env.TEST_APP_DATABASE_URL,timeout:30000},async()=>{
 const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL,max:3,statement_timeout:7000});
 process.env.NODE_ENV="test";process.env.DATABASE_URL=process.env.TEST_APP_DATABASE_URL;
 const {pool,withTenant}=await import("../server/db.js");
 const t="33333333-3333-4333-8333-333333333333",other="44444444-4444-4444-8444-444444444444",subject="isolation-tenant-c",id=randomUUID();
 const operator=await admin.connect();
 let unblock,entered,activation;
 const ready=new Promise(resolve=>{entered=resolve;});
 const hold=new Promise(resolve=>{unblock=resolve;});
 const transaction=withTenant(t,subject,async c=>{
  const gate=await c.query("SELECT private.lock_tenant_available($1) AS ok",[t]);assert.equal(gate.rows[0].ok,true);
  const pid=(await c.query("SELECT pg_backend_pid() AS pid")).rows[0].pid;entered(pid);
  await hold;
  return (await c.query("SELECT count(*)::int AS n FROM public.contracts WHERE tenant_id=$1",[t])).rows[0].n;
 });
 transaction.catch(()=>{});
 try{
  const holder=await Promise.race([ready,transaction.then(()=>{throw Error("Transaction ended before fence test");})]);
  const operatorPid=(await operator.query("SELECT pg_backend_pid() AS pid")).rows[0].pid;
  activation=operator.query("SELECT private.activate_tenant_emergency($1,$2,'data_exposure','CI_RACE_TEST')",[t,id]);activation.catch(()=>{});
  let blocked=false;
  for(let i=0;i<40&&!blocked;i++){
   const r=await admin.query("SELECT $1::integer=ANY(pg_blocking_pids($2::integer)) AS blocked",[holder,operatorPid]);
   blocked=r.rows[0].blocked;if(!blocked)await wait(25);
  }
  assert.equal(blocked,true,"activation must wait for an already authorized tenant transaction");
  unblock();assert.ok(await transaction>0);await activation;
  const attempts=await Promise.all(Array.from({length:8},()=>withTenant(t,subject,async c=>{
   const allowed=(await c.query("SELECT private.lock_tenant_available($1) AS ok",[t])).rows[0].ok;
   const visible=(await c.query("SELECT count(*)::int AS n FROM public.contracts WHERE tenant_id=$1",[t])).rows[0].n;
   return {allowed,visible};
  })));
  assert.ok(attempts.every(x=>x.allowed===false&&x.visible===0));
  assert.ok((await withTenant(other,"isolation-tenant-d",c=>c.query("SELECT id FROM public.contracts"))).rowCount>0);
  // An unsigned GUC and a failed transaction must not expose data on a pooled connection.
  await assert.rejects(()=>withTenant(t,subject,async c=>{
   await c.query("SELECT set_config('app.tenant_id',$1,true)",[other]);throw Error("synthetic rollback");
  }),/synthetic rollback/);
  assert.equal((await pool.query("SELECT count(*)::int AS n FROM public.contracts")).rows[0].n,0);
  await admin.query("SELECT private.release_tenant_emergency($1,$2,'CI_RACE_RECOVERY')",[t,id]);
  assert.ok((await withTenant(t,subject,c=>c.query("SELECT id FROM public.contracts"))).rowCount>0);
 }finally{
  unblock();await transaction.catch(()=>{});if(activation)await activation.catch(()=>{});
  try{await admin.query("SELECT private.release_tenant_emergency($1,$2,'CI_RACE_CLEANUP') WHERE EXISTS(SELECT 1 FROM private.tenant_emergency_incidents WHERE incident_id=$2 AND released_at IS NULL)",[t,id]);}
  finally{operator.release();await Promise.all([pool.end(),admin.end()]);}
 }
});

import test from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import pg from "pg";

test("tenant emergency isolation is role-separated, durable, auditable and reversible only for the exact incident",{skip:!process.env.TEST_APP_DATABASE_URL,timeout:45000},async()=>{
 const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL,max:3});
 process.env.NODE_ENV="test";process.env.DATABASE_URL=process.env.TEST_APP_DATABASE_URL;
 const {pool,withTenant}=await import("../server/db.js");
 const tenant="33333333-3333-4333-8333-333333333333",other="44444444-4444-4444-8444-444444444444";
 const subject="isolation-tenant-c",otherSubject="isolation-tenant-d",id=randomUUID();
 const operator=await admin.connect(),recovery=await admin.connect();
 const activate=(client,incident=id)=>client.query("SELECT private.activate_tenant_emergency($1,$2,'suspected_compromise','CI_INCIDENT')",[tenant,incident]);
 const release=(client,incident=id)=>client.query("SELECT private.release_tenant_emergency($1,$2,'CI_RELEASE')",[tenant,incident]);
 const list=(t=tenant,s=subject)=>withTenant(t,s,c=>c.query("SELECT id FROM public.contracts WHERE tenant_id=$1",[t]));
 const gate=(t=tenant,s=subject)=>withTenant(t,s,c=>c.query("SELECT private.lock_tenant_available($1) AS available",[t]));
 try{
  await operator.query("SET ROLE profitpilot_incident_operator");
  await recovery.query("SET ROLE profitpilot_incident_recovery");
  assert.ok((await list()).rowCount>0);
  assert.ok((await list(other,otherSubject)).rowCount>0);
  assert.equal((await gate()).rows[0].available,true);
  await assert.rejects(()=>activate(pool),/permission denied/i);
  await assert.rejects(()=>release(pool),/permission denied/i);
  await assert.rejects(()=>activate(recovery),/permission denied/i);
  await assert.rejects(()=>release(operator),/permission denied/i);
  await assert.rejects(()=>operator.query("SELECT * FROM private.tenant_emergency_incidents"),/permission denied/i);
  await assert.rejects(()=>recovery.query("UPDATE private.tenant_emergency_incidents SET released_at=now()"),/permission denied/i);
  await activate(operator);
  assert.equal((await list()).rowCount,0);
  assert.equal((await gate()).rows[0].available,false);
  assert.equal((await gate(other,otherSubject)).rows[0].available,true);
  assert.ok((await list(other,otherSubject)).rowCount>0);
  await assert.rejects(()=>activate(operator,randomUUID()),e=>e.code==="23505");
  await assert.rejects(()=>release(recovery,randomUUID()),/does not match/i);
  const active=(await admin.query("SELECT incident_id,released_at FROM private.tenant_emergency_incidents WHERE tenant_id=$1 AND released_at IS NULL",[tenant])).rows;
  assert.deepEqual(active,[{incident_id:id,released_at:null}]);
  await release(recovery);
  assert.ok((await list()).rowCount>0);
  assert.equal((await gate()).rows[0].available,true);
  await assert.rejects(()=>release(recovery),/does not match/i);
  await assert.rejects(()=>activate(operator),e=>e.code==="23505");
  await assert.rejects(()=>admin.query("DELETE FROM private.tenant_emergency_incidents WHERE incident_id=$1",[id]),/append-only/i);
  await assert.rejects(()=>admin.query("UPDATE private.tenant_emergency_incidents SET category='data_exposure' WHERE incident_id=$1",[id]),/immutable/i);
  const events=(await admin.query("SELECT action FROM public.audit_events WHERE tenant_id=$1 AND object_id=$2 ORDER BY action",[tenant,id])).rows.map(x=>x.action);
  assert.deepEqual(events,["emergency_containment_activated","emergency_containment_released"]);
  assert.equal((await admin.query("SELECT private.verify_audit_chain($1) AS ok",[tenant])).rows[0].ok,true);
 }finally{
  try{await admin.query("SELECT private.release_tenant_emergency($1,$2,'CI_CLEANUP') WHERE EXISTS(SELECT 1 FROM private.tenant_emergency_incidents WHERE incident_id=$2 AND released_at IS NULL)",[tenant,id]);}
  finally{await operator.query("RESET ROLE");await recovery.query("RESET ROLE");operator.release();recovery.release();await Promise.all([pool.end(),admin.end()]);}
 }
});

import test from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import pg from "pg";
import {readSecuritySnapshot} from "../scripts/security-command-centre.js";
test("security command centre aggregates incidents and denies financial data, mutation and drifted catalogue visibility",{skip:!process.env.TEST_APP_DATABASE_URL,timeout:45000},async()=>{
 const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL,max:2});
 const runtime=new pg.Pool({connectionString:process.env.TEST_APP_DATABASE_URL,max:1});
 const reader=await admin.connect();
 const tenants=["33333333-3333-4333-8333-333333333333","44444444-4444-4444-8444-444444444444"];
 const ids=[randomUUID(),randomUUID()].sort();
 try{
  await reader.query("SET ROLE profitpilot_security_reader");
  const original=await readSecuritySnapshot(reader,{limit:100,cursor:null});
  assert.equal(original.catalogVerified,true);
  assert.equal(original.counts.activeTenantIncidents,0);
  for(let i=0;i<2;i++)await admin.query("SELECT private.activate_tenant_emergency($1,$2,'suspected_compromise','CI_SECURITY_COMMAND')",[tenants[i],ids[i]]);
  const first=await readSecuritySnapshot(reader,{limit:1,cursor:null});
  assert.equal(first.status,"containment_active");
  assert.equal(first.counts.activeTenantIncidents,2);
  assert.equal(first.activeIncidents[0].incidentId,ids[0]);
  assert.equal(first.nextCursor,ids[0]);
  const second=await readSecuritySnapshot(reader,{limit:1,cursor:first.nextCursor});
  assert.equal(second.activeIncidents[0].incidentId,ids[1]);
  assert.equal(second.nextCursor,null);
  assert.deepEqual(Object.keys(second.activeIncidents[0]).sort(),["activatedAt","category","incidentId","tenantId"]);
  assert.ok(!JSON.stringify(first).includes("CI_SECURITY_COMMAND"));
  await assert.rejects(()=>reader.query("SELECT * FROM public.contracts"),/permission denied/i);
  await assert.rejects(()=>reader.query("SELECT * FROM private.tenant_emergency_incidents"),/permission denied/i);
  await assert.rejects(()=>reader.query("SELECT private.release_tenant_emergency($1,$2,'CI_RELEASE')",[tenants[0],ids[0]]),/permission denied/i);
  await assert.rejects(()=>runtime.query("SELECT private.security_command_snapshot(100,NULL)"),/permission denied/i);
  await assert.rejects(()=>reader.query("SELECT private.security_command_snapshot(101,NULL)"),e=>e.code==="22023");
  await admin.query("GRANT UPDATE(decision) ON public.mapping_decisions TO profitpilot_app");
  try{
   const drift=await readSecuritySnapshot(reader,{limit:100,cursor:null});
   assert.equal(drift.catalogVerified,false);
   assert.equal(drift.status,"catalog_drift");assert.equal(drift.counts,null);assert.equal(drift.activeIncidents,null);
  }finally{await admin.query("REVOKE UPDATE(decision) ON public.mapping_decisions FROM profitpilot_app");}
  assert.equal((await readSecuritySnapshot(reader,{limit:100,cursor:null})).catalogVerified,true);
 }finally{
  try{for(let i=0;i<2;i++)await admin.query("SELECT private.release_tenant_emergency($1,$2,'CI_SECURITY_RECOVERY') WHERE EXISTS(SELECT 1 FROM private.tenant_emergency_incidents WHERE incident_id=$2 AND released_at IS NULL)",[tenants[i],ids[i]]);}
  finally{await reader.query("RESET ROLE");reader.release();await Promise.all([runtime.end(),admin.end()]);}
 }
});
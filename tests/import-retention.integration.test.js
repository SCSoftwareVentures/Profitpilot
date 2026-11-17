import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
test("discarded source payload purge is narrow, held, policy gated and restore-aware",{skip:!process.env.TEST_ADMIN_DATABASE_URL},async()=>{
 const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
 const app=new pg.Pool({connectionString:process.env.TEST_APP_DATABASE_URL});
 const t="88888888-1111-4111-8111-111111111111",u="88888888-2222-4222-8222-222222222222";
 const uuid=n=>"88888888-3333-4333-8333-"+n.toString().padStart(12,"0");
 const [batch,accepted,linked,recent,invoice]=[1,2,3,4,5].map(uuid);
 const purge=(b=batch)=>admin.query("SELECT private.purge_discarded_import($1,$2,'CI retention approval','CI independent dependency review') AS result",[t,b]);
 try{
  await admin.query("INSERT INTO tenants(id,legal_name) VALUES($1,'CI discarded imports')",[t]);
  await admin.query("INSERT INTO users(id,auth_subject,email,auth_issuer) VALUES($1,'discarded-import-ci','discarded@example.invalid','https://ci.invalid')",[u]);
  await admin.query("INSERT INTO tenant_memberships(tenant_id,user_id,role) VALUES($1,$2,'owner')",[t,u]);
  for(const [i,b,s,type,age] of [[1,batch,'rejected','payroll',40],[2,accepted,'accepted','payroll',40],[3,linked,'failed','payroll',40],[4,recent,'failed','payroll',0],[5,invoice,'failed','supplier_invoice',40]]){
   await admin.query("INSERT INTO import_batches(id,tenant_id,source_type,permission_ref,status,file_sha256,file_name,created_by,created_at) VALUES($1,$2,$3,'synthetic',$4,$5,'synthetic.csv',$6,now()-make_interval(days=>$7))",[b,t,type,s,String(i).repeat(64),u,age]);
   await admin.query("INSERT INTO raw_import_rows(tenant_id,batch_id,row_number,payload) VALUES($1,$2,1,$3)",[t,b,JSON.stringify({employee:"Synthetic Person",amount:123})]);
  }
  await assert.rejects(()=>purge(),/retention policy required/i);
  await admin.query("INSERT INTO private.discarded_import_retention_policies(tenant_id,source_type,enabled,minimum_age_days,authority_reference) VALUES($1,'payroll',true,30,'CI only')",[t]);
  await assert.rejects(()=>purge(accepted),/Only a discarded/);
  await assert.rejects(()=>purge(recent),/Retention age/);
  await assert.rejects(()=>purge(invoice),/retention policy required/i);
  await admin.query("INSERT INTO payroll_pools(tenant_id,batch_id,period_start,period_end,total_amount,source_ref) VALUES($1,$2,'2026-01-01','2026-01-31',123,'CI')",[t,linked]);
  await assert.rejects(()=>purge(linked),/Referenced source evidence/);
  await assert.rejects(()=>app.query("SELECT private.purge_discarded_import($1,$2,'abc','def')",[t,batch]),/permission denied/i);
  await assert.rejects(()=>app.query("UPDATE raw_import_rows SET payload='{}' WHERE batch_id=$1",[batch]),/permission denied/i);
  await admin.query("INSERT INTO private.discarded_import_holds(tenant_id,authority_reference) VALUES($1,'CI hold')",[t]);
  await assert.rejects(()=>purge(),/legal hold/);
  await admin.query("DELETE FROM private.discarded_import_holds WHERE tenant_id=$1",[t]);
  const result=(await purge()).rows[0].result;
  assert.deepEqual(result,{batchId:batch,payloadRowsRemoved:1,completePersonalDataDeletion:false});
  assert.deepEqual((await admin.query("SELECT payload FROM raw_import_rows WHERE batch_id=$1",[batch])).rows,[{payload:{}}]);
  await assert.rejects(()=>purge(),/already purged/);
  await assert.rejects(()=>admin.query("UPDATE import_batches SET status='review' WHERE id=$1",[batch]),/immutable/);
  await assert.rejects(()=>admin.query("UPDATE raw_import_rows SET payload='{\"restored\":true}' WHERE batch_id=$1",[batch]),/cannot be restored/);
  await assert.rejects(()=>admin.query("INSERT INTO raw_import_rows(tenant_id,batch_id,row_number,payload) VALUES($1,$2,2,'{}')",[t,batch]),/cannot be restored/);
  await assert.rejects(()=>admin.query("INSERT INTO payroll_pools(tenant_id,batch_id,period_start,period_end,total_amount,source_ref) VALUES($1,$2,'2026-01-01','2026-01-31',123,'CI')",[t,batch]),/cannot be used/);
  const state=(await admin.query("SELECT private.privacy_restore_state() AS state")).rows[0].state;
  assert.deepEqual(state.violations,[]);
  assert.ok(state.markers.some(m=>m.kind==="import_purge"&&m.id===batch&&m.rowCount===1));
  assert.equal((await admin.query("SELECT is_valid FROM private.verify_audit_chain($1)",[t])).rows[0].is_valid,true);
 }finally{await admin.end();await app.end();}
});

import test from "node:test";
import assert from "node:assert/strict";
import {randomUUID,randomBytes} from "node:crypto";
import pg from "pg";
const tenant="33333333-3333-4333-8333-333333333333",actor="55555555-5555-4555-8555-555555555555";
const recoveryBatch="f831ab34-efb8-48b4-9979-434711943ea2";
test("controlled staging disposal honors holds and retention, preserves linked evidence, and denies runtime",{skip:!process.env.TEST_APP_DATABASE_URL},async()=>{
 const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
 const runtime=new pg.Pool({connectionString:process.env.TEST_APP_DATABASE_URL});
 const id=randomUUID(),digest=randomBytes(32).toString("hex"),row=randomUUID();
 const insert=async (batch,sha,kind="customer_invoice")=>admin.query("INSERT INTO import_batches(id,tenant_id,source_type,permission_ref,status,file_sha256,file_name,created_by) VALUES($1,$2,$3,'CI synthetic authority','rejected',$4,'synthetic.csv',$5)",[batch,tenant,kind,sha,actor]);
 try{
  await insert(id,digest);
  await admin.query("INSERT INTO raw_import_rows(id,tenant_id,batch_id,row_number,payload) VALUES($1,$2,$3,1,'{}')",[row,tenant,id]);
  const call=(fn,...args)=>admin.query("SELECT private."+fn+"("+args.map((_,i)=>"$"+(i+1)).join(",")+") AS result",args);
  await assert.rejects(()=>call("execute_import_disposal",tenant,id),/Retention approval missing/);
  await assert.rejects(()=>admin.query("DELETE FROM raw_import_rows WHERE id=$1",[row]),/recorded tombstone/);
  await call("approve_import_disposal",tenant,id,new Date(Date.now()+86400000),"CI_APPROVAL");
  await assert.rejects(()=>call("execute_import_disposal",tenant,id),/not due/);
  await call("set_import_disposal_hold",tenant,id,true,"CI_HOLD");
  await assert.rejects(()=>call("approve_import_disposal",tenant,id,new Date(0),"CI_APPROVAL"),/Active legal hold/);
  await assert.rejects(()=>call("execute_import_disposal",tenant,id),/Active legal hold/);
  await call("set_import_disposal_hold",tenant,id,false,"CI_RELEASE");
  await assert.rejects(()=>call("execute_import_disposal",tenant,id),/Retention approval missing/);
  await call("approve_import_disposal",tenant,id,new Date(0),"CI_APPROVAL");
  await assert.rejects(()=>runtime.query("SELECT private.execute_import_disposal($1,$2)",[tenant,id]),/permission denied/);
  await assert.rejects(()=>runtime.query("SELECT * FROM private.import_disposal_tombstones"),/permission denied/);
  const mapId=randomUUID();
  await admin.query("INSERT INTO mapping_decisions(id,tenant_id,raw_row_id,target_type,decision,method_version) VALUES($1,$2,$3,'invoice_row','held','ci')",[mapId,tenant,row]);
  await assert.rejects(()=>call("execute_import_disposal",tenant,id),/Referenced evidence/);
  await admin.query("DELETE FROM mapping_decisions WHERE id=$1",[mapId]);
  assert.equal((await call("execute_import_disposal",tenant,id)).rows[0].result,1);
  assert.equal((await admin.query("SELECT id FROM import_batches WHERE id=$1",[id])).rowCount,0);
  assert.equal((await admin.query("SELECT id FROM raw_import_rows WHERE id=$1",[row])).rowCount,0);
  assert.equal((await admin.query("SELECT batch_id FROM private.import_disposal_tombstones WHERE batch_id=$1",[id])).rowCount,1);
  await assert.rejects(()=>insert(randomUUID(),digest),/previously disposed/);
  const payroll=randomUUID();await insert(payroll,randomBytes(32).toString("hex"),"payroll");
  await assert.rejects(()=>call("approve_import_disposal",tenant,payroll,new Date(0),"CI_APPROVAL"),/Only rejected or failed invoice/);
  // Seed one approved, unlinked batch for the later pre-disposal backup drill.
  await insert(recoveryBatch,randomBytes(32).toString("hex"));
  await admin.query("INSERT INTO raw_import_rows(tenant_id,batch_id,row_number,payload) VALUES($1,$2,1,'{}')",[tenant,recoveryBatch]);
  await call("approve_import_disposal",tenant,recoveryBatch,new Date(0),"CI_RECOVERY");
 }finally{await Promise.all([admin.end(),runtime.end()]);}
});

import test from "node:test";
import assert from "node:assert/strict";
import {randomUUID,randomBytes} from "node:crypto";
import pg from "pg";
import {MAX_BATCH_ROWS} from "../server/request-budget.js";

test("invoice capacity is atomic, tenant-bound and idempotent even through direct SQL",{skip:!process.env.TEST_APP_DATABASE_URL,timeout:45000},async()=>{
 const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
 process.env.NODE_ENV="test";process.env.DATABASE_URL=process.env.TEST_APP_DATABASE_URL;
 const {pool,withTenant}=await import("../server/db.js");
 const tenant=randomUUID(),user=randomUUID(),subject="ci-capacity-"+user,batch=randomUUID();
 try{
  await admin.query("INSERT INTO public.tenants(id,legal_name) VALUES($1,'Synthetic capacity tenant')",[tenant]);
  await admin.query("INSERT INTO public.users(id,auth_subject,email,status) VALUES($1,$2,'capacity@example.invalid','active')",[user,subject]);
  await admin.query("INSERT INTO public.tenant_memberships(tenant_id,user_id,role,status) VALUES($1,$2,'analyst','active')",[tenant,user]);
  await admin.query("INSERT INTO public.import_batches(id,tenant_id,source_type,permission_ref,status,file_sha256,file_name,created_by) VALUES($1,$2,'customer_invoice','CI capacity','registered',$3,'synthetic.csv',$4)",[batch,tenant,randomBytes(32).toString("hex"),user]);
  const insert=(first,last)=>withTenant(tenant,subject,c=>c.query("INSERT INTO public.raw_import_rows(tenant_id,batch_id,row_number,payload) SELECT $1,$2,n,jsonb_build_object('invoice_id','CI-'||n) FROM generate_series($3::integer,$4::integer) n ON CONFLICT(batch_id,row_number) DO NOTHING RETURNING id",[tenant,batch,first,last]));
  // Seed near the ceiling as a privileged synthetic fixture; the same trigger
  // must count those rows as well as inserts through the ordinary app role.
  await admin.query("INSERT INTO public.raw_import_rows(tenant_id,batch_id,row_number,payload) SELECT $1,$2,n,jsonb_build_object('invoice_id','CI-'||n) FROM generate_series(1,$3::integer) n",[tenant,batch,MAX_BATCH_ROWS-2]);
  const racing=await Promise.allSettled([insert(MAX_BATCH_ROWS-1,MAX_BATCH_ROWS),insert(MAX_BATCH_ROWS+1,MAX_BATCH_ROWS+2)]);
  assert.equal(racing.filter(x=>x.status==="fulfilled").length,1);
  const failed=racing.find(x=>x.status==="rejected");assert.equal(failed.reason.code,"54000");
  const count=await admin.query("SELECT count(*)::integer AS n FROM public.raw_import_rows WHERE tenant_id=$1 AND batch_id=$2",[tenant,batch]);
  assert.equal(count.rows[0].n,MAX_BATCH_ROWS);
  const counter=await admin.query("SELECT used_rows::integer AS n FROM private.invoice_batch_row_budget WHERE tenant_id=$1 AND batch_id=$2",[tenant,batch]);
  assert.equal(counter.rows[0].n,MAX_BATCH_ROWS);
  assert.equal((await insert(1,1)).rowCount,0,"identical retry must not consume quota");
  await assert.rejects(()=>insert(MAX_BATCH_ROWS+3,MAX_BATCH_ROWS+4),e=>e.code==="54000");
  await assert.rejects(()=>pool.query("SELECT * FROM private.invoice_batch_row_budget"),/permission denied/i);
  await assert.rejects(()=>pool.query("UPDATE private.invoice_batch_row_budget SET used_rows=1"),/permission denied/i);
  assert.equal((await admin.query("SELECT count(*)::integer AS n FROM public.raw_import_rows WHERE tenant_id=$1 AND batch_id=$2",[tenant,batch])).rows[0].n,MAX_BATCH_ROWS);
 }finally{await Promise.all([admin.end(),pool.end()]);}
});

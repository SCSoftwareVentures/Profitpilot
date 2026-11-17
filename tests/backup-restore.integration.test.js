import test from "node:test";
import assert from "node:assert/strict";
import {createHmac,randomBytes} from "node:crypto";
import pg from "pg";

const enabled=Boolean(process.env.TEST_RESTORE_ADMIN_DATABASE_URL);
test("synthetic logical backup restores all source rows and preserves tenant boundaries",{skip:!enabled,timeout:40000},async()=>{
 const source=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL,max:2});
 const restored=new pg.Pool({connectionString:process.env.TEST_RESTORE_ADMIN_DATABASE_URL,max:2});
 const runtime=new pg.Pool({connectionString:process.env.TEST_RESTORE_APP_DATABASE_URL,max:2});
 const list=`SELECT n.nspname AS schema,c.relname AS name FROM pg_class c
 JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname IN ('public','private') AND c.relkind IN ('r','p')
 ORDER BY n.nspname,c.relname`;
 const quote=x=>'"'+x.replaceAll('"','""')+'"';
 try{
  const tables=(await source.query(list)).rows;
  assert.ok(tables.length>=20,"restore audit requires populated application schema");
  assert.deepEqual((await restored.query(list)).rows,tables);
  // Compare counts and deterministic row-multiset fingerprints, including
  // private key records, without logging row data or fingerprint values.
  for(const table of tables){
   const name=quote(table.schema)+"."+quote(table.name);
   const query=`SELECT count(*)::text AS n,md5(coalesce(string_agg(h,',' ORDER BY h),'')) AS fingerprint FROM (SELECT md5(to_jsonb(t)::text) AS h FROM ${name} t) fingerprints`;
   const a=(await source.query(query)).rows[0],b=(await restored.query(query)).rows[0];
   assert.ok(a.n===b.n&&a.fingerprint===b.fingerprint,"restored content mismatch: "+name);
  }
  assert.equal((await runtime.query("SELECT id FROM public.contracts")).rowCount,0,"unsigned connections must not enumerate restored contracts");
  await assert.rejects(()=>runtime.query("SELECT secret FROM private.tenant_context_keys"),/permission denied/i);
  const tenant="33333333-3333-4333-8333-333333333333",subject="isolation-tenant-c";
  const result=await restored.query("SELECT key_id,secret FROM private.tenant_context_keys WHERE active ORDER BY key_id LIMIT 1");
  assert.equal(result.rowCount,1,"restored database must have active tenant context key");
  const {key_id:keyId,secret}=result.rows[0];
  const expires=String(Math.floor(Date.now()/1000)+30),nonce=randomBytes(16).toString("hex");
  const signature=createHmac("sha256",secret).update([tenant,subject,expires,nonce,keyId].join("\n")).digest("hex");
  const client=await runtime.connect();
  try{
   await client.query("BEGIN");
   await client.query("SELECT set_config('app.tenant_id',$1,true),set_config('app.tenant_subject',$2,true),set_config('app.tenant_expires',$3,true),set_config('app.tenant_nonce',$4,true),set_config('app.tenant_key_id',$5,true),set_config('app.tenant_signature',$6,true)",[tenant,subject,expires,nonce,keyId,signature]);
   const own=await client.query("SELECT tenant_id FROM public.contracts");
   assert.ok(own.rowCount>0,"valid signed identity must retain access after restoration");
   assert.ok(own.rows.every(x=>x.tenant_id===tenant),"restored signed context must isolate tenants");
   await assert.rejects(()=>client.query("DELETE FROM public.audit_events"),/permission denied/i);
  }finally{try{await client.query("ROLLBACK");}finally{client.release();}}
  assert.equal((await runtime.query("SELECT id FROM public.contracts")).rowCount,0,"restored pooled connection must clear signed context");
  for(const id of [tenant,"44444444-4444-4444-8444-444444444444"]){
   assert.equal((await restored.query("SELECT private.verify_audit_chain($1) AS ok",[id])).rows[0].ok,true,"restored audit chain integrity");
  }
  // Snapshot predates disposal: authoritative source ledger is consulted after restore.
  const batch="f831ab34-efb8-48b4-9979-434711943ea2";
  assert.equal((await restored.query("SELECT id FROM public.import_batches WHERE tenant_id=$1 AND id=$2",[tenant,batch])).rowCount,1);
  assert.equal((await source.query("SELECT private.execute_import_disposal($1,$2) AS removed",[tenant,batch])).rows[0].removed,1);
  const tombstone=(await source.query("SELECT file_sha256,authority_ref,disposed_at::text AS disposed_at FROM private.import_disposal_tombstones WHERE tenant_id=$1 AND batch_id=$2",[tenant,batch])).rows[0];
  const args=[tenant,batch,tombstone.file_sha256,tombstone.authority_ref,tombstone.disposed_at];
  await assert.rejects(()=>restored.query("SELECT private.replay_import_disposal($1,$2,$3,$4,$5)",[tenant,batch,"0".repeat(64),tombstone.authority_ref,tombstone.disposed_at]),/does not match/);
  assert.equal((await restored.query("SELECT private.replay_import_disposal($1,$2,$3,$4,$5) AS removed",args)).rows[0].removed,1);
  assert.equal((await restored.query("SELECT private.replay_import_disposal($1,$2,$3,$4,$5) AS removed",args)).rows[0].removed,0);
  assert.equal((await restored.query("SELECT id FROM public.import_batches WHERE tenant_id=$1 AND id=$2",[tenant,batch])).rowCount,0);
  assert.equal((await restored.query("SELECT id FROM public.raw_import_rows WHERE tenant_id=$1 AND batch_id=$2",[tenant,batch])).rowCount,0);
  await assert.rejects(()=>runtime.query("SELECT * FROM private.import_disposal_tombstones"),/permission denied/i);
 }finally{await Promise.all([source.end(),restored.end(),runtime.end()]);}
});

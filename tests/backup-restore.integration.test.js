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
 }finally{await Promise.all([source.end(),restored.end(),runtime.end()]);}
});

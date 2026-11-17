import test from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import pg from "pg";

test("audit chain rejects direct writes and detects historical tampering",{skip:!process.env.TEST_APP_DATABASE_URL,timeout:30000},async()=>{
 const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
 const app=new pg.Pool({connectionString:process.env.TEST_APP_DATABASE_URL});
 const tenant="33333333-3333-4333-8333-333333333333",other="44444444-4444-4444-8444-444444444444";
 const event=randomUUID();
 let client;
 try{
  assert.equal((await admin.query("SELECT private.verify_audit_chain($1) AS ok",[tenant])).rows[0].ok,true);
  assert.equal((await admin.query("SELECT private.verify_audit_chain($1) AS ok",[other])).rows[0].ok,true);
  const prior=(await admin.query("SELECT entry_count,head_hash FROM private.audit_chain_heads WHERE tenant_id=$1",[tenant])).rows[0];
  await admin.query("INSERT INTO public.audit_events(id,tenant_id,action,object_type) VALUES($1,$2,'ci_integrity_fixture','fixture')",[event,tenant]);
  const after=(await admin.query("SELECT entry_count,head_hash FROM private.audit_chain_heads WHERE tenant_id=$1",[tenant])).rows[0];
  assert.equal(BigInt(after.entry_count),BigInt(prior.entry_count)+1n);
  assert.notEqual(after.head_hash,prior.head_hash);
  await assert.rejects(()=>app.query("INSERT INTO public.audit_events(tenant_id,action,object_type) VALUES($1,'forged','fixture')",[tenant]),/permission denied/i);
  await assert.rejects(()=>app.query("SELECT * FROM private.audit_chain_entries"),/permission denied/i);
  await assert.rejects(()=>app.query("SELECT private.verify_audit_chain($1)",[tenant]),/permission denied/i);
  await assert.rejects(()=>admin.query("UPDATE public.audit_events SET action='tamper' WHERE id=$1",[event]),/append-only/i);
  await assert.rejects(()=>admin.query("DELETE FROM public.audit_events WHERE id=$1",[event]),/append-only/i);
  await assert.rejects(()=>admin.query("UPDATE private.audit_chain_entries SET event_hash=repeat('1',64) WHERE event_id=$1",[event]),/append-only/i);
  client=await admin.connect();await client.query("BEGIN");
  try{
   // Simulates a privileged operator deliberately bypassing a normal guard.
   await client.query("ALTER TABLE public.audit_events DISABLE TRIGGER audit_event_immutable");
   await client.query("UPDATE public.audit_events SET action='tamper' WHERE id=$1",[event]);
   assert.equal((await client.query("SELECT private.verify_audit_chain($1) AS ok",[tenant])).rows[0].ok,false);
   assert.equal((await client.query("SELECT private.verify_audit_chain($1) AS ok",[other])).rows[0].ok,true);
  }finally{await client.query("ROLLBACK");client.release();client=null;}
  assert.equal((await admin.query("SELECT private.verify_audit_chain($1) AS ok",[tenant])).rows[0].ok,true);
 }finally{if(client)client.release();await Promise.all([admin.end(),app.end()]);}
});

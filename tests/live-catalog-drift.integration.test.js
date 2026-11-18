import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";

test("live catalog verification detects policy, permissions, trigger and function drift without exposing baseline",{skip:!process.env.TEST_APP_DATABASE_URL,timeout:45000},async()=>{
 const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL,max:1});
 const runtime=new pg.Pool({connectionString:process.env.TEST_APP_DATABASE_URL,max:1});
 const c=await admin.connect();
 const verify=async(db)=>(await db.query("SELECT private.verify_security_catalog() AS ok")).rows[0].ok;
 try{
  assert.equal(await verify(c),true);assert.equal(await verify(runtime),true);
  await assert.rejects(()=>runtime.query("SELECT * FROM private.security_catalog_baseline"),/permission denied/i);
  await assert.rejects(()=>runtime.query("SELECT private.security_catalog_digest()"),/permission denied/i);
  await assert.rejects(()=>c.query("UPDATE private.security_catalog_baseline SET digest=repeat('0',64)"),/append-only/i);
  const internal=(await c.query("SELECT tgname FROM pg_trigger WHERE tgrelid='public.invoices'::regclass AND tgisinternal ORDER BY tgname LIMIT 1")).rows[0].tgname;
  for(const ddl of [
   "ALTER TABLE public.invoices DISABLE TRIGGER "+'"'+internal.replaceAll('"','""')+'"',
   "ALTER ROLE profitpilot_context_owner LOGIN",
   "CREATE POLICY drift_allow ON public.invoices USING(true)",
   "ALTER POLICY tenant_isolation ON public.invoices USING(true)",
   "ALTER TABLE public.invoices NO FORCE ROW LEVEL SECURITY",
   "GRANT SELECT(inputs) ON public.calculation_runs TO profitpilot_app",
   "GRANT EXECUTE ON FUNCTION private.approve_quarantine_promotion(uuid,uuid) TO profitpilot_app",
   "ALTER TABLE public.mapping_decisions DISABLE TRIGGER automated_mapping_guard",
   "ALTER FUNCTION private.verify_startup_signing_key(text,bigint,text,text) SET search_path=public",
   "CREATE VIEW public.unreviewed_catalog_view AS SELECT * FROM public.invoices",
   "ALTER TABLE public.invoices ADD COLUMN unreviewed text",
   "GRANT EXECUTE ON FUNCTION private.release_tenant_emergency(uuid,uuid,text) TO profitpilot_incident_operator",
   "ALTER TABLE private.tenant_emergency_incidents DISABLE TRIGGER incident_history_guard",
   "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO profitpilot_app"
  ]){
   await c.query("BEGIN");
   try{
    await c.query(ddl);
    assert.equal(await verify(c),false,ddl);
   }finally{await c.query("ROLLBACK");}
   assert.equal(await verify(c),true,"rolled-back drift does not change the baseline");
  }
  await c.query("GRANT UPDATE(decision) ON public.mapping_decisions TO profitpilot_app");
  try{assert.equal(await verify(runtime),false,"runtime detects committed drift");}
  finally{await c.query("REVOKE UPDATE(decision) ON public.mapping_decisions FROM profitpilot_app");}
  assert.equal(await verify(runtime),true);
 }finally{c.release();await Promise.all([admin.end(),runtime.end()]);}
});

import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import pg from "pg";
const policy=readFileSync(new URL("./rls-policy-inventory.catalog.sql",import.meta.url),"utf8");
test("exact policy inventory rejects weakened tenant, actor and privacy boundaries",{skip:!process.env.TEST_ADMIN_DATABASE_URL,timeout:45000},async()=>{
 const db=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL,max:1});
 const c=await db.connect();
 try{
  await c.query(policy);
  for(const [change,expected] of [
   ["CREATE POLICY unauthorized_read ON public.invoices FOR SELECT USING (true)",/Unexpected policy inventory/],
   ["ALTER POLICY tenant_isolation ON public.invoices USING (tenant_id=private.current_tenant_id() OR true)",/Tenant policy definition differs/],
   ["ALTER POLICY tenant_isolation ON public.invoices WITH CHECK (true)",/Tenant policy definition differs/],
   ["ALTER POLICY tenant_isolation ON public.invoices TO profitpilot_app",/Tenant policy definition differs/],
   ["ALTER POLICY users_signed_subject_only ON public.users USING (private.current_tenant_id() IS NOT NULL)",/Tenant policy definition differs/],
   ["ALTER POLICY match_reviews_actor_update ON public.match_reviews USING (true)",/Restrictive policy definition differs/],
   ["DROP POLICY match_reviews_actor_update ON public.match_reviews; CREATE POLICY match_reviews_actor_update ON public.match_reviews AS PERMISSIVE FOR UPDATE TO profitpilot_app USING (private.current_actor_role() IN ('owner','admin','reviewer')) WITH CHECK (private.current_actor_role() IN ('owner','admin','reviewer'))",/Restrictive policy definition differs/],
   ["ALTER POLICY raw_import_rows_invoice_read ON public.raw_import_rows USING (true)",/Restrictive policy definition differs/],
   ["CREATE VIEW public.unreviewed_financial_view AS SELECT * FROM public.invoices",/Unreviewed public relation/]
  ]){
   await c.query("BEGIN");
   try{await c.query(change);await assert.rejects(()=>c.query(policy),expected);}
   finally{await c.query("ROLLBACK");}
  }
  await c.query(policy);
 }finally{c.release();await db.end();}
});

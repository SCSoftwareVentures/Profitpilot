import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import pg from "pg";
const catalog=readFileSync(new URL("./public-runtime-grants.catalog.sql",import.meta.url),"utf8");
test("public grant inventory rejects direct and inherited column privilege drift",{skip:!process.env.TEST_ADMIN_DATABASE_URL,timeout:45000},async()=>{
 const db=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL,max:1});
 const c=await db.connect();
 try{
  await c.query(catalog);
  for(const [change,expected] of [
   ["GRANT UPDATE(email) ON public.users TO profitpilot_app",/Unexpected public column privilege/],
   ["GRANT UPDATE(evidence) ON public.match_reviews TO profitpilot_app",/Unexpected public column privilege/],
   ["GRANT UPDATE ON public.import_batches TO profitpilot_app",/Unexpected public table privilege/],
   ["GRANT UPDATE(decision) ON public.mapping_decisions TO profitpilot_app",/Unexpected public column privilege/],
   ["GRANT INSERT(reviewer_id) ON public.mapping_decisions TO profitpilot_app",/Unexpected public column privilege/],
   ["GRANT DELETE ON public.mapping_decisions TO profitpilot_app",/Unexpected public table privilege/],
   ["GRANT SELECT(inputs) ON public.calculation_runs TO profitpilot_app",/Unexpected public column privilege/],
   ["GRANT SELECT ON public.payroll_source_rows TO PUBLIC",/Unexpected public table privilege/],
   ["GRANT SELECT ON public.contracts TO profitpilot_app WITH GRANT OPTION",/Unapproved public table grant option/],
   ["REVOKE UPDATE(status) ON public.import_batches FROM profitpilot_app",/Unexpected public column privilege/],
   ["ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO profitpilot_app",/Unapproved default public relation grant/],
   ["CREATE SEQUENCE public.unauthorized_seq; GRANT USAGE ON SEQUENCE public.unauthorized_seq TO profitpilot_app",/Unexpected public sequence privilege/]
  ]){
   await c.query("BEGIN");
   try{await c.query(change);await assert.rejects(()=>c.query(catalog),expected);}
   finally{await c.query("ROLLBACK");}
  }
  await c.query(catalog);
 }finally{c.release();await db.end();}
});

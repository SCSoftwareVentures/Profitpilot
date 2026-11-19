import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import pg from "pg";
const catalog=readFileSync(new URL("./private-privilege.catalog.sql",import.meta.url),"utf8");
test("privilege gate detects deliberate grants, role escalation and missing approved capabilities",{skip:!process.env.TEST_ADMIN_DATABASE_URL,timeout:30000},async()=>{
 const db=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL,max:1});
 const client=await db.connect();
 try{
  await client.query(catalog);
  for(const [change,expected] of [
   ["GRANT EXECUTE ON FUNCTION private.replay_identity_revocation(uuid,text,bigint,text,boolean,text) TO profitpilot_app",/Unexpected function permission/],
   ["GRANT SELECT(secret) ON private.tenant_context_keys TO profitpilot_app",/Unexpected direct data privilege/],
   ["GRANT SELECT ON public.users TO profitpilot_scanner",/Unexpected direct data privilege/],
   ["GRANT CREATE ON SCHEMA public TO profitpilot_audit_reader",/Unsafe privileges/],
   ["GRANT profitpilot_scanner TO profitpilot_app",/Unsafe privileges/],
   ["ALTER ROLE profitpilot_scanner BYPASSRLS",/Unsafe privileges/],
   ["REVOKE EXECUTE ON FUNCTION private.current_tenant_id() FROM profitpilot_app",/Missing reviewed function permission/],
   ["GRANT EXECUTE ON FUNCTION private.verify_audit_chain(uuid) TO PUBLIC",/Unexpected function permission|PUBLIC can execute/]
  ]){
   await client.query("BEGIN");
   try{await client.query(change);await assert.rejects(()=>client.query(catalog),expected);}
   finally{await client.query("ROLLBACK");}
   await client.query(catalog);
  }
 }finally{client.release();await db.end();}
});

import {createHmac,randomBytes} from "node:crypto";

// Check the real session, not just the configured username. These are
// minimum readiness invariants, not a replacement for the full CI catalog audit.
export async function verifyDatabaseReadiness(db,env=process.env){
 const role=await db.query("SELECT current_user AS runtime_role,session_user AS login_role, NOT (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication) AS restricted, EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=pg_roles.oid) AS inherited FROM pg_roles WHERE rolname=current_user");
 const row=role.rows[0];
 if(role.rowCount!==1||!row.restricted)throw new Error("Unsafe runtime database role");
 if(env.NODE_ENV!=="production")return true;
 if(row.runtime_role!=="profitpilot_app"||row.login_role!=="profitpilot_app"||row.inherited)throw new Error("Unsafe runtime database role");
 const security=await db.query(`SELECT
  COALESCE((SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()),false) AS tls,
  NOT has_schema_privilege(current_user,'public','CREATE') AND NOT has_schema_privilege(current_user,'private','CREATE') AS schema_restricted,
  NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('public','private') AND c.relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user)) AS ownership_restricted,
  NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p') AND (c.relname IN ('tenants','users') OR EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attname='tenant_id' AND a.attnum>0 AND NOT a.attisdropped)) AND NOT(c.relrowsecurity AND c.relforcerowsecurity)) AS tenant_rls,
  NOT has_column_privilege(current_user,'public.calculation_runs','inputs','SELECT') AND NOT has_column_privilege(current_user,'public.calculation_runs','outputs','SELECT') AND NOT has_any_column_privilege(current_user,'public.payroll_source_rows','SELECT') AND NOT has_any_column_privilege(current_user,'public.allocation_lines','SELECT') AS financial_privacy,
  NOT has_any_column_privilege(current_user,'private.tenant_context_keys','SELECT') AND NOT has_any_column_privilege(current_user,'private.financial_actor_budgets','UPDATE') AND NOT has_any_column_privilege(current_user,'private.financial_tenant_budgets','UPDATE') AS private_state,
  to_regprocedure('private.admit_actor_request(uuid)') IS NOT NULL AND has_function_privilege(current_user,'private.admit_actor_request(uuid)','EXECUTE') AND NOT has_table_privilege(current_user,'private.actor_request_security','SELECT,INSERT,UPDATE,DELETE,TRUNCATE') AND NOT has_any_column_privilege(current_user,'private.actor_request_security','SELECT,INSERT,UPDATE,REFERENCES') AS actor_containment,
  NOT has_table_privilege(current_user,'public.audit_events','INSERT,UPDATE,DELETE,TRUNCATE') AS audit_restricted`);
 if(!security.rows[0]||Object.values(security.rows[0]).some(value=>value!==true))throw new Error("Database security readiness checks failed");
 const key=env.TENANT_CONTEXT_HMAC_KEY_ID||"primary",secret=env.TENANT_CONTEXT_HMAC_SECRET||"";
 if(!/^[a-f0-9]{64,}$/i.test(secret)||secret.length%2!==0)throw new Error("Signing key is missing");
 const time=String(Math.floor(Date.now()/1000)),nonce=randomBytes(16).toString("hex");
 const proof=createHmac("sha256",Buffer.from(secret,"hex")).update(["profitpilot-startup-v1",key,time,nonce].join("\n")).digest("hex");
 const result=await db.query("SELECT private.verify_startup_signing_key($1,$2,$3,$4) AS verified",[key,time,nonce,proof]);
 if(result.rows[0]?.verified!==true)throw new Error("Database signing key readiness check failed");
 return true;
}

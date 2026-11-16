-- ProfitPilot migration 002: tenant row-level security and same-tenant relationships.
-- Apply with the database owner/migration role, never the runtime application role.
BEGIN;
DO $$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='profitpilot_context_owner') THEN
  EXECUTE 'CREATE ROLE profitpilot_context_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION BYPASSRLS';
 END IF;
END $$;
CREATE SCHEMA IF NOT EXISTS private AUTHORIZATION profitpilot_context_owner;
ALTER SCHEMA private OWNER TO profitpilot_context_owner;
REVOKE ALL ON SCHEMA private FROM PUBLIC;
CREATE TABLE IF NOT EXISTS private.tenant_context_keys (
 key_id text PRIMARY KEY,
 secret bytea NOT NULL CHECK(octet_length(secret)>=32),
 active boolean NOT NULL DEFAULT true
);
ALTER TABLE private.tenant_context_keys OWNER TO profitpilot_context_owner;
REVOKE ALL ON private.tenant_context_keys FROM PUBLIC,profitpilot_app;
GRANT USAGE ON SCHEMA public TO profitpilot_context_owner;
GRANT SELECT ON tenants,users,tenant_memberships TO profitpilot_context_owner;

CREATE OR REPLACE FUNCTION private.current_tenant_id()
RETURNS uuid LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,private
AS $function$
DECLARE
 v_tenant uuid; v_subject text; v_expires bigint; v_nonce text;
 v_key_id text; v_signature text; v_secret bytea; v_payload text; v_expected text;
BEGIN
 v_tenant:=private.current_tenant_id();
 v_subject:=nullif(current_setting('app.tenant_subject',true),'');
 v_expires:=nullif(current_setting('app.tenant_expires',true),'')::bigint;
 v_nonce:=nullif(current_setting('app.tenant_nonce',true),'');
 v_key_id:=nullif(current_setting('app.tenant_key_id',true),'');
 v_signature:=lower(nullif(current_setting('app.tenant_signature',true),''));
 IF v_tenant IS NULL OR v_subject IS NULL OR v_expires IS NULL OR v_nonce IS NULL OR v_key_id IS NULL OR v_signature IS NULL THEN RETURN NULL; END IF;
 IF v_expires < floor(extract(epoch FROM clock_timestamp()))::bigint OR v_expires > floor(extract(epoch FROM clock_timestamp()))::bigint+60 THEN RETURN NULL; END IF;
 IF v_nonce !~ '^[a-f0-9]{32}$' OR v_signature !~ '^[a-f0-9]{64}$' THEN RETURN NULL; END IF;
 SELECT secret INTO v_secret FROM private.tenant_context_keys WHERE key_id=v_key_id AND active=true;
 IF v_secret IS NULL THEN RETURN NULL; END IF;
 v_payload:=v_tenant::text||E'\n'||v_subject||E'\n'||v_expires::text||E'\n'||v_nonce||E'\n'||v_key_id;
 v_expected:=encode(public.hmac(convert_to(v_payload,'UTF8'),v_secret,'sha256'),'hex');
 IF v_expected<>v_signature THEN RETURN NULL; END IF;
 IF NOT EXISTS(SELECT 1 FROM public.tenant_memberships tm JOIN public.users u ON u.id=tm.user_id JOIN public.tenants t ON t.id=tm.tenant_id WHERE tm.tenant_id=v_tenant AND u.auth_subject=v_subject AND tm.status='active' AND u.status='active' AND t.status='active') THEN RETURN NULL; END IF;
 RETURN v_tenant;
EXCEPTION WHEN OTHERS THEN RETURN NULL;
END;
$function$;
ALTER FUNCTION private.current_tenant_id() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.current_tenant_id() FROM PUBLIC;
GRANT USAGE ON SCHEMA private TO profitpilot_app;
GRANT EXECUTE ON FUNCTION private.current_tenant_id() TO profitpilot_app;


ALTER TABLE invoices ADD CONSTRAINT invoices_tenant_id_id_unique UNIQUE (tenant_id,id);
ALTER TABLE raw_import_rows ADD CONSTRAINT raw_import_rows_tenant_id_id_unique UNIQUE (tenant_id,id);
ALTER TABLE invoice_lines ADD CONSTRAINT invoice_lines_tenant_id_id_unique UNIQUE (tenant_id,id);
ALTER TABLE mapping_decisions ADD CONSTRAINT mapping_decisions_raw_row_same_tenant_fk
 FOREIGN KEY (tenant_id,raw_row_id) REFERENCES raw_import_rows(tenant_id,id);
ALTER TABLE invoice_lines ADD CONSTRAINT invoice_lines_invoice_same_tenant_fk
 FOREIGN KEY (tenant_id,invoice_id) REFERENCES invoices(tenant_id,id);
ALTER TABLE invoice_lines ADD CONSTRAINT invoice_lines_raw_row_same_tenant_fk
 FOREIGN KEY (tenant_id,source_row_id) REFERENCES raw_import_rows(tenant_id,id);
ALTER TABLE match_reviews ADD CONSTRAINT match_reviews_invoice_line_same_tenant_fk
 FOREIGN KEY (tenant_id,invoice_line_id) REFERENCES invoice_lines(tenant_id,id);
ALTER TABLE match_reviews ADD CONSTRAINT match_reviews_contract_same_tenant_fk
 FOREIGN KEY (tenant_id,contract_id) REFERENCES contracts(tenant_id,id);
ALTER TABLE match_reviews ADD CONSTRAINT match_reviews_site_same_tenant_fk
 FOREIGN KEY (tenant_id,site_id) REFERENCES sites(tenant_id,id);
ALTER TABLE variations ADD CONSTRAINT variations_contract_same_tenant_fk
 FOREIGN KEY (tenant_id,contract_id) REFERENCES contracts(tenant_id,id);
ALTER TABLE variations ADD CONSTRAINT variations_site_same_tenant_fk
 FOREIGN KEY (tenant_id,site_id) REFERENCES sites(tenant_id,id);
ALTER TABLE calculation_runs ADD CONSTRAINT calculations_contract_same_tenant_fk
 FOREIGN KEY (tenant_id,contract_id) REFERENCES contracts(tenant_id,id);
ALTER TABLE calculation_runs ADD CONSTRAINT calculations_site_same_tenant_fk
 FOREIGN KEY (tenant_id,site_id) REFERENCES sites(tenant_id,id);

DO $$
DECLARE t text;
BEGIN
 FOREACH t IN ARRAY ARRAY[
  'tenant_memberships','businesses','sites','contracts','contract_versions',
  'import_batches','raw_import_rows','mapping_decisions','payroll_pools',
  'allocation_runs','invoices','invoice_lines','match_reviews','variations',
  'calculation_runs','audit_events'
 ] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = private.current_tenant_id()) WITH CHECK (tenant_id = private.current_tenant_id())',t);
 END LOOP;
END $$;
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenants
 USING (id = private.current_tenant_id())
 WITH CHECK (id = private.current_tenant_id());

GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO profitpilot_app;
GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO profitpilot_app;
COMMIT;

-- Runtime role must not own tables, be superuser, or have BYPASSRLS.
-- app.tenant_id is set transaction-locally only after the server checks membership.

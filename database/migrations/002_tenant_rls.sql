-- ProfitPilot migration 002: tenant row-level security and same-tenant relationships.
-- Apply with the database owner/migration role, never the runtime application role.
BEGIN;

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
  EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = nullif(current_setting(''app.tenant_id'',true), '''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''app.tenant_id'',true), '''')::uuid)',t);
 END LOOP;
END $$;
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenants
 USING (id = nullif(current_setting('app.tenant_id',true),'')::uuid)
 WITH CHECK (id = nullif(current_setting('app.tenant_id',true),'')::uuid);

GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO profitpilot_app;
GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO profitpilot_app;
COMMIT;

-- Runtime role must not own tables, be superuser, or have BYPASSRLS.
-- app.tenant_id is set transaction-locally only after the server checks membership.

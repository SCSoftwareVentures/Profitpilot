-- ProfitPilot migration 002: tenant row-level security and relationship hardening.
-- Apply only after reviewing the schema against the target PostgreSQL version.
-- The API must set app.tenant_id inside every transaction after verifying membership.
BEGIN;

-- Composite uniqueness enables tenant-safe foreign keys.
ALTER TABLE invoices ADD CONSTRAINT invoices_tenant_id_id_unique UNIQUE (tenant_id,id);
ALTER TABLE raw_import_rows ADD CONSTRAINT raw_import_rows_tenant_id_id_unique UNIQUE (tenant_id,id);

-- Prevent cross-tenant references even if an application bug supplies another tenant's UUID.
ALTER TABLE invoice_lines
  ADD CONSTRAINT invoice_lines_invoice_same_tenant_fk
  FOREIGN KEY (tenant_id,invoice_id) REFERENCES invoices(tenant_id,id);
ALTER TABLE invoice_lines
  ADD CONSTRAINT invoice_lines_raw_row_same_tenant_fk
  FOREIGN KEY (tenant_id,source_row_id) REFERENCES raw_import_rows(tenant_id,id);
ALTER TABLE match_reviews
  ADD CONSTRAINT match_reviews_contract_same_tenant_fk
  FOREIGN KEY (tenant_id,contract_id) REFERENCES contracts(tenant_id,id);
ALTER TABLE match_reviews
  ADD CONSTRAINT match_reviews_site_same_tenant_fk
  FOREIGN KEY (tenant_id,site_id) REFERENCES sites(tenant_id,id);
ALTER TABLE variations
  ADD CONSTRAINT variations_contract_same_tenant_fk
  FOREIGN KEY (tenant_id,contract_id) REFERENCES contracts(tenant_id,id);
ALTER TABLE variations
  ADD CONSTRAINT variations_site_same_tenant_fk
  FOREIGN KEY (tenant_id,site_id) REFERENCES sites(tenant_id,id);
ALTER TABLE calculation_runs
  ADD CONSTRAINT calculations_contract_same_tenant_fk
  FOREIGN KEY (tenant_id,contract_id) REFERENCES contracts(tenant_id,id);
ALTER TABLE calculation_runs
  ADD CONSTRAINT calculations_site_same_tenant_fk
  FOREIGN KEY (tenant_id,site_id) REFERENCES sites(tenant_id,id);

-- Enable and FORCE RLS for every tenant-owned relation.
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

COMMIT;

-- NOTE: app.tenant_id must never be set from an untrusted request without a
-- verified membership lookup. The API sets it transaction-locally only.
-- Run migration with a privileged migration role; runtime role must not own
-- tables, bypass RLS, or hold BYPASSRLS.

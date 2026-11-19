BEGIN;
CREATE TABLE payroll_source_records (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id uuid NOT NULL,
 raw_row_id uuid NOT NULL,
 payroll_pool_id uuid NOT NULL,
 source_ref text NOT NULL CHECK(length(source_ref) BETWEEN 1 AND 200),
 amount numeric(14,2) NOT NULL CHECK(amount>0),
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,source_ref),
 UNIQUE(tenant_id,raw_row_id),
 FOREIGN KEY(tenant_id,raw_row_id) REFERENCES raw_import_rows(tenant_id,id),
 FOREIGN KEY(tenant_id,payroll_pool_id) REFERENCES payroll_pools(tenant_id,id)
);
ALTER TABLE payroll_source_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE payroll_source_records FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON payroll_source_records
 USING(tenant_id=private.current_tenant_id()) WITH CHECK(tenant_id=private.current_tenant_id());
GRANT SELECT,INSERT ON payroll_source_records TO profitpilot_app;
CREATE UNIQUE INDEX payroll_reconciled_batch_once ON payroll_pools(tenant_id,batch_id)
 WHERE source_ref LIKE 'reconciled:%';
GRANT INSERT ON payroll_pools,allocation_runs,allocation_lines TO profitpilot_app;
COMMIT;

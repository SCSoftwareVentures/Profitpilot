-- ProfitPilot migration 003: site-level allocation lines and calculation provenance.
BEGIN;
ALTER TABLE allocation_runs ADD CONSTRAINT allocation_runs_tenant_id_id_unique UNIQUE(tenant_id,id);
CREATE TABLE allocation_lines (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id uuid NOT NULL,
 allocation_run_id uuid NOT NULL,
 site_id uuid,
 bucket_type text NOT NULL CHECK(bucket_type IN ('direct','approved_allocated','non_site','excluded','unallocated')),
 amount numeric(14,2) NOT NULL CHECK(amount>=0),
 source_ref text,
 created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(tenant_id,allocation_run_id) REFERENCES allocation_runs(tenant_id,id),
 FOREIGN KEY(tenant_id,site_id) REFERENCES sites(tenant_id,id)
);
CREATE INDEX allocation_lines_site_run_idx ON allocation_lines(tenant_id,site_id,allocation_run_id);
ALTER TABLE allocation_lines ENABLE ROW LEVEL SECURITY;
ALTER TABLE allocation_lines FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON allocation_lines
 USING(tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT,UPDATE,DELETE ON allocation_lines TO profitpilot_app;
COMMIT;

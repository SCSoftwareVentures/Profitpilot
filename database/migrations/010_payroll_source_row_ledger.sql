-- ProfitPilot migration 010: immutable payroll source-row provenance.
BEGIN;
CREATE TABLE payroll_source_rows (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id uuid NOT NULL,
 payroll_pool_id uuid NOT NULL,
 raw_import_row_id uuid NOT NULL,
 source_row_key text NOT NULL CHECK(length(source_row_key) BETWEEN 1 AND 128 AND substring(source_row_key,1,1) ~ '^[A-Za-z0-9]' AND translate(source_row_key,'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-','')=''),
 row_sha256 text NOT NULL CHECK(row_sha256 ~ '^[a-f0-9]{64}$'),
 amount numeric(14,2) NOT NULL CHECK(amount>=0),
 currency char(3) NOT NULL CHECK(currency ~ '^[A-Z]{3}$'),
 created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(tenant_id,payroll_pool_id) REFERENCES payroll_pools(tenant_id,id),
 FOREIGN KEY(tenant_id,raw_import_row_id) REFERENCES raw_import_rows(tenant_id,id),
 UNIQUE(tenant_id,id),
 UNIQUE(tenant_id,payroll_pool_id,source_row_key)
);
ALTER TABLE allocation_lines ADD COLUMN payroll_source_row_id uuid,
 ADD CONSTRAINT allocation_lines_source_row_same_tenant_fk
 FOREIGN KEY(tenant_id,payroll_source_row_id) REFERENCES payroll_source_rows(tenant_id,id);
CREATE INDEX payroll_source_rows_pool_idx ON payroll_source_rows(tenant_id,payroll_pool_id);
CREATE INDEX allocation_lines_source_row_idx ON allocation_lines(tenant_id,payroll_source_row_id);
ALTER TABLE payroll_source_rows ENABLE ROW LEVEL SECURITY;
ALTER TABLE payroll_source_rows FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON payroll_source_rows
 USING(tenant_id=private.current_tenant_id()) WITH CHECK(tenant_id=private.current_tenant_id());
CREATE FUNCTION private.reject_payroll_source_row_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,private AS $$
BEGIN RAISE EXCEPTION 'Payroll source rows are immutable; create a corrected source version' USING ERRCODE='55000'; END;
$$;
CREATE TRIGGER payroll_source_rows_immutable BEFORE UPDATE OR DELETE ON payroll_source_rows
 FOR EACH ROW EXECUTE FUNCTION private.reject_payroll_source_row_mutation();
CREATE FUNCTION private.reject_allocation_line_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,private AS $$
BEGIN RAISE EXCEPTION 'Allocation lines are append-only; create a superseding allocation run' USING ERRCODE='55000'; END;
$$;
CREATE TRIGGER allocation_lines_immutable BEFORE UPDATE OR DELETE ON allocation_lines
 FOR EACH ROW EXECUTE FUNCTION private.reject_allocation_line_mutation();
CREATE FUNCTION private.validate_payroll_allocation_line()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,private AS $$
DECLARE src payroll_source_rows%ROWTYPE; run allocation_runs%ROWTYPE; used numeric(14,2);
BEGIN
 IF NEW.payroll_source_row_id IS NULL THEN
  RAISE EXCEPTION 'Allocation lines must reference a payroll source row' USING ERRCODE='23514';
 END IF;
 SELECT * INTO src FROM payroll_source_rows
  WHERE tenant_id=NEW.tenant_id AND id=NEW.payroll_source_row_id FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Payroll source row not found in tenant' USING ERRCODE='23503'; END IF;
 SELECT * INTO run FROM allocation_runs
  WHERE tenant_id=NEW.tenant_id AND id=NEW.allocation_run_id FOR UPDATE;
 IF NOT FOUND OR run.payroll_pool_id<>src.payroll_pool_id THEN
  RAISE EXCEPTION 'Allocation run and source row must belong to the same payroll pool' USING ERRCODE='23514';
 END IF;
 IF NEW.bucket_type IN ('direct','approved_allocated') AND NEW.site_id IS NULL THEN
  RAISE EXCEPTION 'Site allocation buckets require a site' USING ERRCODE='23514';
 END IF;
 IF NEW.bucket_type IN ('non_site','excluded','unallocated') AND NEW.site_id IS NOT NULL THEN
  RAISE EXCEPTION 'Non-site, excluded and unallocated buckets cannot carry a site' USING ERRCODE='23514';
 END IF;
 SELECT COALESCE(SUM(amount),0) INTO used FROM allocation_lines
  WHERE tenant_id=NEW.tenant_id AND allocation_run_id=NEW.allocation_run_id
    AND payroll_source_row_id=NEW.payroll_source_row_id;
 IF used+NEW.amount>src.amount THEN
  RAISE EXCEPTION 'Allocation exceeds source payroll row amount' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER allocation_lines_validate_source BEFORE INSERT ON allocation_lines
 FOR EACH ROW EXECUTE FUNCTION private.validate_payroll_allocation_line();
REVOKE INSERT,UPDATE,DELETE ON payroll_source_rows,allocation_lines FROM profitpilot_app;
GRANT SELECT ON payroll_source_rows,allocation_lines TO profitpilot_app;
COMMIT;

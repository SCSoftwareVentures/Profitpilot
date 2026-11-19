-- Database-enforced split allocation integrity for new reviewed payroll runs.
BEGIN;
ALTER TABLE payroll_source_records ADD CONSTRAINT payroll_source_tenant_id_unique UNIQUE(tenant_id,id);
ALTER TABLE allocation_lines ADD COLUMN source_record_id uuid;
ALTER TABLE allocation_lines ADD CONSTRAINT allocation_source_same_tenant_fk
 FOREIGN KEY(tenant_id,source_record_id) REFERENCES payroll_source_records(tenant_id,id);
CREATE INDEX allocation_source_record_idx ON allocation_lines(tenant_id,source_record_id);
-- Legacy manual and v0.1 allocations remain readable; new runtime writes require v0.2.
CREATE FUNCTION private.payroll_reviewer_id() RETURNS uuid
 LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,public,private
 AS $$
 SELECT u.id FROM public.users u JOIN public.tenant_memberships m ON m.user_id=u.id
 WHERE m.tenant_id=private.current_tenant_id() AND u.auth_subject=nullif(current_setting('app.tenant_subject',true),'')
 AND m.status='active' AND m.role IN ('owner','admin','reviewer') AND u.status='active'
 $$;
REVOKE ALL ON FUNCTION private.payroll_reviewer_id() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.payroll_reviewer_id() TO profitpilot_app;
CREATE POLICY payroll_pool_runtime_insert ON payroll_pools AS RESTRICTIVE FOR INSERT TO profitpilot_app
 WITH CHECK(private.payroll_reviewer_id() IS NOT NULL AND source_ref LIKE 'reconciled:%'
 AND EXISTS(SELECT 1 FROM import_batches b WHERE b.tenant_id=payroll_pools.tenant_id AND b.id=payroll_pools.batch_id
 AND b.source_type='payroll' AND b.status='review' AND b.source_period_start=payroll_pools.period_start AND b.source_period_end=payroll_pools.period_end));
CREATE POLICY payroll_run_runtime_insert ON allocation_runs AS RESTRICTIVE FOR INSERT TO profitpilot_app
 WITH CHECK(private.payroll_reviewer_id()=reviewer_id AND method_version='payroll-source-row-0.2.0' AND status='draft'
 AND EXISTS(SELECT 1 FROM payroll_pools p WHERE p.tenant_id=allocation_runs.tenant_id AND p.id=allocation_runs.payroll_pool_id AND p.source_ref LIKE 'reconciled:%'));
CREATE UNIQUE INDEX payroll_v2_run_once ON allocation_runs(tenant_id,payroll_pool_id) WHERE method_version='payroll-source-row-0.2.0';
GRANT UPDATE(status) ON allocation_runs TO profitpilot_app;
CREATE POLICY payroll_run_runtime_update ON allocation_runs AS RESTRICTIVE FOR UPDATE TO profitpilot_app
 USING(private.payroll_reviewer_id()=reviewer_id AND method_version='payroll-source-row-0.2.0' AND status='draft')
 WITH CHECK(private.payroll_reviewer_id()=reviewer_id AND method_version='payroll-source-row-0.2.0' AND status='confirmed');
CREATE POLICY payroll_record_runtime_insert ON payroll_source_records AS RESTRICTIVE FOR INSERT TO profitpilot_app
 WITH CHECK(private.payroll_reviewer_id() IS NOT NULL AND EXISTS(SELECT 1 FROM allocation_runs a WHERE a.tenant_id=payroll_source_records.tenant_id AND a.payroll_pool_id=payroll_source_records.payroll_pool_id AND a.method_version='payroll-source-row-0.2.0' AND a.status='draft' AND a.reviewer_id=private.payroll_reviewer_id()));
CREATE POLICY payroll_line_runtime_insert ON allocation_lines AS RESTRICTIVE FOR INSERT TO profitpilot_app
 WITH CHECK(source_record_id IS NOT NULL AND private.payroll_reviewer_id() IS NOT NULL AND EXISTS(SELECT 1 FROM allocation_runs a WHERE a.tenant_id=allocation_lines.tenant_id AND a.id=allocation_lines.allocation_run_id AND a.method_version='payroll-source-row-0.2.0' AND a.status='draft' AND a.reviewer_id=private.payroll_reviewer_id()));

CREATE FUNCTION private.guard_payroll_source() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,private AS $$
DECLARE run_status text; expected_batch uuid; expected_currency text; expected_start date; expected_end date; raw_data jsonb;
BEGIN
 SELECT a.status,p.batch_id,p.currency,p.period_start,p.period_end INTO run_status,expected_batch,expected_currency,expected_start,expected_end
 FROM allocation_runs a JOIN payroll_pools p ON p.tenant_id=a.tenant_id AND p.id=a.payroll_pool_id
 WHERE a.tenant_id=NEW.tenant_id AND a.payroll_pool_id=NEW.payroll_pool_id AND a.method_version='payroll-source-row-0.2.0' FOR UPDATE OF a;
 IF NOT FOUND THEN
   IF current_user='profitpilot_app' THEN RAISE EXCEPTION 'A v2 draft allocation is required' USING ERRCODE='23514'; END IF;
   RETURN NEW;
 END IF;
 IF run_status<>'draft' THEN RAISE EXCEPTION 'Confirmed allocation sources are sealed' USING ERRCODE='23514'; END IF;
 SELECT r.payload INTO raw_data FROM raw_import_rows r JOIN mapping_decisions m ON m.tenant_id=r.tenant_id AND m.raw_row_id=r.id
 WHERE r.tenant_id=NEW.tenant_id AND r.id=NEW.raw_row_id AND r.batch_id=expected_batch AND m.method_version='payroll-validator-0.1.0' AND m.decision='candidate';
 IF NOT FOUND OR jsonb_typeof(raw_data->'amount') IS DISTINCT FROM 'string' OR (raw_data->>'amount') !~ '^[0-9]{1,12}(\.[0-9]{1,2})?$'
 OR raw_data->>'source_ref' IS DISTINCT FROM NEW.source_ref OR raw_data->>'currency' IS DISTINCT FROM expected_currency
 OR raw_data->>'period_start' IS DISTINCT FROM expected_start::text OR raw_data->>'period_end' IS DISTINCT FROM expected_end::text
 THEN RAISE EXCEPTION 'Source lineage does not match validated payroll row' USING ERRCODE='23514'; END IF;
 IF (raw_data->>'amount')::numeric IS DISTINCT FROM NEW.amount THEN RAISE EXCEPTION 'Source amount mismatch' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER payroll_source_guard BEFORE INSERT ON payroll_source_records FOR EACH ROW EXECUTE FUNCTION private.guard_payroll_source();

CREATE FUNCTION private.guard_payroll_line() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,private AS $$
DECLARE ar allocation_runs%ROWTYPE; sr payroll_source_records%ROWTYPE;
BEGIN
 SELECT * INTO ar FROM allocation_runs WHERE tenant_id=NEW.tenant_id AND id=NEW.allocation_run_id;
 IF NOT FOUND OR ar.method_version<>'payroll-source-row-0.2.0' THEN
   IF current_user='profitpilot_app' OR NEW.source_record_id IS NOT NULL THEN RAISE EXCEPTION 'A v2 draft allocation is required' USING ERRCODE='23514'; END IF;
   RETURN NEW;
 END IF;
 SELECT * INTO ar FROM allocation_runs WHERE tenant_id=NEW.tenant_id AND id=NEW.allocation_run_id FOR UPDATE;
 IF NOT FOUND OR ar.status<>'draft' THEN RAISE EXCEPTION 'Confirmed allocation lines are sealed' USING ERRCODE='23514'; END IF;
 SELECT * INTO sr FROM payroll_source_records WHERE tenant_id=NEW.tenant_id AND id=NEW.source_record_id;
 IF NOT FOUND OR sr.payroll_pool_id<>ar.payroll_pool_id OR NEW.source_ref IS DISTINCT FROM sr.source_ref
 OR NEW.amount<=0 OR ((NEW.bucket_type IN ('direct','approved_allocated')) IS DISTINCT FROM (NEW.site_id IS NOT NULL))
 THEN RAISE EXCEPTION 'Invalid allocation source, amount or bucket' USING ERRCODE='23514'; END IF;
 IF NEW.site_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM sites WHERE tenant_id=NEW.tenant_id AND id=NEW.site_id AND status='active')
 THEN RAISE EXCEPTION 'Allocation site unavailable' USING ERRCODE='23514'; END IF;
 IF COALESCE((SELECT sum(amount) FROM allocation_lines WHERE tenant_id=NEW.tenant_id AND allocation_run_id=ar.id AND source_record_id=sr.id),0)+NEW.amount>sr.amount
 THEN RAISE EXCEPTION 'Allocation exceeds source amount' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER payroll_line_guard BEFORE INSERT ON allocation_lines FOR EACH ROW EXECUTE FUNCTION private.guard_payroll_line();
CREATE UNIQUE INDEX payroll_source_destination_once ON allocation_lines(tenant_id,allocation_run_id,source_record_id,bucket_type,site_id) NULLS NOT DISTINCT WHERE source_record_id IS NOT NULL;

CREATE FUNCTION private.confirm_payroll_run() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,private AS $$
DECLARE p payroll_pools%ROWTYPE; sums record; source_total numeric; source_count bigint;
BEGIN
 IF NEW.method_version<>'payroll-source-row-0.2.0' THEN RETURN NEW; END IF;
 IF TG_OP='INSERT' THEN
   IF NEW.status<>'draft' THEN RAISE EXCEPTION 'A new allocation must start as draft' USING ERRCODE='23514'; END IF;
   RETURN NEW;
 END IF;
 IF OLD.status<>'draft' OR NEW.status<>'confirmed' OR NEW.reviewer_id IS NULL THEN
   RAISE EXCEPTION 'Invalid payroll confirmation transition' USING ERRCODE='23514';
 END IF;
 SELECT * INTO p FROM payroll_pools WHERE tenant_id=NEW.tenant_id AND id=NEW.payroll_pool_id;
 SELECT count(*),COALESCE(sum(amount),0) INTO source_count,source_total FROM payroll_source_records WHERE tenant_id=NEW.tenant_id AND payroll_pool_id=p.id;
 IF source_count=0 OR source_total IS DISTINCT FROM p.total_amount OR source_count<>(SELECT count(*) FROM raw_import_rows WHERE tenant_id=NEW.tenant_id AND batch_id=p.batch_id)
 OR EXISTS(SELECT 1 FROM payroll_source_records sr WHERE sr.tenant_id=NEW.tenant_id AND sr.payroll_pool_id=p.id AND sr.amount<>COALESCE((SELECT sum(l.amount) FROM allocation_lines l WHERE l.tenant_id=sr.tenant_id AND l.allocation_run_id=NEW.id AND l.source_record_id=sr.id),0))
 THEN RAISE EXCEPTION 'Payroll source totals or allocation coverage do not reconcile' USING ERRCODE='23514'; END IF;
 SELECT COALESCE(sum(amount) FILTER(WHERE bucket_type='direct'),0) AS direct,
 COALESCE(sum(amount) FILTER(WHERE bucket_type='approved_allocated'),0) AS allocated,
 COALESCE(sum(amount) FILTER(WHERE bucket_type='non_site'),0) AS non_site,
 COALESCE(sum(amount) FILTER(WHERE bucket_type='excluded'),0) AS excluded,
 COALESCE(sum(amount) FILTER(WHERE bucket_type='unallocated'),0) AS residual
 INTO sums FROM allocation_lines WHERE tenant_id=NEW.tenant_id AND allocation_run_id=NEW.id;
 IF ROW(sums.direct,sums.allocated,sums.non_site,sums.excluded,sums.residual)
 IS DISTINCT FROM ROW(NEW.direct_amount,NEW.allocated_amount,NEW.non_site_amount,NEW.excluded_amount,NEW.residual_amount)
 THEN RAISE EXCEPTION 'Payroll allocation bucket totals do not reconcile' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER payroll_confirmation_guard BEFORE INSERT OR UPDATE ON allocation_runs FOR EACH ROW EXECUTE FUNCTION private.confirm_payroll_run();
COMMIT;

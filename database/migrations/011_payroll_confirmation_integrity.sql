-- ProfitPilot migration 011: require reconciled, reviewer-authorised payroll confirmation.
BEGIN;

CREATE FUNCTION private.validate_payroll_allocation_confirmation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,public,private
AS $$
DECLARE
  pool payroll_pools%ROWTYPE;
  source_count bigint;
  source_total numeric(14,2);
  source_currency_count bigint;
  incomplete_rows bigint;
  line_totals record;
  reviewer_role text;
BEGIN
  IF NEW.status <> 'confirmed' THEN
    RETURN NEW;
  END IF;
  IF TG_OP='UPDATE' THEN
    IF OLD.status='confirmed' THEN
      RAISE EXCEPTION 'Confirmed payroll allocation runs are immutable' USING ERRCODE='55000';
    END IF;
  END IF;

  SELECT * INTO pool
  FROM payroll_pools
  WHERE tenant_id=NEW.tenant_id AND id=NEW.payroll_pool_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Payroll pool not found for confirmation' USING ERRCODE='23503';
  END IF;

  SELECT count(*),COALESCE(sum(amount),0),count(DISTINCT currency)
    INTO source_count,source_total,source_currency_count
  FROM payroll_source_rows
  WHERE tenant_id=NEW.tenant_id AND payroll_pool_id=NEW.payroll_pool_id;

  IF source_count=0 OR source_total<>pool.total_amount THEN
    RAISE EXCEPTION 'Payroll source rows do not reconcile to the payroll pool total' USING ERRCODE='23514';
  END IF;
  IF source_currency_count<>1 OR EXISTS (
    SELECT 1 FROM payroll_source_rows
    WHERE tenant_id=NEW.tenant_id AND payroll_pool_id=NEW.payroll_pool_id
      AND currency<>pool.currency
  ) THEN
    RAISE EXCEPTION 'Payroll source-row currency does not match the payroll pool currency' USING ERRCODE='23514';
  END IF;

  SELECT count(*) INTO incomplete_rows
  FROM payroll_source_rows s
  WHERE s.tenant_id=NEW.tenant_id AND s.payroll_pool_id=NEW.payroll_pool_id
    AND COALESCE((
      SELECT sum(l.amount) FROM allocation_lines l
      WHERE l.tenant_id=NEW.tenant_id AND l.allocation_run_id=NEW.id
        AND l.payroll_source_row_id=s.id
    ),0)<>s.amount;
  IF incomplete_rows<>0 THEN
    RAISE EXCEPTION 'Every payroll source row must be fully represented in the allocation run' USING ERRCODE='23514';
  END IF;

  SELECT
    COALESCE(sum(amount) FILTER (WHERE bucket_type='direct'),0) AS direct_total,
    COALESCE(sum(amount) FILTER (WHERE bucket_type='approved_allocated'),0) AS allocated_total,
    COALESCE(sum(amount) FILTER (WHERE bucket_type='non_site'),0) AS non_site_total,
    COALESCE(sum(amount) FILTER (WHERE bucket_type='excluded'),0) AS excluded_total,
    COALESCE(sum(amount) FILTER (WHERE bucket_type='unallocated'),0) AS unallocated_total
  INTO line_totals
  FROM allocation_lines
  WHERE tenant_id=NEW.tenant_id AND allocation_run_id=NEW.id;

  IF line_totals.direct_total<>NEW.direct_amount
    OR line_totals.allocated_total<>NEW.allocated_amount
    OR line_totals.non_site_total<>NEW.non_site_amount
    OR line_totals.excluded_total<>NEW.excluded_amount
    OR line_totals.unallocated_total<>NEW.residual_amount
    OR NEW.residual_amount<>0 THEN
    RAISE EXCEPTION 'Allocation line totals do not reconcile to the run summary or residual is non-zero' USING ERRCODE='23514';
  END IF;

  IF NEW.reviewer_id IS NULL THEN
    RAISE EXCEPTION 'A tenant reviewer, admin or owner must confirm the payroll allocation' USING ERRCODE='23514';
  END IF;
  SELECT role INTO reviewer_role
  FROM tenant_memberships
  WHERE tenant_id=NEW.tenant_id AND user_id=NEW.reviewer_id AND status='active';
  IF reviewer_role IS NULL OR reviewer_role NOT IN ('reviewer','admin','owner') THEN
    RAISE EXCEPTION 'Payroll allocation confirmation requires an active reviewer, admin or owner' USING ERRCODE='23514';
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER allocation_runs_validate_confirmation
BEFORE INSERT OR UPDATE ON allocation_runs
FOR EACH ROW
EXECUTE FUNCTION private.validate_payroll_allocation_confirmation();

CREATE FUNCTION private.reject_confirmed_allocation_run_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,private AS $$
BEGIN
  IF OLD.status='confirmed' THEN
    RAISE EXCEPTION 'Confirmed payroll allocation runs are immutable' USING ERRCODE='55000';
  END IF;
  RETURN OLD;
END;
$$;
CREATE TRIGGER allocation_runs_confirmed_immutable
BEFORE UPDATE OR DELETE ON allocation_runs
FOR EACH ROW EXECUTE FUNCTION private.reject_confirmed_allocation_run_mutation();

COMMIT;

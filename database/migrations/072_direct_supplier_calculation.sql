-- Version 0.3.0 opt-in, reviewed direct supplier costs; preserve v1 receipts.
BEGIN;
DO $check$ BEGIN IF private.verify_security_catalog() IS DISTINCT FROM true THEN RAISE EXCEPTION 'Prior catalog does not verify'; END IF; END $check$;

CREATE FUNCTION private.supplier_cost_snapshot(t uuid,c uuid,s uuid,starts date,ends date,baseline uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $fn$
DECLARE result jsonb; basis text;
BEGIN
 IF private.current_tenant_id() IS DISTINCT FROM t OR coalesce(private.current_actor_role(),'') NOT IN ('owner','admin','analyst','reviewer')
 OR c IS NULL OR s IS NULL OR starts IS NULL OR ends IS NULL OR ends<starts OR NOT isfinite(starts) OR NOT isfinite(ends)
 OR NOT private.workspace_contract_site_allowed(t,c,s) THEN RAISE EXCEPTION 'Supplier summary denied' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('profitpilot-workspace:'||t::text,0));
 SELECT v.tax_basis INTO basis FROM public.contract_versions v JOIN public.contracts co ON co.tenant_id=v.tenant_id AND co.id=v.contract_id
 JOIN public.sites si ON si.tenant_id=co.tenant_id AND si.business_id=co.business_id AND si.id=s
 WHERE v.tenant_id=t AND v.contract_id=c AND v.id=baseline AND v.approved_at IS NOT NULL AND v.approved_by IS NOT NULL
 AND v.effective_from<=starts AND (v.effective_to IS NULL OR v.effective_to>=ends) AND v.currency='AUD' AND v.tax_basis<>'unknown';
 IF NOT FOUND THEN RAISE EXCEPTION 'Supplier calculation baseline unavailable' USING ERRCODE='23514'; END IF;
 WITH candidates AS (
 SELECT m.id match_id,l.id line_id,h.id invoice_id,k.batch_id,k.raw_row_id,k.baseline_id,l.amount,h.currency,h.tax_basis,
 m.service_period_start p_start,m.service_period_end p_end,r.order_id,q.scope_digest,q.evidence_digest,
 coalesce(q.classification,'pending') classification
 FROM public.match_reviews m JOIN public.invoice_lines l ON l.tenant_id=m.tenant_id AND l.id=m.invoice_line_id
 JOIN public.invoices h ON h.tenant_id=l.tenant_id AND h.id=l.invoice_id
 LEFT JOIN private.invoice_intake_lines k ON k.tenant_id=m.tenant_id AND k.line_id=l.id AND k.match_id=m.id
 LEFT JOIN private.supplier_cost_receipts r ON r.tenant_id=k.tenant_id AND r.batch_id=k.batch_id
 LEFT JOIN private.supplier_cost_orders q ON q.tenant_id=r.tenant_id AND q.batch_id=r.batch_id AND q.order_id=r.order_id
 WHERE m.tenant_id=t AND m.contract_id=c AND m.site_id=s AND m.decision='confirmed' AND h.direction='supplier'
 AND (m.service_period_start IS NULL OR m.service_period_end IS NULL OR (m.service_period_start<=ends AND m.service_period_end>=starts))
 ORDER BY m.id LIMIT 10001
 )
 SELECT jsonb_build_object('directCost',coalesce(sum(amount) FILTER(WHERE classification='direct_site'),0)::numeric(30,2)::text,
 'directCount',count(*) FILTER(WHERE classification='direct_site'),
 'excludedCount',count(*) FILTER(WHERE classification IN ('excluded','payroll_overlap')),
 'pendingCount',count(*) FILTER(WHERE classification IN ('pending','overhead_pending')),
 'invalid',count(*)>10000 OR coalesce(bool_or(classification='direct_site' AND
 (p_start IS NULL OR p_end IS NULL OR p_start<starts OR p_end>ends OR p_end<p_start OR amount<=0 OR currency<>'AUD'
 OR tax_basis IS DISTINCT FROM basis OR baseline_id IS DISTINCT FROM baseline OR order_id IS NULL)),false),
 'lines',coalesce(jsonb_agg(jsonb_build_array(match_id,line_id,invoice_id,batch_id,raw_row_id,baseline_id,amount::text,currency,tax_basis,p_start,p_end,order_id,scope_digest,evidence_digest,classification) ORDER BY match_id),'[]'::jsonb))
 INTO result FROM candidates;
 RETURN result;
END $fn$;
CREATE FUNCTION private.site_supplier_cost_summary(t uuid,c uuid,s uuid,starts date,ends date,baseline uuid) RETURNS jsonb
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT x - 'lines' FROM (SELECT private.supplier_cost_snapshot(t,c,s,starts,ends,baseline) x) a
$fn$;
REVOKE ALL ON FUNCTION private.supplier_cost_snapshot(uuid,uuid,uuid,date,date,uuid),private.site_supplier_cost_summary(uuid,uuid,uuid,date,date,uuid) FROM PUBLIC,profitpilot_app;
GRANT EXECUTE ON FUNCTION private.site_supplier_cost_summary(uuid,uuid,uuid,date,date,uuid) TO profitpilot_app;

CREATE OR REPLACE FUNCTION private.capture_calculation_sources() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $fn$
DECLARE snap jsonb; baseline uuid; baselines integer; revenue numeric; cost numeric; ic integer; ac integer; reviewed integer;
 bad boolean; digest_value text; supplier jsonb; supplier_total numeric:=0;
BEGIN
 IF NEW.formula_version NOT IN ('0.2.0','0.3.0') THEN RETURN NEW; END IF;
 IF private.current_tenant_id() IS DISTINCT FROM NEW.tenant_id OR coalesce(private.current_actor_role(),'') NOT IN ('owner','admin','analyst','reviewer')
 OR NEW.completeness<>'incomplete' THEN RAISE EXCEPTION 'Calculation receipt authority denied' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('payroll-correction:'||NEW.tenant_id::text,0));
 -- Single statement snapshot: a concurrent source change cannot produce a receipt
 -- with a different total/count or silently attach a partial period.
 WITH bas AS (
  SELECT v.id,v.version_no,v.currency,v.tax_basis FROM public.contract_versions v
  JOIN public.contracts c ON c.tenant_id=v.tenant_id AND c.id=v.contract_id
  JOIN public.sites s ON s.tenant_id=c.tenant_id AND s.business_id=c.business_id AND s.id=NEW.site_id
  WHERE v.tenant_id=NEW.tenant_id AND v.contract_id=NEW.contract_id AND v.approved_at IS NOT NULL AND v.approved_by IS NOT NULL
  AND v.effective_from<=NEW.period_start AND (v.effective_to IS NULL OR v.effective_to>=NEW.period_end)
  AND private.workspace_contract_site_allowed(c.tenant_id,c.id,s.id)
 ), inv AS (
  SELECT m.id match_id,l.id line_id,h.id invoice_id,l.amount,h.currency,h.tax_basis,m.service_period_start starts,m.service_period_end ends,
   k.batch_id,k.raw_row_id,k.baseline_id reviewed_baseline
  FROM public.match_reviews m JOIN public.invoice_lines l ON l.tenant_id=m.tenant_id AND l.id=m.invoice_line_id
  JOIN public.invoices h ON h.tenant_id=l.tenant_id AND h.id=l.invoice_id
  LEFT JOIN private.invoice_intake_lines k ON k.tenant_id=m.tenant_id AND k.match_id=m.id AND k.line_id=l.id
  WHERE m.tenant_id=NEW.tenant_id AND m.contract_id=NEW.contract_id AND m.site_id=NEW.site_id AND m.decision='confirmed'
  AND h.direction='customer' AND m.service_period_start<=NEW.period_end AND m.service_period_end>=NEW.period_start
  ORDER BY m.id LIMIT 10001
 ), pay AS (
  SELECT a.id line_id,r.id run_id,p.id pool_id,a.amount,p.currency,p.period_start starts,p.period_end ends,a.bucket_type
  FROM public.allocation_lines a JOIN public.allocation_runs r ON r.tenant_id=a.tenant_id AND r.id=a.allocation_run_id
  JOIN public.payroll_pools p ON p.tenant_id=r.tenant_id AND p.id=r.payroll_pool_id
  WHERE a.tenant_id=NEW.tenant_id AND a.site_id=NEW.site_id AND r.status='confirmed'
  AND p.period_start<=NEW.period_end AND p.period_end>=NEW.period_start
  AND NOT EXISTS(SELECT 1 FROM private.payroll_supersessions x WHERE x.tenant_id=r.tenant_id AND x.old_run_id=r.id)
  ORDER BY a.id LIMIT 10001
 ), ia AS (
  SELECT count(*)::integer n,coalesce(sum(amount),0) total,count(batch_id)::integer reviewed,
   coalesce(bool_or(starts<NEW.period_start OR ends>NEW.period_end OR tax_basis='unknown'
    OR currency IS DISTINCT FROM (SELECT currency FROM bas LIMIT 1)
    OR tax_basis IS DISTINCT FROM (SELECT tax_basis FROM bas LIMIT 1)
    OR (reviewed_baseline IS NOT NULL AND reviewed_baseline IS DISTINCT FROM (SELECT id FROM bas LIMIT 1))),false) invalid,
   jsonb_agg(jsonb_build_array(match_id,line_id,invoice_id,amount::text,currency,tax_basis,starts,ends,batch_id,raw_row_id,reviewed_baseline) ORDER BY match_id) items FROM inv
 ), pa AS (
  SELECT count(*) FILTER(WHERE bucket_type IN ('direct','approved_allocated'))::integer n,
   count(*)::integer all_n,coalesce(sum(amount) FILTER(WHERE bucket_type IN ('direct','approved_allocated')),0) total,
   coalesce(bool_or(starts<NEW.period_start OR ends>NEW.period_end OR (bucket_type IN ('direct','approved_allocated') AND currency IS DISTINCT FROM (SELECT currency FROM bas LIMIT 1))),false) invalid,
   jsonb_agg(jsonb_build_array(line_id,run_id,pool_id,amount::text,currency,starts,ends,bucket_type) ORDER BY line_id) FILTER(WHERE bucket_type IN ('direct','approved_allocated')) items FROM pay
 )
 SELECT (SELECT id FROM bas LIMIT 1),(SELECT count(*)::integer FROM bas),ia.total,pa.total,ia.n,pa.n,ia.reviewed,
 ia.invalid OR pa.invalid OR pa.all_n>10000 OR (SELECT version_no::text FROM bas LIMIT 1) IS DISTINCT FROM NEW.inputs->>'contractVersion'
 OR (SELECT currency FROM bas LIMIT 1) IS DISTINCT FROM NEW.outputs->>'currency',
 jsonb_build_object('format','profitpilot-source-trace-v1','tenantId',NEW.tenant_id,'contractId',NEW.contract_id,'siteId',NEW.site_id,
 'baselineId',(SELECT id FROM bas LIMIT 1),'periodStart',NEW.period_start,'periodEnd',NEW.period_end,'formulaVersion',NEW.formula_version,
 'invoices',ia.items,'allocations',pa.items)
 INTO baseline,baselines,revenue,cost,ic,ac,reviewed,bad,snap FROM ia CROSS JOIN pa;
 IF NEW.formula_version='0.3.0' THEN
  supplier:=private.supplier_cost_snapshot(NEW.tenant_id,NEW.contract_id,NEW.site_id,NEW.period_start,NEW.period_end,baseline);
  supplier_total:=(supplier->>'directCost')::numeric;
  IF (supplier->>'invalid')::boolean OR NEW.outputs->>'payrollCost' IS DISTINCT FROM cost::numeric(30,2)::text
   OR NEW.outputs->>'supplierCost' IS DISTINCT FROM supplier->>'directCost'
   OR NEW.outputs->>'supplierLineCount' IS DISTINCT FROM supplier->>'directCount'
   OR NEW.outputs->>'supplierExcludedLineCount' IS DISTINCT FROM supplier->>'excludedCount'
   OR NEW.outputs->>'supplierPendingLineCount' IS DISTINCT FROM supplier->>'pendingCount'
  THEN RAISE EXCEPTION 'Calculation source snapshot changed or does not reconcile' USING ERRCODE='23514'; END IF;
  snap:=snap||jsonb_build_object('format','profitpilot-source-trace-v2','supplier',supplier,'payrollCost',cost::numeric(30,2)::text);
  cost:=cost+supplier_total;
 END IF;
 IF baselines<>1 OR bad OR ic NOT BETWEEN 1 AND 10000 OR ac NOT BETWEEN 1 AND 10000
 OR NEW.outputs->>'revenue' IS DISTINCT FROM revenue::numeric(30,2)::text
 OR NEW.outputs->>'deliveryCost' IS DISTINCT FROM cost::numeric(30,2)::text
 OR NEW.outputs->>'indicativeContribution' IS DISTINCT FROM (revenue-cost)::numeric(30,2)::text
 OR NEW.outputs->>'invoiceLineCount' IS DISTINCT FROM ic::text OR NEW.outputs->>'allocationLineCount' IS DISTINCT FROM ac::text
 OR NEW.outputs->'contribution' IS DISTINCT FROM 'null'::jsonb OR NEW.outputs->'marginPercent' IS DISTINCT FROM 'null'::jsonb
 OR NEW.outputs->>'completeness' IS DISTINCT FROM 'incomplete'
 THEN RAISE EXCEPTION 'Calculation source snapshot changed or does not reconcile' USING ERRCODE='23514'; END IF;
 digest_value:=encode(public.digest(convert_to(snap::text,'UTF8'),'sha256'),'hex');
 INSERT INTO private.calculation_source_receipts(tenant_id,calculation_id,baseline_id,source_snapshot,snapshot_digest,invoice_count,allocation_count,reviewed_invoice_count)
 VALUES(NEW.tenant_id,NEW.id,baseline,snap,digest_value,ic,ac,reviewed);
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,metadata)
 VALUES(NEW.tenant_id,NEW.created_by,'calculation_source_receipt_created','calculation_run',NEW.id,jsonb_build_object('sourceDigest',digest_value));
 RETURN NEW;
END $fn$;
CREATE OR REPLACE FUNCTION private.guard_traced_calculation() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
BEGIN
 IF OLD.formula_version IN ('0.2.0','0.3.0') OR EXISTS(SELECT 1 FROM private.calculation_source_receipts WHERE calculation_id=OLD.id)
 THEN RAISE EXCEPTION 'Traced calculation is immutable' USING ERRCODE='55000'; END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;RETURN NEW;
END $fn$;
CREATE OR REPLACE FUNCTION private.calculation_trace_projection(p_tenant uuid,p_run uuid) RETURNS jsonb
LANGUAGE sql STABLE SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT jsonb_build_object('status','captured','format',source_snapshot->>'format','digest',snapshot_digest,'baselineId',baseline_id,
 'invoiceLineCount',invoice_count,'reviewedInvoiceLineCount',reviewed_invoice_count,'allocationLineCount',allocation_count,'capturedAt',captured_at)
 ||CASE WHEN source_snapshot->>'format'='profitpilot-source-trace-v2' THEN jsonb_build_object(
 'payrollCost',source_snapshot->>'payrollCost','supplierCost',source_snapshot->'supplier'->>'directCost',
 'supplierLineCount',(source_snapshot->'supplier'->>'directCount')::integer,
 'supplierExcludedLineCount',(source_snapshot->'supplier'->>'excludedCount')::integer,
 'supplierPendingLineCount',(source_snapshot->'supplier'->>'pendingCount')::integer) ELSE '{}'::jsonb END
 FROM private.calculation_source_receipts WHERE tenant_id=p_tenant AND calculation_id=p_run),jsonb_build_object('status','legacy_unavailable'))
$fn$;
CREATE OR REPLACE FUNCTION private.verify_security_catalog()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT digest=private.security_catalog_digest() FROM private.security_catalog_baseline WHERE revision=72),false)
$fn$;
INSERT INTO private.security_catalog_baseline(singleton,revision,digest) VALUES(true,72,private.security_catalog_digest());
COMMIT;

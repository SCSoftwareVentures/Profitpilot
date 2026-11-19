-- Minimize restricted payroll access and arbitrary saved calculation JSON.
BEGIN;
REVOKE SELECT ON public.payroll_source_rows,public.allocation_lines FROM profitpilot_app;
REVOKE SELECT ON public.calculation_runs FROM profitpilot_app;
GRANT SELECT(id,tenant_id,contract_id,site_id,period_start,period_end,formula_version,completeness,created_at,created_by) ON public.calculation_runs TO profitpilot_app;

-- Raw payroll staging is never needed by the invoice-only runtime.
CREATE POLICY raw_import_rows_invoice_read ON public.raw_import_rows AS RESTRICTIVE FOR SELECT TO profitpilot_app
 USING (EXISTS(SELECT 1 FROM public.import_batches b WHERE b.tenant_id=raw_import_rows.tenant_id AND b.id=raw_import_rows.batch_id
 AND b.source_type IN ('customer_invoice','supplier_invoice')));

-- No source references, individual amounts or worker-level identifiers returned.
CREATE FUNCTION private.site_payroll_summary(p_tenant uuid,p_site uuid,p_start date,p_end date)
RETURNS TABLE(partial_count bigint,amount numeric,line_count bigint,currency_count bigint,payroll_currency text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
BEGIN
 IF p_tenant IS NULL OR private.current_tenant_id() IS DISTINCT FROM p_tenant OR coalesce(private.current_actor_role(),'') NOT IN ('owner','admin','analyst','reviewer') THEN
  RAISE EXCEPTION 'Payroll summary authority denied' USING ERRCODE='42501';
 END IF;
 IF p_site IS NULL OR p_start IS NULL OR p_end IS NULL OR NOT isfinite(p_start) OR NOT isfinite(p_end) OR p_end<p_start
 OR NOT EXISTS(SELECT 1 FROM public.sites WHERE tenant_id=p_tenant AND id=p_site) THEN
  RAISE EXCEPTION 'Invalid payroll summary scope' USING ERRCODE='22023';
 END IF;
 RETURN QUERY SELECT
 count(*) FILTER(WHERE pp.period_start<=p_end AND pp.period_end>=p_start AND NOT (pp.period_start>=p_start AND pp.period_end<=p_end)),
 coalesce(sum(al.amount) FILTER(WHERE al.bucket_type IN ('direct','approved_allocated') AND pp.period_start>=p_start AND pp.period_end<=p_end),0)::numeric(14,2),
 count(*) FILTER(WHERE al.bucket_type IN ('direct','approved_allocated') AND pp.period_start>=p_start AND pp.period_end<=p_end),
 count(DISTINCT pp.currency) FILTER(WHERE al.bucket_type IN ('direct','approved_allocated') AND pp.period_start>=p_start AND pp.period_end<=p_end),
 min(pp.currency::text) FILTER(WHERE al.bucket_type IN ('direct','approved_allocated') AND pp.period_start>=p_start AND pp.period_end<=p_end)
 FROM public.allocation_lines al JOIN public.allocation_runs ar ON ar.id=al.allocation_run_id AND ar.tenant_id=al.tenant_id
 JOIN public.payroll_pools pp ON pp.id=ar.payroll_pool_id AND pp.tenant_id=ar.tenant_id
 WHERE al.tenant_id=p_tenant AND al.site_id=p_site AND ar.status='confirmed';
END $fn$;

CREATE FUNCTION private.read_calculation_summary(p_tenant uuid,p_run uuid)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE r public.calculation_runs%ROWTYPE;
BEGIN
 IF p_tenant IS NULL OR private.current_tenant_id() IS DISTINCT FROM p_tenant OR coalesce(private.current_actor_role(),'') NOT IN ('owner','admin','analyst','reviewer','read_only') THEN
  RAISE EXCEPTION 'Calculation read authority denied' USING ERRCODE='42501';
 END IF;
 SELECT * INTO r FROM public.calculation_runs WHERE tenant_id=p_tenant AND id=p_run;
 IF NOT FOUND THEN RETURN NULL; END IF;
 RETURN jsonb_build_object('id',r.id,'contract_id',r.contract_id,'site_id',r.site_id,
 'period_start',r.period_start,'period_end',r.period_end,'completeness',r.completeness,'created_at',r.created_at,
 'formula_version',CASE WHEN r.formula_version ~ '^[0-9]{1,4}[.][0-9]{1,4}[.][0-9]{1,4}$' THEN r.formula_version ELSE NULL END,
 'outputs',jsonb_build_object('currency',CASE WHEN r.outputs->>'currency' ~ '^[A-Z]{3}$' THEN r.outputs->>'currency' ELSE NULL END,
 'revenue',private.safe_export_money(r.outputs->'revenue'),
 'deliveryCost',private.safe_export_money(r.outputs->'deliveryCost'),
 'indicativeContribution',private.safe_export_money(r.outputs->'indicativeContribution'),
 'contribution',CASE WHEN r.completeness='complete' THEN private.safe_export_money(r.outputs->'contribution') ELSE NULL END,
 'marginPercent',CASE WHEN r.completeness='complete' THEN private.safe_export_money(r.outputs->'marginPercent') ELSE NULL END,
 'completeness',r.completeness,'limitations',jsonb_build_array('Management calculation only; not statutory or audited profit.','Source records and arbitrary stored notes are not included.')));
END $fn$;
REVOKE ALL ON FUNCTION private.site_payroll_summary(uuid,uuid,date,date),private.read_calculation_summary(uuid,uuid) FROM PUBLIC,profitpilot_app;
GRANT EXECUTE ON FUNCTION private.site_payroll_summary(uuid,uuid,date,date),private.read_calculation_summary(uuid,uuid) TO profitpilot_app;
COMMIT;

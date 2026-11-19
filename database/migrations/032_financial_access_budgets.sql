-- Application-facing financial functions share durable actor and tenant
-- budgets regardless of originating IP or API replica. Window starts with
-- first accepted request; reset after one hour. Failed transactions do not
-- consume quota; trusted API commits before returning financial results.
BEGIN;
CREATE TABLE private.financial_tenant_budgets(
 tenant_id uuid NOT NULL REFERENCES public.tenants(id),
 scope text NOT NULL CHECK(scope IN ('calculation_read','calculation_export','payroll_summary')),
 window_start timestamptz NOT NULL,
 used integer NOT NULL CHECK(used BETWEEN 1 AND 600),
 PRIMARY KEY(tenant_id,scope)
);
CREATE TABLE private.financial_actor_budgets(
 tenant_id uuid NOT NULL,
 actor_id uuid NOT NULL,
 scope text NOT NULL CHECK(scope IN ('calculation_read','calculation_export','payroll_summary')),
 window_start timestamptz NOT NULL,
 used integer NOT NULL CHECK(used BETWEEN 1 AND 120),
 PRIMARY KEY(tenant_id,actor_id,scope),
 FOREIGN KEY(tenant_id,actor_id) REFERENCES public.tenant_memberships(tenant_id,user_id)
);
REVOKE ALL ON private.financial_tenant_budgets,private.financial_actor_budgets FROM PUBLIC,profitpilot_app;

CREATE FUNCTION private.consume_financial_access_budget(p_tenant uuid,p_scope text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE actor uuid; actor_role text; actor_limit integer; tenant_limit integer; now_at timestamptz;
BEGIN
 IF p_tenant IS NULL OR private.current_tenant_id() IS DISTINCT FROM p_tenant THEN
  RAISE EXCEPTION 'Financial access authority denied' USING ERRCODE='42501';
 END IF;
 SELECT u.id,m.role INTO actor,actor_role FROM public.users u
 JOIN public.tenant_memberships m ON m.user_id=u.id JOIN public.tenants t ON t.id=m.tenant_id
 WHERE u.auth_subject=nullif(current_setting('app.tenant_subject',true),'')
 AND m.tenant_id=p_tenant AND m.status='active' AND u.status='active' AND t.status='active'
 FOR SHARE OF u,m,t;
 IF NOT FOUND THEN RAISE EXCEPTION 'Financial access authority denied' USING ERRCODE='42501'; END IF;
 CASE p_scope
  WHEN 'calculation_read' THEN actor_limit:=120;tenant_limit:=600;
  WHEN 'calculation_export' THEN
   IF actor_role NOT IN ('owner','admin') THEN RAISE EXCEPTION 'Financial access authority denied' USING ERRCODE='42501'; END IF;
   actor_limit:=10;tenant_limit:=50;
  WHEN 'payroll_summary' THEN
   IF actor_role NOT IN ('owner','admin','analyst','reviewer') THEN RAISE EXCEPTION 'Financial access authority denied' USING ERRCODE='42501'; END IF;
   actor_limit:=30;tenant_limit:=150;
  ELSE RAISE EXCEPTION 'Unknown financial access scope' USING ERRCODE='22023';
 END CASE;
 now_at:=clock_timestamp();
 -- Fixed lock order for all callers. Updates are atomic and actor denial
 -- rolls back tenant consumption; no counters change on a rejected scope.
 INSERT INTO private.financial_tenant_budgets AS b(tenant_id,scope,window_start,used)
 VALUES(p_tenant,p_scope,now_at,1)
 ON CONFLICT(tenant_id,scope) DO UPDATE SET
 window_start=CASE WHEN b.window_start<=now_at-interval '1 hour' THEN now_at ELSE b.window_start END,
 used=CASE WHEN b.window_start<=now_at-interval '1 hour' THEN 1 ELSE b.used+1 END
 WHERE b.used<tenant_limit OR b.window_start<=now_at-interval '1 hour';
 IF NOT FOUND THEN RAISE EXCEPTION 'Financial access quota exceeded' USING ERRCODE='P4501'; END IF;
 INSERT INTO private.financial_actor_budgets AS b(tenant_id,actor_id,scope,window_start,used)
 VALUES(p_tenant,actor,p_scope,now_at,1)
 ON CONFLICT(tenant_id,actor_id,scope) DO UPDATE SET
 window_start=CASE WHEN b.window_start<=now_at-interval '1 hour' THEN now_at ELSE b.window_start END,
 used=CASE WHEN b.window_start<=now_at-interval '1 hour' THEN 1 ELSE b.used+1 END
 WHERE b.used<actor_limit OR b.window_start<=now_at-interval '1 hour';
 IF NOT FOUND THEN RAISE EXCEPTION 'Financial access quota exceeded' USING ERRCODE='P4501'; END IF;
 RETURN actor;
END $fn$;
REVOKE ALL ON FUNCTION private.consume_financial_access_budget(uuid,text) FROM PUBLIC,profitpilot_app;

CREATE OR REPLACE FUNCTION private.site_payroll_summary(p_tenant uuid,p_site uuid,p_start date,p_end date)
RETURNS TABLE(partial_count bigint,amount numeric,line_count bigint,currency_count bigint,payroll_currency text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE actor uuid;
BEGIN
 IF p_tenant IS NULL OR private.current_tenant_id() IS DISTINCT FROM p_tenant OR coalesce(private.current_actor_role(),'') NOT IN ('owner','admin','analyst','reviewer') THEN
  RAISE EXCEPTION 'Payroll summary authority denied' USING ERRCODE='42501';
 END IF;
 actor:=private.consume_financial_access_budget(p_tenant,'payroll_summary');
 IF p_site IS NULL OR p_start IS NULL OR p_end IS NULL OR NOT isfinite(p_start) OR NOT isfinite(p_end) OR p_end<p_start
 OR NOT EXISTS(SELECT 1 FROM public.sites WHERE tenant_id=p_tenant AND id=p_site) THEN
  RAISE EXCEPTION 'Invalid payroll summary scope' USING ERRCODE='22023';
 END IF;
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id)
 VALUES(p_tenant,actor,'payroll_summary_accessed','site',p_site);
 RETURN QUERY SELECT
 count(*) FILTER(WHERE pp.period_start<=p_end AND pp.period_end>=p_start AND NOT (pp.period_start>=p_start AND pp.period_end<=p_end)),
 coalesce(sum(al.amount) FILTER(WHERE al.bucket_type IN ('direct','approved_allocated') AND pp.period_start>=p_start AND pp.period_end<=p_end),0)::numeric(14,2),
 count(*) FILTER(WHERE al.bucket_type IN ('direct','approved_allocated') AND pp.period_start>=p_start AND pp.period_end<=p_end),
 count(DISTINCT pp.currency) FILTER(WHERE al.bucket_type IN ('direct','approved_allocated') AND pp.period_start>=p_start AND pp.period_end<=p_end),
 min(pp.currency::text) FILTER(WHERE al.bucket_type IN ('direct','approved_allocated') AND pp.period_start>=p_start AND pp.period_end<=p_end)
 FROM public.allocation_lines al JOIN public.allocation_runs ar ON ar.id=al.allocation_run_id AND ar.tenant_id=al.tenant_id
 JOIN public.payroll_pools pp ON pp.id=ar.payroll_pool_id AND pp.tenant_id=ar.tenant_id
 WHERE al.tenant_id=p_tenant AND al.site_id=p_site AND ar.status='confirmed'
 AND pp.period_start<=p_end AND pp.period_end>=p_start;
END $fn$;

CREATE OR REPLACE FUNCTION private.read_calculation_summary(p_tenant uuid,p_run uuid)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE r public.calculation_runs%ROWTYPE; actor uuid;
BEGIN
 IF p_tenant IS NULL OR private.current_tenant_id() IS DISTINCT FROM p_tenant OR coalesce(private.current_actor_role(),'') NOT IN ('owner','admin','analyst','reviewer','read_only') THEN
  RAISE EXCEPTION 'Calculation read authority denied' USING ERRCODE='42501';
 END IF;
 actor:=private.consume_financial_access_budget(p_tenant,'calculation_read');
 SELECT * INTO r FROM public.calculation_runs WHERE tenant_id=p_tenant AND id=p_run;
 IF NOT FOUND THEN RETURN NULL; END IF;
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id)
 VALUES(p_tenant,actor,'calculation_summary_read','calculation_run',r.id);
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

CREATE OR REPLACE FUNCTION private.export_calculation_summary(p_tenant uuid,p_run uuid,p_purpose text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE record_row public.calculation_runs%ROWTYPE; actor uuid; event_id uuid; summary jsonb;
BEGIN
 IF p_tenant IS NULL OR p_run IS NULL OR private.current_tenant_id() IS DISTINCT FROM p_tenant
 OR coalesce(private.current_actor_role(),'') NOT IN ('owner','admin') THEN
  RAISE EXCEPTION 'Export authority denied' USING ERRCODE='42501';
 END IF;
 IF p_purpose IS NULL OR p_purpose NOT IN ('internal_review','customer_reporting','accountant_review') THEN
  RAISE EXCEPTION 'Invalid export purpose' USING ERRCODE='22023';
 END IF;
 SELECT u.id INTO actor FROM public.users u
 JOIN public.tenant_memberships tm ON tm.user_id=u.id
 JOIN public.tenants t ON t.id=tm.tenant_id
 WHERE u.auth_subject=nullif(current_setting('app.tenant_subject',true),'')
 AND u.status='active' AND tm.tenant_id=p_tenant AND tm.status='active'
 AND tm.role IN ('owner','admin') AND t.status='active'
 FOR SHARE OF u,tm,t;
 IF NOT FOUND THEN RAISE EXCEPTION 'Export authority denied' USING ERRCODE='42501'; END IF;
 PERFORM private.consume_financial_access_budget(p_tenant,'calculation_export');
 SELECT * INTO record_row FROM public.calculation_runs WHERE tenant_id=p_tenant AND id=p_run;
 IF NOT FOUND THEN RETURN NULL; END IF;
 INSERT INTO private.calculation_export_events(tenant_id,actor_user_id,calculation_id,purpose)
 VALUES(p_tenant,actor,p_run,p_purpose) RETURNING id INTO event_id;
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,metadata)
 VALUES(p_tenant,actor,'calculation_summary_exported','calculation_run',p_run,jsonb_build_object('purpose',p_purpose,'exportId',event_id));
 summary:=jsonb_build_object(
  'exportId',event_id,'calculationId',record_row.id,'contractId',record_row.contract_id,'siteId',record_row.site_id,
  'periodStart',record_row.period_start,'periodEnd',record_row.period_end,
  'completeness',record_row.completeness,
  'currency',CASE WHEN (record_row.outputs->>'currency') ~ '^[A-Z]{3}$' THEN record_row.outputs->>'currency' ELSE NULL END,
  'revenue',private.safe_export_money(record_row.outputs->'revenue'),
  'deliveryCost',private.safe_export_money(record_row.outputs->'deliveryCost'),
  'indicativeContribution',private.safe_export_money(record_row.outputs->'indicativeContribution'),
  'contribution',CASE WHEN record_row.completeness='complete' THEN private.safe_export_money(record_row.outputs->'contribution') ELSE NULL END,
  'marginPercent',CASE WHEN record_row.completeness='complete' THEN private.safe_export_money(record_row.outputs->'marginPercent') ELSE NULL END,
  'notice','Management calculation only; not audited or statutory profit.'
 );
 RETURN summary;
END $fn$;
COMMIT;

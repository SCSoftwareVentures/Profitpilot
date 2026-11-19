-- Narrow single-calculation export; no raw source rows, payroll, arbitrary JSON,
-- names, contact fields or free-text input. The API verifies recent MFA.
BEGIN;
CREATE TABLE private.calculation_export_events (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id uuid NOT NULL,
 actor_user_id uuid NOT NULL,
 calculation_id uuid NOT NULL,
 purpose text NOT NULL CHECK(purpose IN ('internal_review','customer_reporting','accountant_review')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON private.calculation_export_events FROM PUBLIC,profitpilot_app;

CREATE FUNCTION private.safe_export_money(v jsonb)
RETURNS text LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $fn$
 SELECT CASE WHEN jsonb_typeof(v)='string' AND (v #>> '{}') ~ '^-?[0-9]{1,18}[.][0-9]{2}$' THEN v #>> '{}' ELSE NULL END
$fn$;

CREATE FUNCTION private.export_calculation_summary(p_tenant uuid,p_run uuid,p_purpose text)
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
 SELECT * INTO record_row FROM public.calculation_runs WHERE tenant_id=p_tenant AND id=p_run;
 IF NOT FOUND THEN RETURN NULL; END IF;
 INSERT INTO private.calculation_export_events(tenant_id,actor_user_id,calculation_id,purpose)
 VALUES(p_tenant,actor,p_run,p_purpose) RETURNING id INTO event_id;
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
REVOKE ALL ON FUNCTION private.safe_export_money(jsonb),private.export_calculation_summary(uuid,uuid,text) FROM PUBLIC,profitpilot_app;
GRANT EXECUTE ON FUNCTION private.export_calculation_summary(uuid,uuid,text) TO profitpilot_app;
COMMIT;

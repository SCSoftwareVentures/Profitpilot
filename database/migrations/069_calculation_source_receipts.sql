-- Immutable bounded source snapshot for indicative calculations. No raw employee
-- or invoice descriptions are included; public projections contain counts/digest only.
BEGIN;
DO $check$ BEGIN
 IF private.verify_security_catalog() IS DISTINCT FROM true THEN RAISE EXCEPTION 'Prior catalog does not verify'; END IF;
END $check$;
CREATE TABLE private.calculation_source_receipts(
 tenant_id uuid NOT NULL,calculation_id uuid PRIMARY KEY REFERENCES public.calculation_runs(id),
 baseline_id uuid NOT NULL REFERENCES public.contract_versions(id),
 source_snapshot jsonb NOT NULL CHECK(jsonb_typeof(source_snapshot)='object' AND octet_length(source_snapshot::text)<=12000000),
 snapshot_digest text NOT NULL CHECK(snapshot_digest ~ '^[a-f0-9]{64}$'),
 invoice_count integer NOT NULL CHECK(invoice_count BETWEEN 1 AND 10000),
 allocation_count integer NOT NULL CHECK(allocation_count BETWEEN 1 AND 10000),
 reviewed_invoice_count integer NOT NULL CHECK(reviewed_invoice_count BETWEEN 0 AND invoice_count),
 captured_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON private.calculation_source_receipts FROM PUBLIC,profitpilot_app;
CREATE TRIGGER calc_receipts_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON private.calculation_source_receipts FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();
CREATE FUNCTION private.capture_calculation_sources() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $fn$
DECLARE snap jsonb; baseline uuid; baselines integer; revenue numeric; cost numeric; ic integer; ac integer; reviewed integer;
 bad boolean; digest_value text;
BEGIN
 IF NEW.formula_version<>'0.2.0' THEN RETURN NEW; END IF;
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
CREATE TRIGGER capture_calc_sources AFTER INSERT ON public.calculation_runs FOR EACH ROW EXECUTE FUNCTION private.capture_calculation_sources();
CREATE FUNCTION private.guard_traced_calculation() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
BEGIN
 IF OLD.formula_version='0.2.0' OR EXISTS(SELECT 1 FROM private.calculation_source_receipts WHERE calculation_id=OLD.id)
 THEN RAISE EXCEPTION 'Traced calculation is immutable' USING ERRCODE='55000'; END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;RETURN NEW;
END $fn$;
CREATE TRIGGER traced_calculation_immutable BEFORE UPDATE OR DELETE ON public.calculation_runs FOR EACH ROW EXECUTE FUNCTION private.guard_traced_calculation();
CREATE FUNCTION private.calculation_trace_projection(p_tenant uuid,p_run uuid) RETURNS jsonb
LANGUAGE sql STABLE SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT jsonb_build_object('status','captured','format','profitpilot-source-trace-v1','digest',snapshot_digest,'baselineId',baseline_id,
 'invoiceLineCount',invoice_count,'reviewedInvoiceLineCount',reviewed_invoice_count,'allocationLineCount',allocation_count,'capturedAt',captured_at)
 FROM private.calculation_source_receipts WHERE tenant_id=p_tenant AND calculation_id=p_run),jsonb_build_object('status','legacy_unavailable'))
$fn$;
REVOKE ALL ON FUNCTION private.capture_calculation_sources(),private.guard_traced_calculation(),private.calculation_trace_projection(uuid,uuid) FROM PUBLIC,profitpilot_app;

CREATE OR REPLACE FUNCTION private.read_calculation_summary(p_tenant uuid,p_run uuid)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE r public.calculation_runs%ROWTYPE; actor uuid;
BEGIN
 IF p_tenant IS NULL OR private.current_tenant_id() IS DISTINCT FROM p_tenant OR coalesce(private.current_actor_role(),'') NOT IN ('owner','admin','analyst','reviewer','read_only') THEN
  RAISE EXCEPTION 'Calculation read authority denied' USING ERRCODE='42501';
 END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('payroll-correction:'||p_tenant::text,0));
 actor:=private.consume_financial_access_budget(p_tenant,'calculation_read');
 SELECT * INTO r FROM public.calculation_runs WHERE tenant_id=p_tenant AND id=p_run;
 IF NOT FOUND THEN RETURN NULL; END IF;
 PERFORM private.assert_calculation_not_superseded(p_tenant,r.period_start,r.period_end,r.created_at);
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id)
 VALUES(p_tenant,actor,'calculation_summary_read','calculation_run',r.id);
 RETURN jsonb_build_object('id',r.id,'contract_id',r.contract_id,'site_id',r.site_id,
 'period_start',r.period_start,'period_end',r.period_end,'completeness',r.completeness,'created_at',r.created_at,
 'formula_version',CASE WHEN r.formula_version ~ '^[0-9]{1,4}[.][0-9]{1,4}[.][0-9]{1,4}$' THEN r.formula_version ELSE NULL END,
 'sourceTrace',private.calculation_trace_projection(r.tenant_id,r.id),
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
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('payroll-correction:'||p_tenant::text,0));
 PERFORM private.consume_financial_access_budget(p_tenant,'calculation_export');
 SELECT * INTO record_row FROM public.calculation_runs WHERE tenant_id=p_tenant AND id=p_run;
 IF NOT FOUND THEN RETURN NULL; END IF;
 PERFORM private.assert_calculation_not_superseded(p_tenant,record_row.period_start,record_row.period_end,record_row.created_at);
 INSERT INTO private.calculation_export_events(tenant_id,actor_user_id,calculation_id,purpose)
 VALUES(p_tenant,actor,p_run,p_purpose) RETURNING id INTO event_id;
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,metadata)
 VALUES(p_tenant,actor,'calculation_summary_exported','calculation_run',p_run,jsonb_build_object('purpose',p_purpose,'exportId',event_id));
 summary:=jsonb_build_object(
  'exportId',event_id,'calculationId',record_row.id,'contractId',record_row.contract_id,'siteId',record_row.site_id,
  'periodStart',record_row.period_start,'periodEnd',record_row.period_end,
  'completeness',record_row.completeness,
  'sourceTrace',private.calculation_trace_projection(record_row.tenant_id,record_row.id),
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
CREATE OR REPLACE FUNCTION private.sensitive_recovery_fingerprint()
RETURNS text LANGUAGE plpgsql STABLE SET search_path=pg_catalog SET timezone='UTC' AS $fn$
DECLARE total bigint; result text;
BEGIN
 WITH entries AS (
  SELECT * FROM (
  SELECT 'account_email'::text AS kind,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') AS hash FROM (SELECT id,email FROM public.users LIMIT 100001) x
  UNION ALL SELECT 'security_work_orders'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.security_work_orders LIMIT 100001) x
  UNION ALL SELECT 'security_work_decisions'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.security_work_decisions LIMIT 100001) x
  UNION ALL SELECT 'security_work_consumptions'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.security_work_consumptions LIMIT 100001) x
  UNION ALL SELECT 'account_correction_nonces'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.account_correction_nonces LIMIT 100001) x
  UNION ALL SELECT 'privacy_rights_cases'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.privacy_rights_cases LIMIT 100001) x
  UNION ALL SELECT 'privacy_rights_acknowledgements'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.privacy_rights_acknowledgements LIMIT 100001) x
  UNION ALL SELECT 'privacy_rights_outcomes'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.privacy_rights_outcomes LIMIT 100001) x
  UNION ALL SELECT 'payroll_proposal_reviews'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.payroll_proposal_reviews LIMIT 100001) x
  UNION ALL SELECT 'payroll_proposal_decisions'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.payroll_proposal_decisions LIMIT 100001) x
  UNION ALL SELECT 'payroll_confirmation_receipts'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.payroll_confirmation_receipts LIMIT 100001) x
  UNION ALL SELECT 'payroll_correction_reservations'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.payroll_correction_reservations LIMIT 100001) x
  UNION ALL SELECT 'payroll_supersessions'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.payroll_supersessions LIMIT 100001) x
  UNION ALL SELECT 'financial_retention_reviews'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.financial_retention_reviews LIMIT 100001) x
  UNION ALL SELECT 'financial_retention_holds'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.financial_retention_holds LIMIT 100001) x
  UNION ALL SELECT 'financial_backup_plans'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.financial_backup_plans LIMIT 100001) x
  UNION ALL SELECT 'privacy_delivery_authorizations'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.privacy_delivery_authorizations LIMIT 100001) x
  UNION ALL SELECT 'privacy_delivery_requests'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.privacy_delivery_requests LIMIT 100001) x
  UNION ALL SELECT 'privacy_receipt_evidence'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.privacy_receipt_evidence LIMIT 100001) x
  UNION ALL SELECT 'privacy_receipt_requests'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.privacy_receipt_requests LIMIT 100001) x
  UNION ALL SELECT 'privacy_dispatch_reservations'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.privacy_dispatch_reservations LIMIT 100001) x
  UNION ALL SELECT 'privacy_dispatch_burns'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.privacy_dispatch_burns LIMIT 100001) x
  UNION ALL SELECT 'privacy_dispatch_revocations'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.privacy_dispatch_revocations LIMIT 100001) x
  UNION ALL SELECT 'privacy_case_key_versions'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.privacy_case_key_versions LIMIT 100001) x
  UNION ALL SELECT 'privacy_compromised_keys'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.privacy_compromised_keys LIMIT 100001) x
  UNION ALL SELECT 'payroll_intake_receipts'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.payroll_intake_receipts LIMIT 100001) x
  UNION ALL SELECT 'payroll_intake_requests'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.payroll_intake_requests LIMIT 100001) x
  UNION ALL SELECT 'payroll_allocation_builds'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.payroll_allocation_builds LIMIT 100001) x
  UNION ALL SELECT 'workspace_records'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.workspace_records LIMIT 100001) x
  UNION ALL SELECT 'workspace_version_orders'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.workspace_version_orders LIMIT 100001) x
  UNION ALL SELECT 'workspace_version_receipts'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.workspace_version_receipts LIMIT 100001) x
  UNION ALL SELECT 'workspace_jobs'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.workspace_jobs LIMIT 100001) x
  UNION ALL SELECT 'workspace_job_events'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.workspace_job_events LIMIT 100001) x
  UNION ALL SELECT 'invoice_intake_orders'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.invoice_intake_orders LIMIT 100001) x
  UNION ALL SELECT 'invoice_intake_receipts'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.invoice_intake_receipts LIMIT 100001) x
  UNION ALL SELECT 'invoice_intake_lines'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.invoice_intake_lines LIMIT 100001) x
  UNION ALL SELECT 'calculation_source_receipts'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.calculation_source_receipts LIMIT 100001) x
  ) all_entries LIMIT 100001
 ), hashes AS (SELECT kind,encode(hash,'hex') AS h FROM entries)
 SELECT count(*),CASE WHEN count(*)<=100000 THEN encode(public.digest(convert_to('profitpilot-sensitive-recovery-v16:'||coalesce(string_agg(kind||':'||h,',' ORDER BY kind COLLATE "C",h COLLATE "C"),''),'UTF8'),'sha256'),'hex') END
 INTO total,result FROM hashes;
 IF total>100000 OR result IS NULL THEN RAISE EXCEPTION 'Sensitive recovery inventory exceeds reviewed capacity' USING ERRCODE='54000'; END IF;
 RETURN result;
END $fn$;
REVOKE ALL ON FUNCTION private.sensitive_recovery_fingerprint() FROM PUBLIC,profitpilot_app;
CREATE OR REPLACE FUNCTION private.verify_security_catalog()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT digest=private.security_catalog_digest() FROM private.security_catalog_baseline WHERE revision=69),false)
$fn$;
INSERT INTO private.security_catalog_baseline(singleton,revision,digest) VALUES(true,69,private.security_catalog_digest());
COMMIT;

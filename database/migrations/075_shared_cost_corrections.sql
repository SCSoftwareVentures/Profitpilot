-- Append-only correction chain; original reports retained, serving fenced.
BEGIN;
DO $check$ BEGIN IF private.verify_security_catalog() IS DISTINCT FROM true THEN RAISE EXCEPTION 'Prior catalog does not verify'; END IF; END $check$;
ALTER TABLE private.shared_cost_orders ADD COLUMN replaces_order_id uuid,
 ADD FOREIGN KEY(tenant_id,source_kind,source_id,replaces_order_id) REFERENCES private.shared_cost_orders(tenant_id,source_kind,source_id,order_id),
 ADD CHECK(replaces_order_id IS NULL OR replaces_order_id<>order_id);
CREATE TABLE private.shared_cost_revisions(
 tenant_id uuid NOT NULL,source_kind text NOT NULL,source_id uuid NOT NULL,prior_order_id uuid NOT NULL,new_order_id uuid NOT NULL,
 corrected_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,prior_order_id),UNIQUE(tenant_id,new_order_id),
 CHECK(prior_order_id<>new_order_id),
 FOREIGN KEY(tenant_id,source_kind,source_id,prior_order_id) REFERENCES private.shared_cost_orders(tenant_id,source_kind,source_id,order_id),
 FOREIGN KEY(tenant_id,source_kind,source_id,new_order_id) REFERENCES private.shared_cost_orders(tenant_id,source_kind,source_id,order_id),
 FOREIGN KEY(tenant_id,new_order_id) REFERENCES private.security_work_consumptions(tenant_id,order_id)
);
REVOKE ALL ON private.shared_cost_revisions FROM PUBLIC,profitpilot_app;
CREATE TRIGGER shared_cost_revision_frozen BEFORE UPDATE OR DELETE OR TRUNCATE ON private.shared_cost_revisions FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();
CREATE VIEW private.active_shared_cost_receipts AS
 SELECT v.* FROM (
 SELECT tenant_id,source_kind,source_id,order_id FROM private.shared_cost_receipts
 UNION ALL SELECT tenant_id,source_kind,source_id,new_order_id FROM private.shared_cost_revisions
 ) v WHERE NOT EXISTS(SELECT 1 FROM private.shared_cost_revisions x WHERE x.tenant_id=v.tenant_id AND x.prior_order_id=v.order_id);
REVOKE ALL ON private.active_shared_cost_receipts FROM PUBLIC,profitpilot_app;
CREATE OR REPLACE FUNCTION private.shared_cost_summary(p_tenant uuid,p_kind text,p_source uuid,p_order uuid) RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE result jsonb;
BEGIN
 SELECT jsonb_build_object('source',q.source_snapshot,'shares',q.shares,'orderId',q.order_id,'scopeDigest',q.scope_digest,'evidenceDigest',q.evidence_digest,
 'sourceActive',private.shared_cost_source(p_tenant,p_kind,p_source) IS NOT DISTINCT FROM q.source_snapshot,
 'status',CASE WHEN r.order_id=q.order_id THEN 'allocated' WHEN r.order_id IS NOT NULL AND q.replaces_order_id IS DISTINCT FROM r.order_id THEN 'superseded'
 WHEN d.decision='rejected' THEN 'rejected' WHEN d.expires_at<=clock_timestamp() OR (d.order_id IS NULL AND w.requested_at+interval '24 hours'<=clock_timestamp()) THEN 'expired'
 WHEN d.decision='approved' THEN 'approved_pending_record' ELSE 'requested' END,'includedInCalculation',false,'paymentAuthorized',false)
 ||CASE WHEN q.replaces_order_id IS NOT NULL THEN jsonb_build_object('replacesOrderId',q.replaces_order_id) ELSE '{}'::jsonb END
 INTO result FROM private.shared_cost_orders q JOIN private.security_work_orders w ON w.tenant_id=q.tenant_id AND w.id=q.order_id
 LEFT JOIN private.security_work_decisions d ON d.tenant_id=q.tenant_id AND d.order_id=q.order_id
 LEFT JOIN private.active_shared_cost_receipts r ON r.tenant_id=q.tenant_id AND r.source_kind=q.source_kind AND r.source_id=q.source_id
 WHERE q.tenant_id=p_tenant AND q.source_kind=p_kind AND q.source_id=p_source AND q.order_id=p_order;
 IF result IS NULL THEN RAISE EXCEPTION 'Shared allocation unavailable' USING ERRCODE='42501'; END IF;RETURN result;
END $fn$;
CREATE FUNCTION private.api_shared_cost_correction_step(p_tenant uuid,p_kind text,p_source uuid,p_order uuid,p_replaces uuid,p_shares jsonb,p_evidence text,p_scope text,p_step text,
 p_auth bigint,p_iat bigint,p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $fn$
DECLARE actor uuid; src jsonb; active_order uuid; prior_shares jsonb; existing private.shared_cost_orders%ROWTYPE; item jsonb; target text; baseline text; amount text; prev text:=''; total numeric:=0; canonical text;
BEGIN
 actor:=private.security_work_actor(p_tenant,p_order,'privileged_operation',p_scope,p_step,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 IF p_kind IS NULL OR p_kind NOT IN ('payroll','overhead') OR p_source IS NULL OR p_evidence IS NULL OR p_evidence !~ '^[a-f0-9]{64}$' OR p_evidence=repeat('0',64)
 OR jsonb_typeof(p_shares) IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'Shared scope denied' USING ERRCODE='42501'; END IF;
 IF jsonb_array_length(p_shares) NOT BETWEEN 1 AND 100 OR octet_length(p_shares::text)>24000 THEN RAISE EXCEPTION 'Shared allocation capacity' USING ERRCODE='54000'; END IF;
 -- Same lock order as calculations: payroll correction then workspace.
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('payroll-correction:'||p_tenant::text,0));
 PERFORM pg_advisory_xact_lock(hashtextextended('profitpilot-workspace:'||p_tenant::text,0));
 SELECT r.order_id,q.shares INTO active_order,prior_shares FROM private.active_shared_cost_receipts r
 JOIN private.shared_cost_orders q ON q.tenant_id=r.tenant_id AND q.order_id=r.order_id
 WHERE r.tenant_id=p_tenant AND r.source_kind=p_kind AND r.source_id=p_source;
 IF p_replaces IS NULL OR active_order IS DISTINCT FROM p_replaces OR p_order=p_replaces THEN RAISE EXCEPTION 'Stale correction predecessor' USING ERRCODE='23514'; END IF;
 IF prior_shares IS NOT DISTINCT FROM p_shares THEN RAISE EXCEPTION 'Correction must change allocation' USING ERRCODE='23514'; END IF;
 src:=private.shared_cost_source(p_tenant,p_kind,p_source);
 IF src IS NULL THEN RAISE EXCEPTION 'Active reviewed source unavailable' USING ERRCODE='42501'; END IF;
 canonical:='shared-cost-correction-v1'||E'\n'||p_kind||E'\n'||p_source||E'\n'||p_replaces||E'\n'||p_evidence;
 FOR item IN SELECT value FROM jsonb_array_elements(p_shares) LOOP
  IF jsonb_typeof(item) IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'Invalid share' USING ERRCODE='23514'; END IF;
  IF jsonb_array_length(item)<>3 OR jsonb_typeof(item->2) IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'Invalid share' USING ERRCODE='23514'; END IF;
  target:=item->>0;baseline:=item->>1;amount:=item->>2;
  IF amount IS NULL OR amount !~ '^(0|[1-9][0-9]{0,11})[.][0-9]{2}$' OR amount='0.00'
  OR (target IS NULL)<>(baseline IS NULL) THEN RAISE EXCEPTION 'Invalid share' USING ERRCODE='23514'; END IF;
  IF target IS NULL THEN
   IF item->0 IS DISTINCT FROM 'null'::jsonb OR item->1 IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION 'Invalid remainder' USING ERRCODE='23514'; END IF;
   target:='~';baseline:='~';
  ELSE
   IF jsonb_typeof(item->0) IS DISTINCT FROM 'string' OR jsonb_typeof(item->1) IS DISTINCT FROM 'string'
   OR target !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
   OR baseline !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
   THEN RAISE EXCEPTION 'Invalid target' USING ERRCODE='23514'; END IF;
   IF NOT EXISTS(SELECT 1 FROM private.workspace_records a JOIN public.contract_versions v ON v.tenant_id=a.tenant_id AND v.contract_id=a.parent_id
    JOIN public.contracts c ON c.tenant_id=v.tenant_id AND c.id=v.contract_id
    JOIN public.sites s ON s.tenant_id=c.tenant_id AND s.business_id=c.business_id AND s.id=a.related_id
    WHERE a.tenant_id=p_tenant AND a.kind='contract_site' AND a.parent_id=target::uuid AND a.related_id=(src->>'siteId')::uuid
    AND v.id=baseline::uuid AND v.approved_at IS NOT NULL AND v.approved_by IS NOT NULL AND v.currency='AUD' AND v.tax_basis<>'unknown'
    AND v.effective_from<=(src->>'periodStart')::date AND (v.effective_to IS NULL OR v.effective_to>=(src->>'periodEnd')::date)
    AND (p_kind='payroll' OR v.tax_basis=src->>'taxBasis'))
   THEN RAISE EXCEPTION 'Approved contract target unavailable' USING ERRCODE='42501'; END IF;
  END IF;
  IF target COLLATE "C"<=prev COLLATE "C" THEN RAISE EXCEPTION 'Duplicate or unordered share' USING ERRCODE='23514'; END IF;
  prev:=target;total:=total+amount::numeric;
  canonical:=canonical||E'\n'||target||','||baseline||','||amount;
 END LOOP;
 IF total IS DISTINCT FROM (src->>'amount')::numeric THEN RAISE EXCEPTION 'Allocation must reconcile exactly' USING ERRCODE='23514'; END IF;
 IF p_scope IS DISTINCT FROM encode(public.digest(convert_to(canonical,'UTF8'),'sha256'),'hex') THEN RAISE EXCEPTION 'Shared scope denied' USING ERRCODE='42501'; END IF;
 IF p_step<>'request' THEN
  SELECT * INTO existing FROM private.shared_cost_orders WHERE tenant_id=p_tenant AND order_id=p_order AND source_kind=p_kind AND source_id=p_source AND scope_digest=p_scope;
  IF NOT FOUND OR existing.source_snapshot IS DISTINCT FROM src OR existing.replaces_order_id IS DISTINCT FROM p_replaces THEN RAISE EXCEPTION 'Reviewed source changed' USING ERRCODE='42501'; END IF;
 END IF;

 IF p_step='request' AND (SELECT count(*) FROM private.shared_cost_orders WHERE tenant_id=p_tenant AND source_kind=p_kind AND source_id=p_source)>=20 THEN RAISE EXCEPTION 'Review capacity reached' USING ERRCODE='54000'; END IF;
 PERFORM private.record_security_work(p_tenant,p_order,'privileged_operation',p_scope,p_step,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 IF p_step='request' THEN
  INSERT INTO private.shared_cost_orders(tenant_id,order_id,source_kind,source_id,source_snapshot,shares,evidence_digest,scope_digest,replaces_order_id)
  VALUES(p_tenant,p_order,p_kind,p_source,src,p_shares,p_evidence,p_scope,p_replaces);
 ELSIF p_step='consume' THEN
  INSERT INTO private.shared_cost_revisions(tenant_id,source_kind,source_id,prior_order_id,new_order_id) VALUES(p_tenant,p_kind,p_source,p_replaces,p_order);
  INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,metadata)
  VALUES(p_tenant,actor,'shared_cost_corrected','shared_cost_source',p_source,jsonb_build_object('kind',p_kind,'scopeDigest',p_scope,'orderId',p_order,'priorOrderId',p_replaces));
 END IF;
 PERFORM private.sensitive_api_fresh(p_auth,p_expires);
 RETURN private.shared_cost_summary(p_tenant,p_kind,p_source,p_order);
END $fn$;
REVOKE ALL ON FUNCTION private.api_shared_cost_correction_step(uuid,text,uuid,uuid,uuid,jsonb,text,text,text,bigint,bigint,text,bigint,text,text,text) FROM PUBLIC,profitpilot_app;
GRANT EXECUTE ON FUNCTION private.api_shared_cost_correction_step(uuid,text,uuid,uuid,uuid,jsonb,text,text,text,bigint,bigint,text,bigint,text,text,text) TO profitpilot_app;
CREATE OR REPLACE FUNCTION private.shared_cost_calculation_snapshot(t uuid,c uuid,s uuid,starts date,ends date,baseline uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $fn$
DECLARE result jsonb; basis text;
BEGIN
 IF private.current_tenant_id() IS DISTINCT FROM t OR coalesce(private.current_actor_role(),'') NOT IN ('owner','admin','analyst','reviewer')
 OR c IS NULL OR s IS NULL OR starts IS NULL OR ends IS NULL OR ends<starts OR NOT isfinite(starts) OR NOT isfinite(ends)
 OR NOT private.workspace_contract_site_allowed(t,c,s) THEN RAISE EXCEPTION 'Shared calculation denied' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('payroll-correction:'||t::text,0));
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('profitpilot-workspace:'||t::text,0));
 SELECT v.tax_basis INTO basis FROM public.contract_versions v JOIN public.contracts co ON co.tenant_id=v.tenant_id AND co.id=v.contract_id
 JOIN public.sites si ON si.tenant_id=co.tenant_id AND si.business_id=co.business_id AND si.id=s
 WHERE v.tenant_id=t AND v.contract_id=c AND v.id=baseline AND v.approved_at IS NOT NULL AND v.approved_by IS NOT NULL
 AND v.effective_from<=starts AND (v.effective_to IS NULL OR v.effective_to>=ends) AND v.currency='AUD' AND v.tax_basis<>'unknown';
 IF NOT FOUND THEN RAISE EXCEPTION 'Shared calculation baseline unavailable' USING ERRCODE='23514'; END IF;
 WITH sources AS MATERIALIZED (
 SELECT * FROM (
 SELECT 'payroll'::text kind,a.id FROM public.allocation_lines a
 JOIN public.allocation_runs r ON r.tenant_id=a.tenant_id AND r.id=a.allocation_run_id
 JOIN public.payroll_pools p ON p.tenant_id=r.tenant_id AND p.id=r.payroll_pool_id
 WHERE a.tenant_id=t AND a.site_id=s AND a.amount>0 AND a.bucket_type IN ('direct','approved_allocated')
 AND r.status='confirmed' AND p.period_start<=ends AND p.period_end>=starts
 AND NOT EXISTS(SELECT 1 FROM private.payroll_supersessions x WHERE x.tenant_id=r.tenant_id AND x.old_run_id=r.id)
 UNION ALL
 SELECT 'overhead'::text kind,k.line_id FROM private.invoice_intake_lines k
 JOIN public.match_reviews m ON m.tenant_id=k.tenant_id AND m.id=k.match_id AND m.invoice_line_id=k.line_id
 JOIN private.supplier_cost_receipts r ON r.tenant_id=k.tenant_id AND r.batch_id=k.batch_id
 JOIN private.supplier_cost_orders q ON q.tenant_id=r.tenant_id AND q.batch_id=r.batch_id AND q.order_id=r.order_id
 WHERE k.tenant_id=t AND m.site_id=s AND m.decision='confirmed' AND q.classification='overhead_pending'
 AND (m.service_period_start IS NULL OR m.service_period_end IS NULL OR (m.service_period_start<=ends AND m.service_period_end>=starts))
 ) u ORDER BY kind,id LIMIT 10001
 ), facts AS MATERIALIZED (
 SELECT x.kind,x.id,private.shared_cost_source(t,x.kind,x.id) actual,q.order_id,q.source_snapshot,q.shares,q.scope_digest,q.evidence_digest
 FROM sources x LEFT JOIN private.active_shared_cost_receipts r ON r.tenant_id=t AND r.source_kind=x.kind AND r.source_id=x.id
 LEFT JOIN private.shared_cost_orders q ON q.tenant_id=r.tenant_id AND q.source_kind=r.source_kind AND q.source_id=r.source_id AND q.order_id=r.order_id
 ), assessed AS (
 SELECT f.*,coalesce((SELECT sum((v->>2)::numeric) FROM jsonb_array_elements(f.shares) v WHERE v->>0=c::text AND v->>1=baseline::text),0) chosen,
 coalesce((SELECT sum((v->>2)::numeric) FROM jsonb_array_elements(f.shares) v WHERE v->>0 IS NULL),0) remainder,
 EXISTS(SELECT 1 FROM jsonb_array_elements(f.shares) v WHERE v->>0=c::text AND v->>1 IS DISTINCT FROM baseline::text) wrong_baseline
 FROM facts f
 )
 SELECT jsonb_build_object('payrollCost',coalesce(sum(chosen) FILTER(WHERE kind='payroll'),0)::numeric(30,2)::text,
 'overheadCost',coalesce(sum(chosen) FILTER(WHERE kind='overhead'),0)::numeric(30,2)::text,
 'unallocatedSiteCost',coalesce(sum(remainder),0)::numeric(30,2)::text,
 'sourceCount',count(*),'missingCount',count(*) FILTER(WHERE order_id IS NULL),
 'invalid',count(*)>10000 OR coalesce(bool_or(actual IS NULL OR (order_id IS NOT NULL AND actual IS DISTINCT FROM source_snapshot)
 OR (actual->>'periodStart')::date<starts OR (actual->>'periodEnd')::date>ends OR actual->>'currency'<>'AUD'
 OR (kind='overhead' AND actual->>'taxBasis' IS DISTINCT FROM basis) OR wrong_baseline),false),
 'lines',coalesce(jsonb_agg(jsonb_build_array(kind,id,actual,order_id,shares,scope_digest,evidence_digest,chosen::numeric(30,2)::text,remainder::numeric(30,2)::text) ORDER BY kind,id),'[]'::jsonb))
 INTO result FROM assessed;
 RETURN result;
END $fn$;
CREATE FUNCTION private.assert_shared_calculation_current(t uuid,r uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog AS $fn$
BEGIN
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('profitpilot-workspace:'||t::text,0));
 IF EXISTS(SELECT 1 FROM private.calculation_source_receipts c
 CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN c.source_snapshot->>'format'='profitpilot-source-trace-v3' THEN c.source_snapshot->'shared'->'lines' ELSE '[]'::jsonb END) l
 JOIN private.shared_cost_revisions x ON x.tenant_id=t AND x.source_kind=l->>0 AND x.source_id::text=l->>1 AND x.prior_order_id::text=l->>3
 WHERE c.tenant_id=t AND c.calculation_id=r)
 THEN RAISE EXCEPTION 'Calculation requires reconciliation after shared cost correction' USING ERRCODE='P4503'; END IF;
END $fn$;
REVOKE ALL ON FUNCTION private.assert_shared_calculation_current(uuid,uuid) FROM PUBLIC,profitpilot_app;
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
 PERFORM private.assert_shared_calculation_current(p_tenant,p_run);
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
 PERFORM private.assert_shared_calculation_current(p_tenant,p_run);
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
  UNION ALL SELECT 'supplier_cost_orders'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.supplier_cost_orders LIMIT 100001) x
  UNION ALL SELECT 'supplier_cost_receipts'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.supplier_cost_receipts LIMIT 100001) x
  UNION ALL SELECT 'shared_cost_orders',public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.shared_cost_orders LIMIT 100001) x
  UNION ALL SELECT 'shared_cost_receipts',public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.shared_cost_receipts LIMIT 100001) x
  UNION ALL SELECT 'shared_cost_revisions',public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.shared_cost_revisions LIMIT 100001) x
  ) all_entries LIMIT 100001
 ), hashes AS (SELECT kind,encode(hash,'hex') AS h FROM entries)
 SELECT count(*),CASE WHEN count(*)<=100000 THEN encode(public.digest(convert_to('profitpilot-sensitive-recovery-v19:'||coalesce(string_agg(kind||':'||h,',' ORDER BY kind COLLATE "C",h COLLATE "C"),''),'UTF8'),'sha256'),'hex') END
 INTO total,result FROM hashes;
 IF total>100000 OR result IS NULL THEN RAISE EXCEPTION 'Sensitive recovery inventory exceeds reviewed capacity' USING ERRCODE='54000'; END IF;
 RETURN result;
END $fn$;
REVOKE ALL ON FUNCTION private.sensitive_recovery_fingerprint() FROM PUBLIC,profitpilot_app;
CREATE OR REPLACE FUNCTION private.verify_security_catalog() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT digest=private.security_catalog_digest() FROM private.security_catalog_baseline WHERE revision=75),false)
$fn$;
INSERT INTO private.security_catalog_baseline(singleton,revision,digest) VALUES(true,75,private.security_catalog_digest());
COMMIT;

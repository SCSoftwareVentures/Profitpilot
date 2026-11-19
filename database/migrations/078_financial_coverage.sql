-- Point-in-time bounded diagnostic. Never certifies completeness, grants
-- payment authority, or silently assigns tenant-wide outstanding costs.
BEGIN;
DO $check$ BEGIN IF private.verify_security_catalog() IS DISTINCT FROM true THEN RAISE EXCEPTION 'Prior catalog does not verify'; END IF; END $check$;
CREATE OR REPLACE FUNCTION private.sensitive_api_actor(
 p_tenant uuid,p_target uuid,p_action text,p_scope text,p_auth bigint,p_iat bigint,
 p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text)
RETURNS uuid LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE actor uuid; actor_role text; subject text; now_s bigint; key_bytes bytea; expected text;
BEGIN
 IF p_tenant IS NULL OR p_target IS NULL OR private.current_tenant_id() IS DISTINCT FROM p_tenant
 OR private.lock_tenant_available(p_tenant) IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'Sensitive operation denied' USING ERRCODE='42501'; END IF;
 subject:=nullif(current_setting('app.tenant_subject',true),'');
 SELECT u.id,m.role INTO actor,actor_role FROM public.users u JOIN public.tenant_memberships m ON m.user_id=u.id
 WHERE u.auth_subject=subject AND u.status='active' AND m.tenant_id=p_tenant AND m.status='active' FOR SHARE OF u,m;
 IF NOT FOUND THEN RAISE EXCEPTION 'Sensitive operation denied' USING ERRCODE='42501'; END IF;
 IF p_action IS NULL OR p_action NOT IN ('payroll_submit','payroll_read','account_read','account_correct_email','invoice_disposal_preview','privacy_case_request','privacy_case_status','privacy_case_intake','privacy_case_acknowledge','privacy_case_resolve','privacy_case_refuse','payroll_correction_preview','payroll_correction_status','privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status','privacy_key_revoke','payroll_intake_preview','payroll_intake_status','payroll_allocation_build','payroll_allocation_status','workspace_create','workspace_read','workspace_version_status','workspace_job_write','workspace_job_read','invoice_intake_preview','invoice_intake_status','supplier_cost_status','shared_cost_status','financial_coverage')
 OR (p_action IN ('privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status','privacy_key_revoke','payroll_intake_preview','payroll_intake_status','payroll_allocation_build','payroll_allocation_status','workspace_create','workspace_read','workspace_version_status','workspace_job_write','workspace_job_read','invoice_intake_preview','invoice_intake_status','supplier_cost_status','shared_cost_status','financial_coverage') AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('payroll_correction_preview','payroll_correction_status') AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('privacy_case_intake','privacy_case_acknowledge','privacy_case_resolve','privacy_case_refuse') AND actor_role NOT IN ('owner','admin'))
 OR (p_action='payroll_submit' AND actor_role NOT IN ('owner','admin','analyst'))
 OR (p_action='payroll_read' AND actor_role NOT IN ('owner','admin','reviewer'))
 OR (p_action='invoice_disposal_preview' AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('account_read','account_correct_email') AND p_target<>p_tenant)
 THEN RAISE EXCEPTION 'Sensitive operation denied' USING ERRCODE='42501'; END IF;
 now_s:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 IF p_scope IS NULL OR p_scope !~ '^[a-f0-9]{64}$'
 OR (p_action IN ('account_correct_email','privacy_case_request','privacy_case_intake','privacy_case_resolve','privacy_case_refuse','payroll_correction_preview','privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status','privacy_key_revoke','payroll_intake_preview','payroll_intake_status','payroll_allocation_build','payroll_allocation_status','workspace_create','workspace_read','workspace_version_status','workspace_job_write','workspace_job_read','invoice_intake_preview','invoice_intake_status','supplier_cost_status','shared_cost_status','financial_coverage') AND p_scope=repeat('0',64))
 OR (p_action NOT IN ('account_correct_email','privacy_case_request','privacy_case_intake','privacy_case_resolve','privacy_case_refuse','payroll_correction_preview','privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status','privacy_key_revoke','payroll_intake_preview','payroll_intake_status','payroll_allocation_build','payroll_allocation_status','workspace_create','workspace_read','workspace_version_status','workspace_job_write','workspace_job_read','invoice_intake_preview','invoice_intake_status','supplier_cost_status','shared_cost_status','financial_coverage') AND p_scope<>repeat('0',64))
 OR p_auth IS NULL OR p_auth<=0 OR p_auth<now_s-300 OR p_auth>now_s+5
 OR p_iat IS NULL OR p_iat<now_s-905 OR p_iat>now_s+5 OR p_auth>p_iat+5
 OR p_session IS NULL OR p_session !~ '^[a-f0-9]{64}$'
 OR p_expires IS NULL OR p_expires<now_s OR p_expires>now_s+30
 OR p_nonce IS NULL OR p_nonce !~ '^[a-f0-9]{32}$'
 OR p_key IS NULL OR p_key !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$'
 OR p_signature IS NULL OR p_signature !~ '^[a-f0-9]{64}$'
 THEN RAISE EXCEPTION 'Sensitive operation denied' USING ERRCODE='42501'; END IF;
 SELECT secret INTO key_bytes FROM private.tenant_context_keys WHERE key_id=p_key AND active FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Sensitive operation denied' USING ERRCODE='42501'; END IF;
 expected:=encode(public.hmac(convert_to('profitpilot-sensitive-api-v1'||E'\n'||p_tenant||E'\n'||p_target||E'\n'||p_action||E'\n'||p_scope||E'\n'||subject||E'\n'||p_auth||E'\n'||p_iat||E'\n'||p_session||E'\n'||p_expires||E'\n'||p_nonce||E'\n'||p_key,'UTF8'),key_bytes,'sha256'),'hex');
 IF expected IS DISTINCT FROM p_signature
 OR EXISTS(SELECT 1 FROM private.identity_session_cutoffs WHERE user_id=actor AND revoked_through>=p_auth)
 OR EXISTS(SELECT 1 FROM private.revoked_identity_sessions WHERE user_id=actor AND session_digest=p_session)
 THEN RAISE EXCEPTION 'Sensitive operation denied' USING ERRCODE='42501'; END IF;
 RETURN actor;
END $fn$;

CREATE FUNCTION private.api_financial_coverage(t uuid,c uuid,action text,scope text,auth bigint,iat bigint,session_digest text,expiry bigint,nonce text,key_id text,signature text,s uuid,starts date,ends date)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $fn$
DECLARE actor uuid; baseline uuid; n integer; tax text; supplier jsonb; shared jsonb; business jsonb; imports jsonb; payroll jsonb; invoices jsonb; pending jsonb; blockers jsonb:='[]'::jsonb; gaps jsonb; result jsonb;
BEGIN
 IF s IS NULL OR starts IS NULL OR ends IS NULL OR NOT isfinite(starts) OR NOT isfinite(ends) OR ends<starts OR ends-starts>366 OR action IS DISTINCT FROM 'financial_coverage'
 OR scope IS DISTINCT FROM encode(public.digest(convert_to('financial-coverage-v1'||E'\n'||s||E'\n'||starts||E'\n'||ends,'UTF8'),'sha256'),'hex') THEN RAISE EXCEPTION 'Coverage scope denied' USING ERRCODE='42501'; END IF;
 actor:=private.sensitive_api_actor(t,c,action,scope,auth,iat,session_digest,expiry,nonce,key_id,signature);
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('payroll-correction:'||t::text,0));
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('profitpilot-workspace:'||t::text,0));
 IF NOT EXISTS(SELECT 1 FROM public.contracts co JOIN public.sites si ON si.tenant_id=co.tenant_id AND si.business_id=co.business_id AND si.id=s WHERE co.tenant_id=t AND co.id=c AND private.workspace_contract_site_allowed(t,c,s))
 THEN RAISE EXCEPTION 'Coverage authority denied' USING ERRCODE='42501'; END IF;
 PERFORM private.consume_financial_access_budget(t,'payroll_summary');
 SELECT count(*)::integer,(array_agg(v.id ORDER BY v.id))[1],min(v.tax_basis) INTO n,baseline,tax FROM public.contract_versions v
 WHERE v.tenant_id=t AND v.contract_id=c AND v.approved_at IS NOT NULL AND v.approved_by IS NOT NULL AND v.effective_from<=starts AND (v.effective_to IS NULL OR v.effective_to>=ends) AND v.currency='AUD' AND v.tax_basis<>'unknown';
 IF n<>1 THEN
  result:=jsonb_build_object('format','profitpilot-financial-coverage-v1','contractId',c,'siteId',s,'periodStart',starts,'periodEnd',ends,'status','blocked','canAttemptCalculation',false,'definitiveProfitAvailable',false,'blockers',jsonb_build_array('BASELINE_REQUIRED'),'gaps',jsonb_build_array('EXTERNAL_SOURCE_COMPLETENESS_UNVERIFIED'));
 ELSE
  supplier:=private.supplier_cost_snapshot(t,c,s,starts,ends,baseline);
  shared:=private.shared_cost_calculation_snapshot(t,c,s,starts,ends,baseline);
  business:=private.business_overhead_snapshot(t,c,s,starts,ends,baseline);
  WITH b AS MATERIALIZED (
   SELECT id,source_type,status,source_period_start,source_period_end FROM public.import_batches WHERE tenant_id=t
   AND (source_period_start IS NULL OR source_period_end IS NULL OR (source_period_start<=ends AND source_period_end>=starts)) ORDER BY id LIMIT 10001
  )
  SELECT jsonb_build_object('count',count(*),'overCapacity',count(*)>10000,
   'unresolvedCount',count(*) FILTER(WHERE status IN ('registered','validating','review')),
   'failedOrRejectedCount',count(*) FILTER(WHERE status IN ('failed','rejected')),
   'unknownPeriodCount',count(*) FILTER(WHERE source_period_start IS NULL OR source_period_end IS NULL),
   'acceptedWithoutMaterializationCount',count(*) FILTER(WHERE status='accepted' AND
    ((source_type IN ('customer_invoice','supplier_invoice') AND NOT EXISTS(SELECT 1 FROM private.invoice_intake_receipts r WHERE r.tenant_id=t AND r.batch_id=b.id))
     OR (source_type='payroll' AND NOT EXISTS(SELECT 1 FROM public.payroll_pools p WHERE p.tenant_id=t AND p.batch_id=b.id))))) INTO imports FROM b;
  WITH pools AS MATERIALIZED (
   SELECT p.id,p.currency,p.period_start,p.period_end,p.total_amount FROM public.payroll_pools p
   WHERE p.tenant_id=t AND p.period_start<=ends AND p.period_end>=starts ORDER BY p.id LIMIT 10001
  ), active AS (
   SELECT p.*,r.id run_id,r.non_site_amount,r.excluded_amount,r.residual_amount FROM pools p
   LEFT JOIN public.allocation_runs r ON r.tenant_id=t AND r.payroll_pool_id=p.id AND r.status='confirmed'
   AND NOT EXISTS(SELECT 1 FROM private.payroll_supersessions x WHERE x.tenant_id=t AND x.old_run_id=r.id)
  )
  SELECT jsonb_build_object('poolCount',count(DISTINCT id),'overCapacity',count(*)>10000,
   'unconfirmedPoolCount',count(DISTINCT id) FILTER(WHERE run_id IS NULL),
   'nonAudPoolCount',count(DISTINCT id) FILTER(WHERE currency<>'AUD'),
   'partialPeriodPoolCount',count(DISTINCT id) FILTER(WHERE period_start<starts OR period_end>ends),
   'nonSiteAmountAUD',coalesce(sum(non_site_amount) FILTER(WHERE currency='AUD' AND period_start>=starts AND period_end<=ends),0)::numeric(30,2)::text,
   'excludedAmountAUD',coalesce(sum(excluded_amount) FILTER(WHERE currency='AUD' AND period_start>=starts AND period_end<=ends),0)::numeric(30,2)::text,
   'residualAmountAUD',coalesce(sum(residual_amount) FILTER(WHERE currency='AUD' AND period_start>=starts AND period_end<=ends),0)::numeric(30,2)::text,
   'unconfirmedPoolAmountAUD',coalesce(sum(total_amount) FILTER(WHERE run_id IS NULL AND currency='AUD' AND period_start>=starts AND period_end<=ends),0)::numeric(30,2)::text)
  INTO payroll FROM active;
  WITH matches AS MATERIALIZED (
   SELECT m.id,m.decision,m.service_period_start ps,m.service_period_end pe,l.amount,i.currency,i.tax_basis,k.batch_id,k.baseline_id
   FROM public.match_reviews m JOIN public.invoice_lines l ON l.tenant_id=m.tenant_id AND l.id=m.invoice_line_id
   JOIN public.invoices i ON i.tenant_id=l.tenant_id AND i.id=l.invoice_id
   LEFT JOIN private.invoice_intake_lines k ON k.tenant_id=m.tenant_id AND k.match_id=m.id AND k.line_id=l.id
   WHERE m.tenant_id=t AND m.contract_id=c AND m.site_id=s AND i.direction='customer'
   AND (m.service_period_start IS NULL OR m.service_period_end IS NULL OR (m.service_period_start<=ends AND m.service_period_end>=starts))
   ORDER BY m.id LIMIT 10001
  )
  SELECT jsonb_build_object('matchCount',count(*),'overCapacity',count(*)>10000,
   'confirmedCount',count(*) FILTER(WHERE decision='confirmed' AND ps>=starts AND pe<=ends),
   'unreviewedConfirmedCount',count(*) FILTER(WHERE decision='confirmed' AND batch_id IS NULL),
   'pendingCount',count(*) FILTER(WHERE decision IN ('candidate','held')),
   'rejectedCount',count(*) FILTER(WHERE decision='rejected'),
   'invalidConfirmedCount',count(*) FILTER(WHERE decision='confirmed' AND (ps IS NULL OR pe IS NULL OR ps<starts OR pe>ends OR currency<>'AUD' OR tax_basis IS DISTINCT FROM tax OR (baseline_id IS NOT NULL AND baseline_id<>baseline))))
  INTO invoices FROM matches;
  -- Business overhead sources are already represented in the business snapshot;
  -- pending supplier classifications below are counted tenant-wide, not charged.
  WITH candidates AS MATERIALIZED (
   SELECT k.line_id,l.amount,h.currency,q.classification FROM private.invoice_intake_lines k
   JOIN public.invoice_lines l ON l.tenant_id=k.tenant_id AND l.id=k.line_id
   JOIN public.invoices h ON h.tenant_id=k.tenant_id AND h.id=k.invoice_id
   JOIN public.match_reviews m ON m.tenant_id=k.tenant_id AND m.id=k.match_id
   LEFT JOIN private.supplier_cost_receipts r ON r.tenant_id=k.tenant_id AND r.batch_id=k.batch_id
   LEFT JOIN private.supplier_cost_orders q ON q.tenant_id=r.tenant_id AND q.order_id=r.order_id
   WHERE k.tenant_id=t AND h.direction='supplier' AND m.decision='confirmed'
   AND (m.service_period_start IS NULL OR m.service_period_end IS NULL OR (m.service_period_start<=ends AND m.service_period_end>=starts))
   ORDER BY k.line_id LIMIT 10001
  )
  SELECT jsonb_build_object('count',count(*),'overCapacity',count(*)>10000,
   'unclassifiedCount',count(*) FILTER(WHERE classification IS NULL),
   'unclassifiedAmountAUD',coalesce(sum(amount) FILTER(WHERE classification IS NULL AND currency='AUD'),0)::numeric(30,2)::text,
   'overlapOrExcludedCount',count(*) FILTER(WHERE classification IN ('payroll_overlap','excluded')))
  INTO pending FROM candidates;
  IF (invoices->>'confirmedCount')::integer=0 THEN blockers:=blockers||'"CUSTOMER_REVENUE_REQUIRED"'::jsonb; END IF;
  IF (invoices->>'invalidConfirmedCount')::integer>0 THEN blockers:=blockers||'"CUSTOMER_PERIOD_OR_BASIS_INVALID"'::jsonb; END IF;
  IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(shared->'lines') x WHERE x->>0='payroll') THEN blockers:=blockers||'"SITE_PAYROLL_REQUIRED"'::jsonb; END IF;
  IF (supplier->>'invalid')::boolean THEN blockers:=blockers||'"DIRECT_SUPPLIER_SCOPE_INVALID"'::jsonb; END IF;
  IF (shared->>'invalid')::boolean OR (shared->>'missingCount')::integer>0 THEN blockers:=blockers||'"SHARED_COST_ALLOCATION_REQUIRED"'::jsonb; END IF;
  IF (business->>'invalid')::boolean OR (business->>'missingCount')::integer>0 THEN blockers:=blockers||'"BUSINESS_OVERHEAD_ALLOCATION_REQUIRED"'::jsonb; END IF;
  IF (imports->>'overCapacity')::boolean OR (payroll->>'overCapacity')::boolean OR (invoices->>'overCapacity')::boolean OR (pending->>'overCapacity')::boolean THEN blockers:=blockers||'"DIAGNOSTIC_CAPACITY_EXCEEDED"'::jsonb; END IF;
  gaps:=jsonb_build_array('EXTERNAL_SOURCE_COMPLETENESS_UNVERIFIED','CREDITS_AND_ADJUSTMENTS_NOT_RECONCILED','TENANT_WIDE_COSTS_NOT_ATTRIBUTED');
  IF (imports->>'unresolvedCount')::integer>0 OR (imports->>'acceptedWithoutMaterializationCount')::integer>0 OR (imports->>'failedOrRejectedCount')::integer>0 OR (imports->>'unknownPeriodCount')::integer>0 THEN gaps:=gaps||'"IMPORT_RECONCILIATION_OUTSTANDING"'::jsonb; END IF;
  IF (payroll->>'unconfirmedPoolCount')::integer>0 OR (payroll->>'nonSiteAmountAUD')::numeric>0 OR (payroll->>'excludedAmountAUD')::numeric>0 OR (payroll->>'residualAmountAUD')::numeric>0 OR (payroll->>'partialPeriodPoolCount')::integer>0 OR (payroll->>'nonAudPoolCount')::integer>0 THEN gaps:=gaps||'"TENANT_PAYROLL_RECONCILIATION_OUTSTANDING"'::jsonb; END IF;
  IF (pending->>'unclassifiedCount')::integer>0 THEN gaps:=gaps||'"SUPPLIER_CLASSIFICATION_OUTSTANDING"'::jsonb; END IF;
  IF (invoices->>'pendingCount')::integer>0 OR (invoices->>'unreviewedConfirmedCount')::integer>0 OR (invoices->>'rejectedCount')::integer>0 THEN gaps:=gaps||'"INVOICE_RECONCILIATION_OUTSTANDING"'::jsonb; END IF;
  IF (shared->>'unallocatedSiteCost')::numeric>0 OR (business->>'unallocatedCost')::numeric>0 THEN gaps:=gaps||'"REVIEWED_UNALLOCATED_REMAINDER"'::jsonb; END IF;
  result:=jsonb_build_object('format','profitpilot-financial-coverage-v1','contractId',c,'siteId',s,'baselineId',baseline,'periodStart',starts,'periodEnd',ends,'status',CASE WHEN blockers='[]'::jsonb THEN 'indicative_only' ELSE 'blocked' END,'canAttemptCalculation',blockers='[]'::jsonb,'definitiveProfitAvailable',false,'blockers',blockers,'gaps',gaps,
   'scopeInvoices',invoices,'tenantImports',imports,'tenantPayroll',payroll,'tenantSupplier',pending,
   'shared',shared-'lines','businessOverhead',business-'lines'-'businessId',
   'missingSharedSources',(SELECT coalesce(jsonb_agg(jsonb_build_object('kind',x->>0,'sourceId',x->>1,'amount',x->2->>'amount')),'[]'::jsonb) FROM (SELECT x FROM jsonb_array_elements((shared->'lines')||(business->'lines')) x WHERE x->>3 IS NULL LIMIT 100) q));
 END IF;
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,metadata) VALUES(t,actor,'financial_coverage_read','contract',c,jsonb_build_object('siteId',s,'periodStart',starts,'periodEnd',ends,'status',result->>'status'));
 PERFORM private.sensitive_api_fresh(auth,expiry);
 RETURN result||jsonb_build_object('asOf',clock_timestamp(),'notice','Point-in-time diagnostic only. Tenant-wide amounts are contextual and not attributable to this contract; omitted sources and external accounting completeness remain unverified. Calculation revalidates current inputs.');
END $fn$;
REVOKE ALL ON FUNCTION private.api_financial_coverage(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text,uuid,date,date) FROM PUBLIC,profitpilot_app;
GRANT EXECUTE ON FUNCTION private.api_financial_coverage(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text,uuid,date,date) TO profitpilot_app;
CREATE OR REPLACE FUNCTION private.verify_security_catalog() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT digest=private.security_catalog_digest() FROM private.security_catalog_baseline WHERE revision=78),false)
$fn$;
INSERT INTO private.security_catalog_baseline(singleton,revision,digest) VALUES(true,78,private.security_catalog_digest());
COMMIT;

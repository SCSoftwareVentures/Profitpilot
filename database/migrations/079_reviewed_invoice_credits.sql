-- Immutable independently reviewed single-line credit adjustments.
-- Original service period management restatement only; no statutory tax
-- posting, settlement or shared overhead credit allocation.
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
 IF p_action IS NULL OR p_action NOT IN ('payroll_submit','payroll_read','account_read','account_correct_email','invoice_disposal_preview','privacy_case_request','privacy_case_status','privacy_case_intake','privacy_case_acknowledge','privacy_case_resolve','privacy_case_refuse','payroll_correction_preview','payroll_correction_status','privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status','privacy_key_revoke','payroll_intake_preview','payroll_intake_status','payroll_allocation_build','payroll_allocation_status','workspace_create','workspace_read','workspace_version_status','workspace_job_write','workspace_job_read','invoice_intake_preview','invoice_intake_status','supplier_cost_status','shared_cost_status','financial_coverage','invoice_credit_status')
 OR (p_action IN ('privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status','privacy_key_revoke','payroll_intake_preview','payroll_intake_status','payroll_allocation_build','payroll_allocation_status','workspace_create','workspace_read','workspace_version_status','workspace_job_write','workspace_job_read','invoice_intake_preview','invoice_intake_status','supplier_cost_status','shared_cost_status','financial_coverage','invoice_credit_status') AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('payroll_correction_preview','payroll_correction_status') AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('privacy_case_intake','privacy_case_acknowledge','privacy_case_resolve','privacy_case_refuse') AND actor_role NOT IN ('owner','admin'))
 OR (p_action='payroll_submit' AND actor_role NOT IN ('owner','admin','analyst'))
 OR (p_action='payroll_read' AND actor_role NOT IN ('owner','admin','reviewer'))
 OR (p_action='invoice_disposal_preview' AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('account_read','account_correct_email') AND p_target<>p_tenant)
 THEN RAISE EXCEPTION 'Sensitive operation denied' USING ERRCODE='42501'; END IF;
 now_s:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 IF p_scope IS NULL OR p_scope !~ '^[a-f0-9]{64}$'
 OR (p_action IN ('account_correct_email','privacy_case_request','privacy_case_intake','privacy_case_resolve','privacy_case_refuse','payroll_correction_preview','privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status','privacy_key_revoke','payroll_intake_preview','payroll_intake_status','payroll_allocation_build','payroll_allocation_status','workspace_create','workspace_read','workspace_version_status','workspace_job_write','workspace_job_read','invoice_intake_preview','invoice_intake_status','supplier_cost_status','shared_cost_status','financial_coverage','invoice_credit_status') AND p_scope=repeat('0',64))
 OR (p_action NOT IN ('account_correct_email','privacy_case_request','privacy_case_intake','privacy_case_resolve','privacy_case_refuse','payroll_correction_preview','privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status','privacy_key_revoke','payroll_intake_preview','payroll_intake_status','payroll_allocation_build','payroll_allocation_status','workspace_create','workspace_read','workspace_version_status','workspace_job_write','workspace_job_read','invoice_intake_preview','invoice_intake_status','supplier_cost_status','shared_cost_status','financial_coverage','invoice_credit_status') AND p_scope<>repeat('0',64))
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

CREATE TABLE private.invoice_credit_orders(
 tenant_id uuid NOT NULL,order_id uuid NOT NULL,line_id uuid NOT NULL,credit_ref_digest text NOT NULL CHECK(credit_ref_digest ~ '^[a-f0-9]{64}$' AND credit_ref_digest<>repeat('0',64)),
 amount numeric(14,2) NOT NULL CHECK(amount>0),evidence_digest text NOT NULL CHECK(evidence_digest ~ '^[a-f0-9]{64}$' AND evidence_digest<>repeat('0',64)),
 scope_digest text NOT NULL CHECK(scope_digest ~ '^[a-f0-9]{64}$'),source_snapshot jsonb NOT NULL CHECK(jsonb_typeof(source_snapshot)='object' AND octet_length(source_snapshot::text)<=4096),
 PRIMARY KEY(tenant_id,order_id),UNIQUE(tenant_id,line_id,credit_ref_digest,order_id),
 FOREIGN KEY(tenant_id,line_id) REFERENCES private.invoice_intake_lines(tenant_id,line_id),
 FOREIGN KEY(tenant_id,order_id) REFERENCES private.security_work_orders(tenant_id,id));
CREATE TABLE private.invoice_credit_receipts(
 tenant_id uuid NOT NULL,order_id uuid NOT NULL,line_id uuid NOT NULL,credit_ref_digest text NOT NULL,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,order_id),UNIQUE(tenant_id,credit_ref_digest),
 FOREIGN KEY(tenant_id,line_id,credit_ref_digest,order_id) REFERENCES private.invoice_credit_orders(tenant_id,line_id,credit_ref_digest,order_id),
 FOREIGN KEY(tenant_id,order_id) REFERENCES private.security_work_consumptions(tenant_id,order_id));
CREATE INDEX invoice_credit_receipts_line ON private.invoice_credit_receipts(tenant_id,line_id);
CREATE INDEX invoice_credit_orders_line ON private.invoice_credit_orders(tenant_id,line_id);
REVOKE ALL ON private.invoice_credit_orders,private.invoice_credit_receipts FROM PUBLIC,profitpilot_app;
CREATE TRIGGER invoice_credit_order_frozen BEFORE UPDATE OR DELETE OR TRUNCATE ON private.invoice_credit_orders FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();
CREATE TRIGGER invoice_credit_receipt_frozen BEFORE UPDATE OR DELETE OR TRUNCATE ON private.invoice_credit_receipts FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();
CREATE FUNCTION private.invoice_credit_source(t uuid,l uuid) RETURNS jsonb
LANGUAGE sql STABLE SET search_path=pg_catalog SET timezone='UTC' AS $fn$
 SELECT jsonb_build_object('lineId',k.line_id,'invoiceId',k.invoice_id,'batchId',k.batch_id,'matchId',k.match_id,'contractId',m.contract_id,'siteId',m.site_id,'baselineId',k.baseline_id,
 'direction',h.direction,'periodStart',m.service_period_start,'periodEnd',m.service_period_end,'currency',h.currency,'taxBasis',h.tax_basis,'originalAmount',i.amount::text,
 'classificationOrder',q.order_id)
 FROM private.invoice_intake_lines k JOIN public.invoice_lines i ON i.tenant_id=k.tenant_id AND i.id=k.line_id
 JOIN public.invoices h ON h.tenant_id=k.tenant_id AND h.id=k.invoice_id
 JOIN public.match_reviews m ON m.tenant_id=k.tenant_id AND m.id=k.match_id AND m.invoice_line_id=k.line_id
 LEFT JOIN private.supplier_cost_receipts r ON r.tenant_id=k.tenant_id AND r.batch_id=k.batch_id
 LEFT JOIN private.supplier_cost_orders q ON q.tenant_id=r.tenant_id AND q.order_id=r.order_id
 WHERE k.tenant_id=t AND k.line_id=l AND i.amount>0 AND m.decision='confirmed' AND m.contract_id IS NOT NULL AND m.site_id IS NOT NULL
 AND m.service_period_start IS NOT NULL AND m.service_period_end IS NOT NULL AND h.currency='AUD' AND h.tax_basis<>'unknown'
 AND (h.direction='customer' OR (h.direction='supplier' AND q.classification='direct_site'))
$fn$;
CREATE FUNCTION private.invoice_credit_summary(t uuid,l uuid,o uuid) RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE result jsonb;
BEGIN
 SELECT jsonb_build_object('orderId',q.order_id,'source',q.source_snapshot,'creditReferenceDigest',q.credit_ref_digest,'amount',q.amount::text,
 'evidenceDigest',q.evidence_digest,'scopeDigest',q.scope_digest,'status',CASE WHEN r.order_id=q.order_id THEN 'recorded' WHEN d.decision='rejected' THEN 'rejected'
 WHEN d.expires_at<=clock_timestamp() OR (d.order_id IS NULL AND w.requested_at+interval '24 hours'<=clock_timestamp()) THEN 'expired'
 WHEN d.decision='approved' THEN 'approved_pending_record' ELSE 'requested' END,'paymentAuthorized',false,'accountingTreatment','original_service_period_management_only')
 INTO result FROM private.invoice_credit_orders q JOIN private.security_work_orders w ON w.tenant_id=q.tenant_id AND w.id=q.order_id
 LEFT JOIN private.security_work_decisions d ON d.tenant_id=q.tenant_id AND d.order_id=q.order_id
 LEFT JOIN private.invoice_credit_receipts r ON r.tenant_id=q.tenant_id AND r.order_id=q.order_id WHERE q.tenant_id=t AND q.line_id=l AND q.order_id=o;
 IF result IS NULL THEN RAISE EXCEPTION 'Credit order unavailable' USING ERRCODE='42501'; END IF;RETURN result;
END $fn$;
CREATE FUNCTION private.api_invoice_credit_step(t uuid,l uuid,o uuid,ref text,amount_text text,evidence text,scope text,step text,
 auth bigint,iat bigint,session_digest text,expiry bigint,nonce text,key_id text,signature text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE actor uuid; src jsonb; q private.invoice_credit_orders%ROWTYPE; consumed numeric;
BEGIN
 actor:=private.security_work_actor(t,o,'privileged_operation',scope,step,auth,iat,session_digest,expiry,nonce,key_id,signature);
 IF l IS NULL OR ref IS NULL OR ref !~ '^[a-f0-9]{64}$' OR ref=repeat('0',64) OR evidence IS NULL OR evidence !~ '^[a-f0-9]{64}$' OR evidence=repeat('0',64)
 OR amount_text IS NULL OR amount_text !~ '^(0|[1-9][0-9]{0,11})[.][0-9]{2}$' OR amount_text='0.00'
 OR scope IS DISTINCT FROM encode(public.digest(convert_to('invoice-credit-v1'||E'\n'||l||E'\n'||ref||E'\n'||amount_text||E'\n'||evidence,'UTF8'),'sha256'),'hex')
 THEN RAISE EXCEPTION 'Credit scope denied' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('profitpilot-workspace:'||t::text,0));
 src:=private.invoice_credit_source(t,l);
 IF src IS NULL THEN RAISE EXCEPTION 'Accepted eligible invoice line unavailable' USING ERRCODE='42501'; END IF;
 IF step<>'request' THEN
  SELECT * INTO q FROM private.invoice_credit_orders WHERE tenant_id=t AND line_id=l AND order_id=o AND scope_digest=scope;
  IF NOT FOUND OR q.source_snapshot IS DISTINCT FROM src THEN RAISE EXCEPTION 'Credit source changed' USING ERRCODE='42501'; END IF;
 END IF;
 IF step<>'reject' THEN
  IF EXISTS(SELECT 1 FROM private.invoice_credit_receipts WHERE tenant_id=t AND credit_ref_digest=ref) THEN RAISE EXCEPTION 'Credit reference already recorded' USING ERRCODE='23514'; END IF;
  SELECT coalesce(sum(x.amount),0) INTO consumed FROM private.invoice_credit_receipts r JOIN private.invoice_credit_orders x ON x.tenant_id=r.tenant_id AND x.order_id=r.order_id WHERE r.tenant_id=t AND r.line_id=l;
  IF consumed+amount_text::numeric>(src->>'originalAmount')::numeric THEN RAISE EXCEPTION 'Credits exceed original line' USING ERRCODE='23514'; END IF;
 END IF;
 IF step='request' AND (SELECT count(*) FROM private.invoice_credit_orders WHERE tenant_id=t AND line_id=l)>=50 THEN RAISE EXCEPTION 'Credit review capacity reached' USING ERRCODE='54000'; END IF;
 PERFORM private.record_security_work(t,o,'privileged_operation',scope,step,auth,iat,session_digest,expiry,nonce,key_id,signature);
 IF step='request' THEN
  INSERT INTO private.invoice_credit_orders(tenant_id,order_id,line_id,credit_ref_digest,amount,evidence_digest,scope_digest,source_snapshot) VALUES(t,o,l,ref,amount_text::numeric,evidence,scope,src);
 ELSIF step='consume' THEN
  INSERT INTO private.invoice_credit_receipts(tenant_id,order_id,line_id,credit_ref_digest) VALUES(t,o,l,ref);
  INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,metadata) VALUES(t,actor,'invoice_credit_recorded','invoice_line',l,jsonb_build_object('orderId',o,'scopeDigest',scope));
 END IF;
 PERFORM private.sensitive_api_fresh(auth,expiry);RETURN private.invoice_credit_summary(t,l,o);
END $fn$;
CREATE FUNCTION private.api_invoice_credit_status(t uuid,o uuid,action text,scope text,auth bigint,iat bigint,session_digest text,expiry bigint,nonce text,key_id text,signature text,l uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE result jsonb;
BEGIN
 IF action IS DISTINCT FROM 'invoice_credit_status' OR scope IS DISTINCT FROM encode(public.digest(convert_to('invoice-credit-status-v1'||E'\n'||l,'UTF8'),'sha256'),'hex') THEN RAISE EXCEPTION 'Credit status denied' USING ERRCODE='42501'; END IF;
 PERFORM private.sensitive_api_actor(t,o,action,scope,auth,iat,session_digest,expiry,nonce,key_id,signature);
 result:=private.invoice_credit_summary(t,l,o);PERFORM private.sensitive_api_fresh(auth,expiry);RETURN result;
END $fn$;
CREATE FUNCTION private.invoice_credit_snapshot(t uuid,c uuid,s uuid,starts date,ends date,baseline uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $fn$
DECLARE result jsonb;
BEGIN
 IF private.current_tenant_id() IS DISTINCT FROM t OR c IS NULL OR s IS NULL OR starts IS NULL OR ends IS NULL OR ends<starts OR NOT isfinite(starts) OR NOT isfinite(ends)
 THEN RAISE EXCEPTION 'Credit snapshot denied' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('profitpilot-workspace:'||t::text,0));
 WITH credits AS MATERIALIZED (
 SELECT q.*,private.invoice_credit_source(t,q.line_id) actual FROM private.invoice_credit_receipts r JOIN private.invoice_credit_orders q ON q.tenant_id=r.tenant_id AND q.order_id=r.order_id
 WHERE r.tenant_id=t AND q.source_snapshot->>'contractId'=c::text AND q.source_snapshot->>'siteId'=s::text
 AND (q.source_snapshot->>'periodStart')::date<=ends AND (q.source_snapshot->>'periodEnd')::date>=starts
 ORDER BY q.order_id LIMIT 10001
 )
 SELECT jsonb_build_object('customerCredit',coalesce(sum(amount) FILTER(WHERE source_snapshot->>'direction'='customer'),0)::numeric(30,2)::text,
 'supplierCredit',coalesce(sum(amount) FILTER(WHERE source_snapshot->>'direction'='supplier'),0)::numeric(30,2)::text,
 'creditCount',count(*),'invalid',count(*)>10000 OR coalesce(bool_or(actual IS DISTINCT FROM source_snapshot OR source_snapshot->>'baselineId' IS DISTINCT FROM baseline::text
 OR (source_snapshot->>'periodStart')::date<starts OR (source_snapshot->>'periodEnd')::date>ends),false),
 'lines',coalesce(jsonb_agg(jsonb_build_array(order_id,line_id,credit_ref_digest,amount::text,evidence_digest,scope_digest,source_snapshot) ORDER BY order_id),'[]'::jsonb))
 INTO result FROM credits;RETURN result;
END $fn$;
CREATE FUNCTION private.site_invoice_credit_summary(t uuid,c uuid,s uuid,starts date,ends date,baseline uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
BEGIN
 IF coalesce(private.current_actor_role(),'') NOT IN ('owner','admin','analyst','reviewer') OR NOT private.workspace_contract_site_allowed(t,c,s) THEN RAISE EXCEPTION 'Credit summary denied' USING ERRCODE='42501'; END IF;
 RETURN private.invoice_credit_snapshot(t,c,s,starts,ends,baseline)-'lines';
END $fn$;
CREATE FUNCTION private.assert_credit_calculation_current(t uuid,r uuid) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE cr public.calculation_runs%ROWTYPE; stored jsonb; base uuid; current_credit jsonb;
BEGIN
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('profitpilot-workspace:'||t::text,0));
 SELECT * INTO cr FROM public.calculation_runs WHERE tenant_id=t AND id=r;
 SELECT source_snapshot->'credits'->'lines',baseline_id INTO stored,base FROM private.calculation_source_receipts WHERE tenant_id=t AND calculation_id=r;
 current_credit:=private.invoice_credit_snapshot(t,cr.contract_id,cr.site_id,cr.period_start,cr.period_end,base);
 IF (current_credit->>'invalid')::boolean OR current_credit->'lines' IS DISTINCT FROM coalesce(stored,'[]'::jsonb)
 THEN RAISE EXCEPTION 'Calculation requires reconciliation after invoice credit' USING ERRCODE='P4504'; END IF;
END $fn$;
REVOKE ALL ON FUNCTION private.invoice_credit_source(uuid,uuid),private.invoice_credit_summary(uuid,uuid,uuid),private.invoice_credit_snapshot(uuid,uuid,uuid,date,date,uuid),private.assert_credit_calculation_current(uuid,uuid),private.site_invoice_credit_summary(uuid,uuid,uuid,date,date,uuid),private.api_invoice_credit_step(uuid,uuid,uuid,text,text,text,text,text,bigint,bigint,text,bigint,text,text,text),private.api_invoice_credit_status(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text,uuid) FROM PUBLIC,profitpilot_app;
GRANT EXECUTE ON FUNCTION private.site_invoice_credit_summary(uuid,uuid,uuid,date,date,uuid),private.api_invoice_credit_step(uuid,uuid,uuid,text,text,text,text,text,bigint,bigint,text,bigint,text,text,text),private.api_invoice_credit_status(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text,uuid) TO profitpilot_app;

CREATE OR REPLACE FUNCTION private.capture_calculation_sources() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $fn$
DECLARE snap jsonb; baseline uuid; baselines integer; revenue numeric; cost numeric; ic integer; ac integer; reviewed integer;
 bad boolean; digest_value text; supplier jsonb; supplier_total numeric:=0; shared jsonb; business jsonb; credits jsonb;
BEGIN
 IF NEW.formula_version NOT IN ('0.2.0','0.3.0','0.4.0','0.5.0','0.6.0') THEN RETURN NEW; END IF;
 IF private.current_tenant_id() IS DISTINCT FROM NEW.tenant_id OR coalesce(private.current_actor_role(),'') NOT IN ('owner','admin','analyst','reviewer')
 OR NEW.completeness<>'incomplete' THEN RAISE EXCEPTION 'Calculation receipt authority denied' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('payroll-correction:'||NEW.tenant_id::text,0));
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('profitpilot-workspace:'||NEW.tenant_id::text,0));
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
 IF NEW.formula_version IN ('0.3.0','0.4.0','0.5.0','0.6.0') THEN
  supplier:=private.supplier_cost_snapshot(NEW.tenant_id,NEW.contract_id,NEW.site_id,NEW.period_start,NEW.period_end,baseline);
  supplier_total:=(supplier->>'directCost')::numeric;
  IF NEW.formula_version IN ('0.4.0','0.5.0','0.6.0') THEN
   shared:=private.shared_cost_calculation_snapshot(NEW.tenant_id,NEW.contract_id,NEW.site_id,NEW.period_start,NEW.period_end,baseline);
   IF (shared->>'invalid')::boolean OR (shared->>'missingCount')::integer<>0
    OR NEW.outputs->>'overheadCost' IS DISTINCT FROM shared->>'overheadCost'
    OR NEW.outputs->>'sharedSourceCount' IS DISTINCT FROM shared->>'sourceCount'
    OR NEW.outputs->>'unallocatedSharedCost' IS DISTINCT FROM shared->>'unallocatedSiteCost'
   THEN RAISE EXCEPTION 'Calculation source snapshot changed or does not reconcile' USING ERRCODE='23514'; END IF;
   cost:=(shared->>'payrollCost')::numeric;
  END IF;
  IF (supplier->>'invalid')::boolean OR NEW.outputs->>'payrollCost' IS DISTINCT FROM cost::numeric(30,2)::text
   OR NEW.outputs->>'supplierCost' IS DISTINCT FROM supplier->>'directCost'
   OR NEW.outputs->>'supplierLineCount' IS DISTINCT FROM supplier->>'directCount'
   OR NEW.outputs->>'supplierExcludedLineCount' IS DISTINCT FROM supplier->>'excludedCount'
   OR NEW.outputs->>'supplierPendingLineCount' IS DISTINCT FROM supplier->>'pendingCount'
  THEN RAISE EXCEPTION 'Calculation source snapshot changed or does not reconcile' USING ERRCODE='23514'; END IF;
  snap:=snap||jsonb_build_object('format','profitpilot-source-trace-v2','supplier',supplier,'payrollCost',cost::numeric(30,2)::text);
  cost:=cost+supplier_total;
  IF NEW.formula_version IN ('0.4.0','0.5.0','0.6.0') THEN
   snap:=snap||jsonb_build_object('format','profitpilot-source-trace-v3','shared',shared);
   cost:=cost+(shared->>'overheadCost')::numeric;
  END IF;
 END IF;
 IF NEW.formula_version IN ('0.5.0','0.6.0') THEN
  business:=private.business_overhead_snapshot(NEW.tenant_id,NEW.contract_id,NEW.site_id,NEW.period_start,NEW.period_end,baseline);
  IF (business->>'invalid')::boolean OR (business->>'missingCount')::integer<>0
   OR NEW.outputs->>'businessOverheadCost' IS DISTINCT FROM business->>'cost'
   OR NEW.outputs->>'businessOverheadSourceCount' IS DISTINCT FROM business->>'sourceCount'
   OR NEW.outputs->>'unallocatedBusinessOverhead' IS DISTINCT FROM business->>'unallocatedCost'
  THEN RAISE EXCEPTION 'Calculation source snapshot changed or does not reconcile' USING ERRCODE='23514'; END IF;
  cost:=cost+(business->>'cost')::numeric;
  snap:=snap||jsonb_build_object('format','profitpilot-source-trace-v4','businessOverhead',business);
 END IF;
 credits:=private.invoice_credit_snapshot(NEW.tenant_id,NEW.contract_id,NEW.site_id,NEW.period_start,NEW.period_end,baseline);
 IF (credits->>'invalid')::boolean OR (NEW.formula_version<>'0.6.0' AND (credits->>'creditCount')::integer>0)
 THEN RAISE EXCEPTION 'Calculation source snapshot changed or does not reconcile' USING ERRCODE='23514'; END IF;
 IF NEW.formula_version='0.6.0' THEN
  IF NEW.outputs->>'customerCredit' IS DISTINCT FROM credits->>'customerCredit' OR NEW.outputs->>'supplierCredit' IS DISTINCT FROM credits->>'supplierCredit'
  OR NEW.outputs->>'creditCount' IS DISTINCT FROM credits->>'creditCount' OR NEW.outputs->>'grossRevenue' IS DISTINCT FROM revenue::numeric(30,2)::text
  THEN RAISE EXCEPTION 'Calculation source snapshot changed or does not reconcile' USING ERRCODE='23514'; END IF;
  snap:=snap||jsonb_build_object('format','profitpilot-source-trace-v5','credits',credits,'grossRevenue',revenue::numeric(30,2)::text);
  revenue:=revenue-(credits->>'customerCredit')::numeric;
  cost:=cost-(credits->>'supplierCredit')::numeric;
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
 IF OLD.formula_version IN ('0.2.0','0.3.0','0.4.0','0.5.0','0.6.0') OR EXISTS(SELECT 1 FROM private.calculation_source_receipts WHERE calculation_id=OLD.id)
 THEN RAISE EXCEPTION 'Traced calculation is immutable' USING ERRCODE='55000'; END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;RETURN NEW;
END $fn$;
CREATE OR REPLACE FUNCTION private.calculation_trace_projection(p_tenant uuid,p_run uuid) RETURNS jsonb
LANGUAGE sql STABLE SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT jsonb_build_object('status','captured','format',source_snapshot->>'format','digest',snapshot_digest,'baselineId',baseline_id,
 'invoiceLineCount',invoice_count,'reviewedInvoiceLineCount',reviewed_invoice_count,'allocationLineCount',allocation_count,'capturedAt',captured_at)
 ||CASE WHEN source_snapshot->>'format' IN ('profitpilot-source-trace-v2','profitpilot-source-trace-v3','profitpilot-source-trace-v4','profitpilot-source-trace-v5') THEN jsonb_build_object(
 'payrollCost',source_snapshot->>'payrollCost','supplierCost',source_snapshot->'supplier'->>'directCost',
 'supplierLineCount',(source_snapshot->'supplier'->>'directCount')::integer,
 'supplierExcludedLineCount',(source_snapshot->'supplier'->>'excludedCount')::integer,
 'supplierPendingLineCount',(source_snapshot->'supplier'->>'pendingCount')::integer) ELSE '{}'::jsonb END
 ||CASE WHEN source_snapshot->>'format' IN ('profitpilot-source-trace-v3','profitpilot-source-trace-v4','profitpilot-source-trace-v5') THEN jsonb_build_object(
 'overheadCost',source_snapshot->'shared'->>'overheadCost','sharedSourceCount',(source_snapshot->'shared'->>'sourceCount')::integer,
 'unallocatedSharedCost',source_snapshot->'shared'->>'unallocatedSiteCost') ELSE '{}'::jsonb END
 ||CASE WHEN source_snapshot->>'format' IN ('profitpilot-source-trace-v4','profitpilot-source-trace-v5') THEN jsonb_build_object(
 'businessOverheadCost',source_snapshot->'businessOverhead'->>'cost',
 'businessOverheadSourceCount',(source_snapshot->'businessOverhead'->>'sourceCount')::integer,
 'unallocatedBusinessOverhead',source_snapshot->'businessOverhead'->>'unallocatedCost') ELSE '{}'::jsonb END
 ||CASE WHEN source_snapshot->>'format'='profitpilot-source-trace-v5' THEN jsonb_build_object('grossRevenue',source_snapshot->>'grossRevenue',
 'customerCredit',source_snapshot->'credits'->>'customerCredit','supplierCredit',source_snapshot->'credits'->>'supplierCredit','creditCount',(source_snapshot->'credits'->>'creditCount')::integer) ELSE '{}'::jsonb END
 FROM private.calculation_source_receipts WHERE tenant_id=p_tenant AND calculation_id=p_run),jsonb_build_object('status','legacy_unavailable'))
$fn$;
CREATE OR REPLACE FUNCTION private.assert_shared_calculation_current(t uuid,r uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog AS $fn$
BEGIN
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('profitpilot-workspace:'||t::text,0));
 IF EXISTS(SELECT 1 FROM private.calculation_source_receipts c
 CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN c.source_snapshot->>'format' IN ('profitpilot-source-trace-v3','profitpilot-source-trace-v4','profitpilot-source-trace-v5') THEN (c.source_snapshot->'shared'->'lines')||coalesce(c.source_snapshot->'businessOverhead'->'lines','[]'::jsonb) ELSE '[]'::jsonb END) l
 JOIN private.shared_cost_revisions x ON x.tenant_id=t AND x.source_kind=l->>0 AND x.source_id::text=l->>1 AND x.prior_order_id::text=l->>3
 WHERE c.tenant_id=t AND c.calculation_id=r)
 THEN RAISE EXCEPTION 'Calculation requires reconciliation after shared cost correction' USING ERRCODE='P4503'; END IF;
END $fn$;
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
 PERFORM private.assert_credit_calculation_current(p_tenant,p_run);
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
 PERFORM private.assert_credit_calculation_current(p_tenant,p_run);
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
CREATE OR REPLACE FUNCTION private.api_financial_coverage(t uuid,c uuid,action text,scope text,auth bigint,iat bigint,session_digest text,expiry bigint,nonce text,key_id text,signature text,s uuid,starts date,ends date)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $fn$
DECLARE actor uuid; baseline uuid; n integer; tax text; supplier jsonb; shared jsonb; business jsonb; credits jsonb; imports jsonb; payroll jsonb; invoices jsonb; pending jsonb; blockers jsonb:='[]'::jsonb; gaps jsonb; result jsonb;
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
  credits:=private.invoice_credit_snapshot(t,c,s,starts,ends,baseline);
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
  IF (credits->>'invalid')::boolean THEN blockers:=blockers||'"CREDIT_SCOPE_INVALID"'::jsonb; END IF;
  gaps:=jsonb_build_array('EXTERNAL_SOURCE_COMPLETENESS_UNVERIFIED','CREDITS_AND_ADJUSTMENTS_NOT_RECONCILED','TENANT_WIDE_COSTS_NOT_ATTRIBUTED');
  IF (imports->>'unresolvedCount')::integer>0 OR (imports->>'acceptedWithoutMaterializationCount')::integer>0 OR (imports->>'failedOrRejectedCount')::integer>0 OR (imports->>'unknownPeriodCount')::integer>0 THEN gaps:=gaps||'"IMPORT_RECONCILIATION_OUTSTANDING"'::jsonb; END IF;
  IF (payroll->>'unconfirmedPoolCount')::integer>0 OR (payroll->>'nonSiteAmountAUD')::numeric>0 OR (payroll->>'excludedAmountAUD')::numeric>0 OR (payroll->>'residualAmountAUD')::numeric>0 OR (payroll->>'partialPeriodPoolCount')::integer>0 OR (payroll->>'nonAudPoolCount')::integer>0 THEN gaps:=gaps||'"TENANT_PAYROLL_RECONCILIATION_OUTSTANDING"'::jsonb; END IF;
  IF (pending->>'unclassifiedCount')::integer>0 THEN gaps:=gaps||'"SUPPLIER_CLASSIFICATION_OUTSTANDING"'::jsonb; END IF;
  IF (invoices->>'pendingCount')::integer>0 OR (invoices->>'unreviewedConfirmedCount')::integer>0 OR (invoices->>'rejectedCount')::integer>0 THEN gaps:=gaps||'"INVOICE_RECONCILIATION_OUTSTANDING"'::jsonb; END IF;
  IF (shared->>'unallocatedSiteCost')::numeric>0 OR (business->>'unallocatedCost')::numeric>0 THEN gaps:=gaps||'"REVIEWED_UNALLOCATED_REMAINDER"'::jsonb; END IF;
  result:=jsonb_build_object('format','profitpilot-financial-coverage-v1','contractId',c,'siteId',s,'baselineId',baseline,'periodStart',starts,'periodEnd',ends,'status',CASE WHEN blockers='[]'::jsonb THEN 'indicative_only' ELSE 'blocked' END,'canAttemptCalculation',blockers='[]'::jsonb,'definitiveProfitAvailable',false,'blockers',blockers,'gaps',gaps,
   'scopeInvoices',invoices,'recordedCredits',credits-'lines','tenantImports',imports,'tenantPayroll',payroll,'tenantSupplier',pending,
   'shared',shared-'lines','businessOverhead',business-'lines'-'businessId',
   'missingSharedSources',(SELECT coalesce(jsonb_agg(jsonb_build_object('kind',x->>0,'sourceId',x->>1,'amount',x->2->>'amount')),'[]'::jsonb) FROM (SELECT x FROM jsonb_array_elements((shared->'lines')||(business->'lines')) x WHERE x->>3 IS NULL LIMIT 100) q));
 END IF;
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,metadata) VALUES(t,actor,'financial_coverage_read','contract',c,jsonb_build_object('siteId',s,'periodStart',starts,'periodEnd',ends,'status',result->>'status'));
 PERFORM private.sensitive_api_fresh(auth,expiry);
 RETURN result||jsonb_build_object('asOf',clock_timestamp(),'notice','Point-in-time diagnostic only. Tenant-wide amounts are contextual and not attributable to this contract; omitted sources and external accounting completeness remain unverified. Calculation revalidates current inputs.');
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
  UNION ALL SELECT 'invoice_credit_orders',public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.invoice_credit_orders LIMIT 100001) x
  UNION ALL SELECT 'invoice_credit_receipts',public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.invoice_credit_receipts LIMIT 100001) x
  ) all_entries LIMIT 100001
 ), hashes AS (SELECT kind,encode(hash,'hex') AS h FROM entries)
 SELECT count(*),CASE WHEN count(*)<=100000 THEN encode(public.digest(convert_to('profitpilot-sensitive-recovery-v20:'||coalesce(string_agg(kind||':'||h,',' ORDER BY kind COLLATE "C",h COLLATE "C"),''),'UTF8'),'sha256'),'hex') END
 INTO total,result FROM hashes;
 IF total>100000 OR result IS NULL THEN RAISE EXCEPTION 'Sensitive recovery inventory exceeds reviewed capacity' USING ERRCODE='54000'; END IF;
 RETURN result;
END $fn$;
REVOKE ALL ON FUNCTION private.sensitive_recovery_fingerprint() FROM PUBLIC,profitpilot_app;
CREATE OR REPLACE FUNCTION private.verify_security_catalog() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT digest=private.security_catalog_digest() FROM private.security_catalog_baseline WHERE revision=79),false)
$fn$;
INSERT INTO private.security_catalog_baseline(singleton,revision,digest) VALUES(true,79,private.security_catalog_digest());
COMMIT;

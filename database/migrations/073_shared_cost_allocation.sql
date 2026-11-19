-- Exact source-line allocation of site payroll or reviewed supplier overhead.
-- Receipts are preparatory; no existing calculation automatically includes them.
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
 IF p_action IS NULL OR p_action NOT IN ('payroll_submit','payroll_read','account_read','account_correct_email','invoice_disposal_preview','privacy_case_request','privacy_case_status','privacy_case_intake','privacy_case_acknowledge','privacy_case_resolve','privacy_case_refuse','payroll_correction_preview','payroll_correction_status','privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status','privacy_key_revoke','payroll_intake_preview','payroll_intake_status','payroll_allocation_build','payroll_allocation_status','workspace_create','workspace_read','workspace_version_status','workspace_job_write','workspace_job_read','invoice_intake_preview','invoice_intake_status','supplier_cost_status','shared_cost_status')
 OR (p_action IN ('privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status','privacy_key_revoke','payroll_intake_preview','payroll_intake_status','payroll_allocation_build','payroll_allocation_status','workspace_create','workspace_read','workspace_version_status','workspace_job_write','workspace_job_read','invoice_intake_preview','invoice_intake_status','supplier_cost_status','shared_cost_status') AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('payroll_correction_preview','payroll_correction_status') AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('privacy_case_intake','privacy_case_acknowledge','privacy_case_resolve','privacy_case_refuse') AND actor_role NOT IN ('owner','admin'))
 OR (p_action='payroll_submit' AND actor_role NOT IN ('owner','admin','analyst'))
 OR (p_action='payroll_read' AND actor_role NOT IN ('owner','admin','reviewer'))
 OR (p_action='invoice_disposal_preview' AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('account_read','account_correct_email') AND p_target<>p_tenant)
 THEN RAISE EXCEPTION 'Sensitive operation denied' USING ERRCODE='42501'; END IF;
 now_s:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 IF p_scope IS NULL OR p_scope !~ '^[a-f0-9]{64}$'
 OR (p_action IN ('account_correct_email','privacy_case_request','privacy_case_intake','privacy_case_resolve','privacy_case_refuse','payroll_correction_preview','privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status','privacy_key_revoke','payroll_intake_preview','payroll_intake_status','payroll_allocation_build','payroll_allocation_status','workspace_create','workspace_read','workspace_version_status','workspace_job_write','workspace_job_read','invoice_intake_preview','invoice_intake_status','supplier_cost_status','shared_cost_status') AND p_scope=repeat('0',64))
 OR (p_action NOT IN ('account_correct_email','privacy_case_request','privacy_case_intake','privacy_case_resolve','privacy_case_refuse','payroll_correction_preview','privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status','privacy_key_revoke','payroll_intake_preview','payroll_intake_status','payroll_allocation_build','payroll_allocation_status','workspace_create','workspace_read','workspace_version_status','workspace_job_write','workspace_job_read','invoice_intake_preview','invoice_intake_status','supplier_cost_status','shared_cost_status') AND p_scope<>repeat('0',64))
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

CREATE TABLE private.shared_cost_orders(
 tenant_id uuid NOT NULL,order_id uuid NOT NULL,source_kind text NOT NULL CHECK(source_kind IN ('payroll','overhead')),
 source_id uuid NOT NULL,source_snapshot jsonb NOT NULL CHECK(octet_length(source_snapshot::text)<=4096),
 shares jsonb NOT NULL CHECK(jsonb_typeof(shares)='array' AND jsonb_array_length(shares) BETWEEN 1 AND 100 AND octet_length(shares::text)<=24000),
 evidence_digest text NOT NULL CHECK(evidence_digest ~ '^[a-f0-9]{64}$' AND evidence_digest<>repeat('0',64)),
 scope_digest text NOT NULL CHECK(scope_digest ~ '^[a-f0-9]{64}$'),
 PRIMARY KEY(tenant_id,order_id),UNIQUE(tenant_id,source_kind,source_id,order_id),
 FOREIGN KEY(tenant_id,order_id) REFERENCES private.security_work_orders(tenant_id,id)
);
CREATE TABLE private.shared_cost_receipts(
 tenant_id uuid NOT NULL,source_kind text NOT NULL,source_id uuid NOT NULL,order_id uuid NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,source_kind,source_id),UNIQUE(tenant_id,order_id),
 FOREIGN KEY(tenant_id,source_kind,source_id,order_id) REFERENCES private.shared_cost_orders(tenant_id,source_kind,source_id,order_id),
 FOREIGN KEY(tenant_id,order_id) REFERENCES private.security_work_consumptions(tenant_id,order_id)
);
REVOKE ALL ON private.shared_cost_orders,private.shared_cost_receipts FROM PUBLIC,profitpilot_app;
CREATE TRIGGER shared_cost_order_frozen BEFORE UPDATE OR DELETE OR TRUNCATE ON private.shared_cost_orders FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();
CREATE TRIGGER shared_cost_receipt_frozen BEFORE UPDATE OR DELETE OR TRUNCATE ON private.shared_cost_receipts FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();
CREATE FUNCTION private.shared_cost_source(p_tenant uuid,p_kind text,p_source uuid) RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog SET timezone='UTC' AS $fn$
DECLARE result jsonb;
BEGIN
 IF p_kind='payroll' THEN
  SELECT jsonb_build_object('kind','payroll','sourceId',a.id,'siteId',a.site_id,'runId',r.id,'periodStart',p.period_start,'periodEnd',p.period_end,'amount',a.amount::text,'currency',p.currency,'evidenceDigest',cr.evidence_digest)
  INTO result FROM public.allocation_lines a
  JOIN public.allocation_runs r ON r.tenant_id=a.tenant_id AND r.id=a.allocation_run_id
  JOIN public.payroll_pools p ON p.tenant_id=r.tenant_id AND p.id=r.payroll_pool_id
  JOIN private.payroll_confirmation_receipts cr ON cr.tenant_id=r.tenant_id AND cr.allocation_run_id=r.id
  WHERE a.tenant_id=p_tenant AND a.id=p_source AND a.site_id IS NOT NULL AND a.amount>0 AND a.bucket_type IN ('direct','approved_allocated')
  AND r.status='confirmed' AND p.currency='AUD' AND NOT EXISTS(SELECT 1 FROM private.payroll_supersessions x WHERE x.tenant_id=r.tenant_id AND x.old_run_id=r.id);
 ELSIF p_kind='overhead' THEN
  SELECT jsonb_build_object('kind','overhead','sourceId',l.id,'siteId',m.site_id,'batchId',k.batch_id,'classificationOrder',q.order_id,'periodStart',m.service_period_start,'periodEnd',m.service_period_end,'amount',l.amount::text,'currency',h.currency,'taxBasis',h.tax_basis,'evidenceDigest',q.evidence_digest)
  INTO result FROM private.invoice_intake_lines k JOIN public.invoice_lines l ON l.tenant_id=k.tenant_id AND l.id=k.line_id
  JOIN public.invoices h ON h.tenant_id=l.tenant_id AND h.id=l.invoice_id
  JOIN public.match_reviews m ON m.tenant_id=k.tenant_id AND m.id=k.match_id AND m.invoice_line_id=l.id
  JOIN private.supplier_cost_receipts r ON r.tenant_id=k.tenant_id AND r.batch_id=k.batch_id
  JOIN private.supplier_cost_orders q ON q.tenant_id=r.tenant_id AND q.batch_id=r.batch_id AND q.order_id=r.order_id
  WHERE k.tenant_id=p_tenant AND k.line_id=p_source AND q.classification='overhead_pending' AND h.direction='supplier'
  AND m.decision='confirmed' AND m.site_id IS NOT NULL AND m.service_period_start IS NOT NULL AND m.service_period_end IS NOT NULL
  AND l.amount>0 AND h.currency='AUD' AND h.tax_basis<>'unknown';
 END IF;
 RETURN result;
END $fn$;
CREATE FUNCTION private.shared_cost_summary(p_tenant uuid,p_kind text,p_source uuid,p_order uuid) RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE result jsonb;
BEGIN
 SELECT jsonb_build_object('source',q.source_snapshot,'shares',q.shares,'orderId',q.order_id,'scopeDigest',q.scope_digest,'evidenceDigest',q.evidence_digest,
 'sourceActive',private.shared_cost_source(p_tenant,p_kind,p_source) IS NOT DISTINCT FROM q.source_snapshot,
 'status',CASE WHEN r.order_id=q.order_id THEN 'allocated' WHEN r.order_id IS NOT NULL THEN 'superseded'
 WHEN d.decision='rejected' THEN 'rejected' WHEN d.expires_at<=clock_timestamp() OR (d.order_id IS NULL AND w.requested_at+interval '24 hours'<=clock_timestamp()) THEN 'expired'
 WHEN d.decision='approved' THEN 'approved_pending_record' ELSE 'requested' END,'includedInCalculation',false,'paymentAuthorized',false)
 INTO result FROM private.shared_cost_orders q JOIN private.security_work_orders w ON w.tenant_id=q.tenant_id AND w.id=q.order_id
 LEFT JOIN private.security_work_decisions d ON d.tenant_id=q.tenant_id AND d.order_id=q.order_id
 LEFT JOIN private.shared_cost_receipts r ON r.tenant_id=q.tenant_id AND r.source_kind=q.source_kind AND r.source_id=q.source_id
 WHERE q.tenant_id=p_tenant AND q.source_kind=p_kind AND q.source_id=p_source AND q.order_id=p_order;
 IF result IS NULL THEN RAISE EXCEPTION 'Shared allocation unavailable' USING ERRCODE='42501'; END IF;RETURN result;
END $fn$;
CREATE FUNCTION private.api_shared_cost_step(p_tenant uuid,p_kind text,p_source uuid,p_order uuid,p_shares jsonb,p_evidence text,p_scope text,p_step text,
 p_auth bigint,p_iat bigint,p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $fn$
DECLARE actor uuid; src jsonb; existing private.shared_cost_orders%ROWTYPE; item jsonb; target text; baseline text; amount text; prev text:=''; total numeric:=0; canonical text;
BEGIN
 actor:=private.security_work_actor(p_tenant,p_order,'privileged_operation',p_scope,p_step,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 IF p_kind IS NULL OR p_kind NOT IN ('payroll','overhead') OR p_source IS NULL OR p_evidence IS NULL OR p_evidence !~ '^[a-f0-9]{64}$' OR p_evidence=repeat('0',64)
 OR jsonb_typeof(p_shares) IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'Shared scope denied' USING ERRCODE='42501'; END IF;
 IF jsonb_array_length(p_shares) NOT BETWEEN 1 AND 100 OR octet_length(p_shares::text)>24000 THEN RAISE EXCEPTION 'Shared allocation capacity' USING ERRCODE='54000'; END IF;
 -- Same lock order as calculations: payroll correction then workspace.
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('payroll-correction:'||p_tenant::text,0));
 PERFORM pg_advisory_xact_lock(hashtextextended('profitpilot-workspace:'||p_tenant::text,0));
 src:=private.shared_cost_source(p_tenant,p_kind,p_source);
 IF src IS NULL THEN RAISE EXCEPTION 'Active reviewed source unavailable' USING ERRCODE='42501'; END IF;
 canonical:='shared-cost-v1'||E'\n'||p_kind||E'\n'||p_source||E'\n'||p_evidence;
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
  IF NOT FOUND OR existing.source_snapshot IS DISTINCT FROM src THEN RAISE EXCEPTION 'Reviewed source changed' USING ERRCODE='42501'; END IF;
 END IF;
 IF p_step<>'reject' AND EXISTS(SELECT 1 FROM private.shared_cost_receipts WHERE tenant_id=p_tenant AND source_kind=p_kind AND source_id=p_source)
 THEN RAISE EXCEPTION 'Source already allocated' USING ERRCODE='23514'; END IF;
 IF p_step='request' AND (SELECT count(*) FROM private.shared_cost_orders WHERE tenant_id=p_tenant AND source_kind=p_kind AND source_id=p_source)>=20 THEN RAISE EXCEPTION 'Review capacity reached' USING ERRCODE='54000'; END IF;
 PERFORM private.record_security_work(p_tenant,p_order,'privileged_operation',p_scope,p_step,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 IF p_step='request' THEN
  INSERT INTO private.shared_cost_orders(tenant_id,order_id,source_kind,source_id,source_snapshot,shares,evidence_digest,scope_digest)
  VALUES(p_tenant,p_order,p_kind,p_source,src,p_shares,p_evidence,p_scope);
 ELSIF p_step='consume' THEN
  INSERT INTO private.shared_cost_receipts(tenant_id,source_kind,source_id,order_id) VALUES(p_tenant,p_kind,p_source,p_order);
  INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,metadata)
  VALUES(p_tenant,actor,'shared_cost_allocated','shared_cost_source',p_source,jsonb_build_object('kind',p_kind,'scopeDigest',p_scope,'orderId',p_order));
 END IF;
 PERFORM private.sensitive_api_fresh(p_auth,p_expires);
 RETURN private.shared_cost_summary(p_tenant,p_kind,p_source,p_order);
END $fn$;
CREATE FUNCTION private.api_shared_cost_status(p_tenant uuid,p_order uuid,p_action text,p_scope text,p_auth bigint,p_iat bigint,p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text,p_kind text,p_source uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE result jsonb;
BEGIN
 IF p_kind IS NULL OR p_kind NOT IN ('payroll','overhead') OR p_action IS DISTINCT FROM 'shared_cost_status'
 OR p_scope IS DISTINCT FROM encode(public.digest(convert_to('shared-cost-status-v1'||E'\n'||p_kind||E'\n'||p_source,'UTF8'),'sha256'),'hex') THEN RAISE EXCEPTION 'Shared status denied' USING ERRCODE='42501'; END IF;
 PERFORM private.sensitive_api_actor(p_tenant,p_order,p_action,p_scope,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 result:=private.shared_cost_summary(p_tenant,p_kind,p_source,p_order);
 PERFORM private.sensitive_api_fresh(p_auth,p_expires);RETURN result;
END $fn$;
REVOKE ALL ON FUNCTION private.shared_cost_source(uuid,text,uuid),private.shared_cost_summary(uuid,text,uuid,uuid),private.api_shared_cost_step(uuid,text,uuid,uuid,jsonb,text,text,text,bigint,bigint,text,bigint,text,text,text),private.api_shared_cost_status(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text,text,uuid) FROM PUBLIC,profitpilot_app;
GRANT EXECUTE ON FUNCTION private.api_shared_cost_step(uuid,text,uuid,uuid,jsonb,text,text,text,bigint,bigint,text,bigint,text,text,text),private.api_shared_cost_status(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text,text,uuid) TO profitpilot_app;

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
  ) all_entries LIMIT 100001
 ), hashes AS (SELECT kind,encode(hash,'hex') AS h FROM entries)
 SELECT count(*),CASE WHEN count(*)<=100000 THEN encode(public.digest(convert_to('profitpilot-sensitive-recovery-v18:'||coalesce(string_agg(kind||':'||h,',' ORDER BY kind COLLATE "C",h COLLATE "C"),''),'UTF8'),'sha256'),'hex') END
 INTO total,result FROM hashes;
 IF total>100000 OR result IS NULL THEN RAISE EXCEPTION 'Sensitive recovery inventory exceeds reviewed capacity' USING ERRCODE='54000'; END IF;
 RETURN result;
END $fn$;
REVOKE ALL ON FUNCTION private.sensitive_recovery_fingerprint() FROM PUBLIC,profitpilot_app;
CREATE OR REPLACE FUNCTION private.verify_security_catalog() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT digest=private.security_catalog_digest() FROM private.security_catalog_baseline WHERE revision=73),false)
$fn$;
INSERT INTO private.security_catalog_baseline(singleton,revision,digest) VALUES(true,73,private.security_catalog_digest());
COMMIT;

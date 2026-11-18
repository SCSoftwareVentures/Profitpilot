-- Expose exact scoped payroll correction capabilities, never general ledger access.
BEGIN;
DO $check$ BEGIN
 IF private.verify_security_catalog() IS DISTINCT FROM true THEN RAISE EXCEPTION 'Prior security catalog does not verify'; END IF;
END $check$;
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
 IF p_action IS NULL OR p_action NOT IN ('payroll_submit','payroll_read','account_read','account_correct_email','invoice_disposal_preview','privacy_case_request','privacy_case_status','privacy_case_intake','privacy_case_acknowledge','privacy_case_resolve','privacy_case_refuse','payroll_correction_preview','payroll_correction_status')
 OR (p_action IN ('payroll_correction_preview','payroll_correction_status') AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('privacy_case_intake','privacy_case_acknowledge','privacy_case_resolve','privacy_case_refuse') AND actor_role NOT IN ('owner','admin'))
 OR (p_action='payroll_submit' AND actor_role NOT IN ('owner','admin','analyst'))
 OR (p_action='payroll_read' AND actor_role NOT IN ('owner','admin','reviewer'))
 OR (p_action='invoice_disposal_preview' AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('account_read','account_correct_email') AND p_target<>p_tenant)
 THEN RAISE EXCEPTION 'Sensitive operation denied' USING ERRCODE='42501'; END IF;
 now_s:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 IF p_scope IS NULL OR p_scope !~ '^[a-f0-9]{64}$'
 OR (p_action IN ('account_correct_email','privacy_case_request','privacy_case_intake','privacy_case_resolve','privacy_case_refuse','payroll_correction_preview') AND p_scope=repeat('0',64))
 OR (p_action NOT IN ('account_correct_email','privacy_case_request','privacy_case_intake','privacy_case_resolve','privacy_case_refuse','payroll_correction_preview') AND p_scope<>repeat('0',64))
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


CREATE FUNCTION private.api_payroll_correction_preview(
 p_tenant uuid,p_old uuid,p_action text,p_scope text,p_auth bigint,p_iat bigint,p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text,
 p_proposal uuid,p_reason text,p_evidence text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE actor uuid; scope_hash text; summary jsonb; old_total text;
BEGIN
 IF p_action IS DISTINCT FROM 'payroll_correction_preview' OR p_proposal IS NULL OR p_reason IS NULL
 OR p_reason NOT IN ('allocation_error','source_correction','duplicate_source','privacy_correction')
 OR p_evidence IS NULL OR p_evidence !~ '^[a-f0-9]{64}$' OR p_evidence=repeat('0',64)
 OR p_scope IS DISTINCT FROM encode(public.digest(convert_to('payroll-correction-preview-v1'||E'\n'||p_old||E'\n'||p_proposal||E'\n'||p_reason||E'\n'||p_evidence,'UTF8'),'sha256'),'hex')
 THEN RAISE EXCEPTION 'Correction preview denied' USING ERRCODE='42501'; END IF;
 actor:=private.sensitive_api_actor(p_tenant,p_old,p_action,p_scope,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('payroll-correction:'||p_tenant::text,0));
 scope_hash:=private.payroll_correction_scope(p_tenant,p_old,p_proposal,p_reason,p_evidence);
 PERFORM private.consume_financial_access_budget(p_tenant,'payroll_summary');
 summary:=private.payroll_api_summary(p_tenant,p_proposal);
 SELECT p.total_amount::text INTO old_total FROM public.allocation_runs r JOIN public.payroll_pools p ON p.tenant_id=r.tenant_id AND p.id=r.payroll_pool_id WHERE r.tenant_id=p_tenant AND r.id=p_old;
 PERFORM private.sensitive_api_fresh(p_auth,p_expires);
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id)
 VALUES(p_tenant,actor,'payroll_correction_previewed','allocation_run',p_old);
 RETURN jsonb_build_object('oldRunId',p_old,'oldTotal',old_total,'proposalId',p_proposal,'proposalDigest',summary->>'evidenceDigest','replacementTotal',summary->>'total','currency',summary->>'currency','periodStart',summary->>'periodStart','periodEnd',summary->>'periodEnd','scopeDigest',scope_hash);
END $fn$;

CREATE FUNCTION private.correction_order_summary(p_tenant uuid,p_order uuid)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE result jsonb;
BEGIN
 SELECT jsonb_build_object('orderId',q.order_id,'oldRunId',q.old_run_id,'replacementRunId',q.new_run_id,'proposalId',q.proposal_id,'proposalDigest',p.evidence_digest,'reason',q.reason_code,'scopeDigest',q.scope_digest,'authorityEvidenceDigest',q.evidence_digest,
 'status',CASE WHEN s.order_id IS NOT NULL THEN 'executed' WHEN d.decision='rejected' THEN 'rejected' WHEN d.expires_at<=clock_timestamp() OR (d.order_id IS NULL AND w.requested_at+interval '24 hours'<=clock_timestamp()) THEN 'expired' WHEN d.decision='approved' THEN 'approved' ELSE 'requested' END,'approvalExpiresAt',d.expires_at)
 INTO result FROM private.payroll_correction_reservations q JOIN private.security_work_orders w ON w.tenant_id=q.tenant_id AND w.id=q.order_id JOIN private.payroll_proposal_reviews p ON p.tenant_id=q.tenant_id AND p.id=q.proposal_id
 LEFT JOIN private.security_work_decisions d ON d.tenant_id=q.tenant_id AND d.order_id=q.order_id LEFT JOIN private.payroll_supersessions s ON s.tenant_id=q.tenant_id AND s.order_id=q.order_id
 WHERE q.tenant_id=p_tenant AND q.order_id=p_order;
 IF result IS NULL THEN RAISE EXCEPTION 'Correction order unavailable' USING ERRCODE='42501'; END IF;
 RETURN result;
END $fn$;

CREATE FUNCTION private.api_payroll_correction_status(
 p_tenant uuid,p_order uuid,p_action text,p_scope text,p_auth bigint,p_iat bigint,p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE actor uuid; result jsonb;
BEGIN
 IF p_action IS DISTINCT FROM 'payroll_correction_status' THEN RAISE EXCEPTION 'Correction status denied' USING ERRCODE='42501'; END IF;
 actor:=private.sensitive_api_actor(p_tenant,p_order,p_action,p_scope,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 result:=private.correction_order_summary(p_tenant,p_order);
 PERFORM private.sensitive_api_fresh(p_auth,p_expires);
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id) VALUES(p_tenant,actor,'payroll_correction_status_read','security_work_order',p_order);
 RETURN result;
END $fn$;

CREATE FUNCTION private.api_payroll_correction_step(
 p_tenant uuid,p_order uuid,p_old uuid,p_proposal uuid,p_reason text,p_evidence text,p_scope text,p_step text,
 p_auth bigint,p_iat bigint,p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text,p_confirm_nonce text,p_confirm_signature text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE actor uuid; submitter uuid; q private.payroll_correction_reservations%ROWTYPE;
BEGIN
 IF p_step IS NULL OR p_step NOT IN ('request','approve','reject','consume') OR
 (p_step='consume' AND (p_confirm_nonce IS NULL OR p_confirm_signature IS NULL)) OR
 (p_step<>'consume' AND (p_confirm_nonce IS NOT NULL OR p_confirm_signature IS NOT NULL))
 THEN RAISE EXCEPTION 'Correction step denied' USING ERRCODE='42501'; END IF;
 actor:=private.security_work_actor(p_tenant,p_order,'privileged_operation',p_scope,p_step,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 PERFORM pg_advisory_xact_lock(hashtextextended('payroll-correction:'||p_tenant::text,0));
 SELECT submitted_by INTO submitter FROM private.payroll_proposal_reviews WHERE tenant_id=p_tenant AND id=p_proposal;
 IF NOT FOUND OR actor=submitter THEN RAISE EXCEPTION 'Independent correction authority required' USING ERRCODE='42501'; END IF;
 IF p_step='request' THEN
  PERFORM private.request_payroll_correction(p_tenant,p_order,p_old,p_proposal,p_reason,p_evidence,p_scope,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 ELSE
  SELECT * INTO q FROM private.payroll_correction_reservations WHERE tenant_id=p_tenant AND order_id=p_order FOR UPDATE;
  IF NOT FOUND OR ROW(q.old_run_id,q.proposal_id,q.reason_code,q.evidence_digest,q.scope_digest) IS DISTINCT FROM ROW(p_old,p_proposal,p_reason,p_evidence,p_scope)
  THEN RAISE EXCEPTION 'Correction order unavailable' USING ERRCODE='42501'; END IF;
  IF p_step='consume' THEN
   PERFORM private.execute_payroll_correction(p_tenant,p_order,p_scope,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature,p_confirm_nonce,p_confirm_signature);
  ELSE
   IF private.payroll_correction_scope(p_tenant,p_old,p_proposal,p_reason,p_evidence) IS DISTINCT FROM p_scope THEN RAISE EXCEPTION 'Correction scope changed' USING ERRCODE='42501'; END IF;
   PERFORM private.record_security_work(p_tenant,p_order,'privileged_operation',p_scope,p_step,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
  END IF;
 END IF;
 PERFORM private.sensitive_api_fresh(p_auth,p_expires);
 RETURN private.correction_order_summary(p_tenant,p_order);
END $fn$;
REVOKE ALL ON FUNCTION private.api_payroll_correction_preview(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text,uuid,text,text),
 private.correction_order_summary(uuid,uuid),private.api_payroll_correction_status(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text),
 private.api_payroll_correction_step(uuid,uuid,uuid,uuid,text,text,text,text,bigint,bigint,text,bigint,text,text,text,text,text) FROM PUBLIC,profitpilot_app;
GRANT EXECUTE ON FUNCTION private.api_payroll_correction_preview(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text,uuid,text,text),
 private.api_payroll_correction_status(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text),
 private.api_payroll_correction_step(uuid,uuid,uuid,uuid,text,text,text,text,bigint,bigint,text,bigint,text,text,text,text,text) TO profitpilot_app;
CREATE OR REPLACE FUNCTION private.verify_security_catalog()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT digest=private.security_catalog_digest() FROM private.security_catalog_baseline WHERE revision=52),false)
$fn$;
INSERT INTO private.security_catalog_baseline(singleton,revision,digest) VALUES(true,52,private.security_catalog_digest());
COMMIT;

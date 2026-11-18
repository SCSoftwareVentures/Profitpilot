-- Narrow staffed receipt evidence capability. No live delivery or proof of identity.
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
 IF p_action IS NULL OR p_action NOT IN ('payroll_submit','payroll_read','account_read','account_correct_email','invoice_disposal_preview','privacy_case_request','privacy_case_status','privacy_case_intake','privacy_case_acknowledge','privacy_case_resolve','privacy_case_refuse','payroll_correction_preview','payroll_correction_status','privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status')
 OR (p_action IN ('privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status') AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('payroll_correction_preview','payroll_correction_status') AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('privacy_case_intake','privacy_case_acknowledge','privacy_case_resolve','privacy_case_refuse') AND actor_role NOT IN ('owner','admin'))
 OR (p_action='payroll_submit' AND actor_role NOT IN ('owner','admin','analyst'))
 OR (p_action='payroll_read' AND actor_role NOT IN ('owner','admin','reviewer'))
 OR (p_action='invoice_disposal_preview' AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('account_read','account_correct_email') AND p_target<>p_tenant)
 THEN RAISE EXCEPTION 'Sensitive operation denied' USING ERRCODE='42501'; END IF;
 now_s:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 IF p_scope IS NULL OR p_scope !~ '^[a-f0-9]{64}$'
 OR (p_action IN ('account_correct_email','privacy_case_request','privacy_case_intake','privacy_case_resolve','privacy_case_refuse','payroll_correction_preview','privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status') AND p_scope=repeat('0',64))
 OR (p_action NOT IN ('account_correct_email','privacy_case_request','privacy_case_intake','privacy_case_resolve','privacy_case_refuse','payroll_correction_preview','privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status') AND p_scope<>repeat('0',64))
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




CREATE TABLE private.privacy_receipt_requests(
 tenant_id uuid NOT NULL,case_id uuid NOT NULL,release_order_id uuid NOT NULL,review_order_id uuid NOT NULL,
 scope_digest text NOT NULL CHECK(scope_digest ~ '^[a-f0-9]{64}$' AND scope_digest<>repeat('0',64)),
 PRIMARY KEY(tenant_id,review_order_id),
 FOREIGN KEY(tenant_id,case_id) REFERENCES private.privacy_rights_cases(tenant_id,id),
 FOREIGN KEY(tenant_id,release_order_id) REFERENCES private.privacy_delivery_authorizations(tenant_id,order_id),
 FOREIGN KEY(tenant_id,review_order_id) REFERENCES private.security_work_orders(tenant_id,id),
 CHECK(release_order_id<>review_order_id)
);
REVOKE ALL ON private.privacy_receipt_requests FROM PUBLIC,profitpilot_app;
CREATE TRIGGER privacy_receipt_requests_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON private.privacy_receipt_requests
 FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();

CREATE FUNCTION private.privacy_receipt_order_summary(p_tenant uuid,p_case uuid,p_release uuid,p_review uuid)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE result jsonb;
BEGIN
 SELECT jsonb_build_object('caseId',q.case_id,'releaseOrderId',q.release_order_id,'reviewOrderId',q.review_order_id,'scopeDigest',q.scope_digest,
 'status',CASE WHEN e.review_order_id IS NOT NULL THEN 'evidence-recorded' WHEN d.decision='rejected' THEN 'rejected'
 WHEN other_e.release_order_id IS NOT NULL THEN 'superseded' WHEN d.expires_at<=clock_timestamp() OR (d.order_id IS NULL AND w.requested_at+interval '24 hours'<=clock_timestamp()) THEN 'expired'
 WHEN d.decision='approved' THEN 'approved' ELSE 'requested' END,
 'receiptEvidenceRecorded',e.review_order_id IS NOT NULL,'recordedAt',e.recorded_at,'deliveryVerified',false)
 INTO result FROM private.privacy_receipt_requests q
 JOIN private.security_work_orders w ON w.tenant_id=q.tenant_id AND w.id=q.review_order_id
 LEFT JOIN private.security_work_decisions d ON d.tenant_id=q.tenant_id AND d.order_id=q.review_order_id
 LEFT JOIN private.privacy_receipt_evidence e ON e.tenant_id=q.tenant_id AND e.review_order_id=q.review_order_id AND e.release_order_id=q.release_order_id AND e.case_id=q.case_id
 LEFT JOIN private.privacy_receipt_evidence other_e ON other_e.tenant_id=q.tenant_id AND other_e.release_order_id=q.release_order_id AND other_e.case_id=q.case_id
 WHERE q.tenant_id=p_tenant AND q.case_id=p_case AND q.release_order_id=p_release AND q.review_order_id=p_review;
 IF result IS NULL THEN RAISE EXCEPTION 'Receipt review unavailable' USING ERRCODE='42501'; END IF;
 RETURN result;
END $fn$;

CREATE FUNCTION private.api_privacy_receipt_preview(
 p_tenant uuid,p_review uuid,p_action text,p_scope text,p_auth bigint,p_iat bigint,p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text,
 p_case uuid,p_release uuid,p_challenge text,p_receipt text,p_signer text,p_evidence text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE actor uuid; scope_hash text;
BEGIN
 IF p_action IS DISTINCT FROM 'privacy_receipt_preview' OR p_scope IS DISTINCT FROM encode(public.digest(convert_to('privacy-receipt-preview-v1'||E'\n'||p_case||E'\n'||p_release||E'\n'||p_challenge||E'\n'||p_receipt||E'\n'||p_signer||E'\n'||p_evidence,'UTF8'),'sha256'),'hex')
 THEN RAISE EXCEPTION 'Receipt preview denied' USING ERRCODE='42501'; END IF;
 actor:=private.sensitive_api_actor(p_tenant,p_review,p_action,p_scope,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 -- Require a release reservation created through the authenticated API.
 PERFORM private.privacy_delivery_order_summary(p_tenant,p_case,p_release);
 scope_hash:=private.privacy_receipt_scope(p_tenant,p_case,p_release,p_review,p_challenge,p_receipt,p_signer,p_evidence);
 PERFORM private.sensitive_api_fresh(p_auth,p_expires);
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id)
 VALUES(p_tenant,actor,'privacy_receipt_previewed','privacy_rights_case',p_case);
 RETURN jsonb_build_object('caseId',p_case,'releaseOrderId',p_release,'reviewOrderId',p_review,'scopeDigest',scope_hash,'receiptEvidenceRecorded',false,'deliveryVerified',false);
END $fn$;

CREATE FUNCTION private.api_privacy_receipt_status(
 p_tenant uuid,p_review uuid,p_action text,p_scope text,p_auth bigint,p_iat bigint,p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text,p_case uuid,p_release uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE actor uuid; result jsonb;
BEGIN
 IF p_action IS DISTINCT FROM 'privacy_receipt_status' OR p_scope IS DISTINCT FROM encode(public.digest(convert_to('privacy-receipt-status-v1'||E'\n'||p_case||E'\n'||p_release,'UTF8'),'sha256'),'hex')
 THEN RAISE EXCEPTION 'Receipt status denied' USING ERRCODE='42501'; END IF;
 actor:=private.sensitive_api_actor(p_tenant,p_review,p_action,p_scope,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 result:=private.privacy_receipt_order_summary(p_tenant,p_case,p_release,p_review);
 PERFORM private.sensitive_api_fresh(p_auth,p_expires);
 RETURN result;
END $fn$;

CREATE FUNCTION private.api_privacy_receipt_step(
 p_tenant uuid,p_case uuid,p_release uuid,p_review uuid,p_challenge text,p_receipt text,p_signer text,p_evidence text,p_scope text,p_step text,
 p_auth bigint,p_iat bigint,p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
BEGIN
 PERFORM private.security_work_actor(p_tenant,p_review,'privileged_operation',p_scope,p_step,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 PERFORM private.privacy_delivery_order_summary(p_tenant,p_case,p_release);
 IF p_step<>'request' AND NOT EXISTS(SELECT 1 FROM private.privacy_receipt_requests WHERE tenant_id=p_tenant AND case_id=p_case AND release_order_id=p_release AND review_order_id=p_review AND scope_digest=p_scope)
 THEN RAISE EXCEPTION 'Receipt review unavailable' USING ERRCODE='42501'; END IF;
 PERFORM private.record_privacy_receipt_evidence(p_tenant,p_case,p_release,p_review,p_challenge,p_receipt,p_signer,p_evidence,p_scope,p_step,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 IF p_step='request' THEN
  INSERT INTO private.privacy_receipt_requests(tenant_id,case_id,release_order_id,review_order_id,scope_digest) VALUES(p_tenant,p_case,p_release,p_review,p_scope);
 END IF;
 PERFORM private.sensitive_api_fresh(p_auth,p_expires);
 RETURN private.privacy_receipt_order_summary(p_tenant,p_case,p_release,p_review);
END $fn$;
REVOKE ALL ON FUNCTION private.privacy_receipt_order_summary(uuid,uuid,uuid,uuid),private.api_privacy_receipt_preview(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text,uuid,uuid,text,text,text,text),
 private.api_privacy_receipt_status(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text,uuid,uuid),
 private.api_privacy_receipt_step(uuid,uuid,uuid,uuid,text,text,text,text,text,text,bigint,bigint,text,bigint,text,text,text) FROM PUBLIC,profitpilot_app;
GRANT EXECUTE ON FUNCTION private.api_privacy_receipt_preview(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text,uuid,uuid,text,text,text,text),
 private.api_privacy_receipt_status(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text,uuid,uuid),
 private.api_privacy_receipt_step(uuid,uuid,uuid,uuid,text,text,text,text,text,text,bigint,bigint,text,bigint,text,text,text) TO profitpilot_app;
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
  ) all_entries LIMIT 100001
 ), hashes AS (SELECT kind,encode(hash,'hex') AS h FROM entries)
 SELECT count(*),CASE WHEN count(*)<=100000 THEN encode(public.digest(convert_to('profitpilot-sensitive-recovery-v7:'||coalesce(string_agg(kind||':'||h,',' ORDER BY kind COLLATE "C",h COLLATE "C"),''),'UTF8'),'sha256'),'hex') END
 INTO total,result FROM hashes;
 IF total>100000 OR result IS NULL THEN RAISE EXCEPTION 'Sensitive recovery inventory exceeds reviewed capacity' USING ERRCODE='54000'; END IF;
 RETURN result;
END $fn$;

REVOKE ALL ON FUNCTION private.sensitive_recovery_fingerprint() FROM PUBLIC,profitpilot_app;
CREATE OR REPLACE FUNCTION private.verify_security_catalog()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT digest=private.security_catalog_digest() FROM private.security_catalog_baseline WHERE revision=59),false)
$fn$;
INSERT INTO private.security_catalog_baseline(singleton,revision,digest) VALUES(true,59,private.security_catalog_digest());
COMMIT;

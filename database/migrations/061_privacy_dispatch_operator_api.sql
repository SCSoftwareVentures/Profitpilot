-- Candidate-only administration. No transmission, tokens or key storage.
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
 IF p_action IS NULL OR p_action NOT IN ('payroll_submit','payroll_read','account_read','account_correct_email','invoice_disposal_preview','privacy_case_request','privacy_case_status','privacy_case_intake','privacy_case_acknowledge','privacy_case_resolve','privacy_case_refuse','payroll_correction_preview','payroll_correction_status','privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status')
 OR (p_action IN ('privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status') AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('payroll_correction_preview','payroll_correction_status') AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('privacy_case_intake','privacy_case_acknowledge','privacy_case_resolve','privacy_case_refuse') AND actor_role NOT IN ('owner','admin'))
 OR (p_action='payroll_submit' AND actor_role NOT IN ('owner','admin','analyst'))
 OR (p_action='payroll_read' AND actor_role NOT IN ('owner','admin','reviewer'))
 OR (p_action='invoice_disposal_preview' AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('account_read','account_correct_email') AND p_target<>p_tenant)
 THEN RAISE EXCEPTION 'Sensitive operation denied' USING ERRCODE='42501'; END IF;
 now_s:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 IF p_scope IS NULL OR p_scope !~ '^[a-f0-9]{64}$'
 OR (p_action IN ('account_correct_email','privacy_case_request','privacy_case_intake','privacy_case_resolve','privacy_case_refuse','payroll_correction_preview','privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status') AND p_scope=repeat('0',64))
 OR (p_action NOT IN ('account_correct_email','privacy_case_request','privacy_case_intake','privacy_case_resolve','privacy_case_refuse','payroll_correction_preview','privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status') AND p_scope<>repeat('0',64))
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





CREATE OR REPLACE FUNCTION private.privacy_receipt_scope(p_tenant uuid,p_case uuid,p_release uuid,p_review uuid,p_challenge text,p_receipt text,p_signer text,p_evidence text)
RETURNS text LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog SET timezone='UTC' AS $fn$
DECLARE a private.privacy_delivery_authorizations%ROWTYPE; h text;
BEGIN
 IF p_tenant IS NULL OR p_case IS NULL OR p_release IS NULL OR p_review IS NULL OR p_release=p_review
 OR private.current_tenant_id() IS DISTINCT FROM p_tenant OR coalesce(private.current_actor_role(),'') NOT IN ('owner','admin')
 OR private.lock_tenant_available(p_tenant) IS DISTINCT FROM true OR p_challenge IS NOT DISTINCT FROM p_receipt
 THEN RAISE EXCEPTION 'Privacy receipt denied' USING ERRCODE='42501'; END IF;
 FOREACH h IN ARRAY ARRAY[p_challenge,p_receipt,p_signer,p_evidence] LOOP
  IF h IS NULL OR h !~ '^[a-f0-9]{64}$' OR h=repeat('0',64) THEN RAISE EXCEPTION 'Privacy receipt denied' USING ERRCODE='42501'; END IF;
 END LOOP;
 SELECT * INTO a FROM private.privacy_delivery_authorizations WHERE tenant_id=p_tenant AND case_id=p_case AND order_id=p_release FOR UPDATE;
 IF NOT FOUND OR p_signer IN (a.sender_key_digest,a.recipient_key_digest)
 THEN RAISE EXCEPTION 'Privacy receipt denied' USING ERRCODE='42501'; END IF;
 -- Reserved dispatches require the exact spent challenge and independently
 -- reviewed recipient signing key; historical revocation does not erase evidence.
 IF EXISTS(SELECT 1 FROM private.privacy_dispatch_reservations WHERE tenant_id=p_tenant AND release_order_id=p_release)
 AND NOT EXISTS(SELECT 1 FROM private.privacy_dispatch_reservations r JOIN private.privacy_dispatch_burns b
  ON b.tenant_id=r.tenant_id AND b.release_order_id=r.release_order_id
  WHERE r.tenant_id=p_tenant AND r.release_order_id=p_release AND r.challenge_digest=p_challenge AND r.receipt_key_digest=p_signer)
 THEN RAISE EXCEPTION 'Receipt does not match spent dispatch' USING ERRCODE='42501'; END IF;
 IF EXISTS(SELECT 1 FROM private.privacy_receipt_evidence WHERE tenant_id=p_tenant AND release_order_id=p_release)
 THEN RAISE EXCEPTION 'Receipt already reconciled' USING ERRCODE='23505'; END IF;
 RETURN encode(public.digest(convert_to(jsonb_build_array('profitpilot-privacy-receipt-evidence-v1',p_tenant,p_case,p_release,p_review,a.scope_digest,a.envelope_digest,a.response_digest,a.sender_key_digest,a.recipient_key_digest,a.authorized_at,p_challenge,p_receipt,p_signer,p_evidence)::text,'UTF8'),'sha256'),'hex');
END $fn$;


CREATE FUNCTION private.api_privacy_dispatch_status(
 p_tenant uuid,p_release uuid,p_action text,p_scope text,p_auth bigint,p_iat bigint,p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text,p_case uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE result jsonb;
BEGIN
 IF p_action IS DISTINCT FROM 'privacy_dispatch_status' OR p_scope IS DISTINCT FROM encode(public.digest(convert_to('profitpilot-privacy-dispatch-status-v1'||E'\n'||p_case||E'\n'||p_release,'UTF8'),'sha256'),'hex')
 THEN RAISE EXCEPTION 'Dispatch status denied' USING ERRCODE='42501'; END IF;
 PERFORM private.sensitive_api_actor(p_tenant,p_release,p_action,p_scope,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 PERFORM private.privacy_delivery_order_summary(p_tenant,p_case,p_release);
 result:=private.privacy_dispatch_status(p_tenant,p_case,p_release);
 PERFORM private.sensitive_api_fresh(p_auth,p_expires);
 RETURN result;
END $fn$;

CREATE FUNCTION private.api_privacy_dispatch_step(
 p_tenant uuid,p_case uuid,p_release uuid,p_action text,p_challenge text,p_signer text,p_deadline bigint,p_reason text,p_evidence text,p_scope text,
 p_auth bigint,p_iat bigint,p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
BEGIN
 PERFORM private.sensitive_api_actor(p_tenant,p_release,p_action,p_scope,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 PERFORM private.privacy_delivery_order_summary(p_tenant,p_case,p_release);
 RETURN private.record_privacy_dispatch(p_tenant,p_case,p_release,p_action,p_challenge,p_signer,p_deadline,p_reason,p_evidence,p_scope,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
END $fn$;
REVOKE ALL ON FUNCTION private.api_privacy_dispatch_status(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text,uuid),
 private.api_privacy_dispatch_step(uuid,uuid,uuid,text,text,text,bigint,text,text,text,bigint,bigint,text,bigint,text,text,text) FROM PUBLIC,profitpilot_app;
GRANT EXECUTE ON FUNCTION private.api_privacy_dispatch_status(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text,uuid),
 private.api_privacy_dispatch_step(uuid,uuid,uuid,text,text,text,bigint,text,text,text,bigint,bigint,text,bigint,text,text,text) TO profitpilot_app;
CREATE OR REPLACE FUNCTION private.verify_security_catalog()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT digest=private.security_catalog_digest() FROM private.security_catalog_baseline WHERE revision=61),false)
$fn$;
INSERT INTO private.security_catalog_baseline(singleton,revision,digest) VALUES(true,61,private.security_catalog_digest());
COMMIT;

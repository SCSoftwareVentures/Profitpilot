-- Durable candidate dispatch fence. No network access, transport or runtime grant.
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
 IF p_action IS NULL OR p_action NOT IN ('payroll_submit','payroll_read','account_read','account_correct_email','invoice_disposal_preview','privacy_case_request','privacy_case_status','privacy_case_intake','privacy_case_acknowledge','privacy_case_resolve','privacy_case_refuse','payroll_correction_preview','payroll_correction_status','privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke')
 OR (p_action IN ('privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke') AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('payroll_correction_preview','payroll_correction_status') AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('privacy_case_intake','privacy_case_acknowledge','privacy_case_resolve','privacy_case_refuse') AND actor_role NOT IN ('owner','admin'))
 OR (p_action='payroll_submit' AND actor_role NOT IN ('owner','admin','analyst'))
 OR (p_action='payroll_read' AND actor_role NOT IN ('owner','admin','reviewer'))
 OR (p_action='invoice_disposal_preview' AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('account_read','account_correct_email') AND p_target<>p_tenant)
 THEN RAISE EXCEPTION 'Sensitive operation denied' USING ERRCODE='42501'; END IF;
 now_s:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 IF p_scope IS NULL OR p_scope !~ '^[a-f0-9]{64}$'
 OR (p_action IN ('account_correct_email','privacy_case_request','privacy_case_intake','privacy_case_resolve','privacy_case_refuse','payroll_correction_preview','privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke') AND p_scope=repeat('0',64))
 OR (p_action NOT IN ('account_correct_email','privacy_case_request','privacy_case_intake','privacy_case_resolve','privacy_case_refuse','payroll_correction_preview','privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke') AND p_scope<>repeat('0',64))
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





CREATE TABLE private.privacy_dispatch_reservations(
 tenant_id uuid NOT NULL,release_order_id uuid NOT NULL,
 challenge_digest text NOT NULL CHECK(challenge_digest ~ '^[a-f0-9]{64}$' AND challenge_digest<>repeat('0',64)),
 receipt_key_digest text NOT NULL CHECK(receipt_key_digest ~ '^[a-f0-9]{64}$' AND receipt_key_digest<>repeat('0',64)),
 expires_at timestamptz NOT NULL,reserved_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 actor_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,release_order_id),UNIQUE(tenant_id,challenge_digest),
 FOREIGN KEY(tenant_id,release_order_id) REFERENCES private.privacy_delivery_authorizations(tenant_id,order_id),
 FOREIGN KEY(tenant_id,actor_id) REFERENCES public.tenant_memberships(tenant_id,user_id),
 CHECK(expires_at>reserved_at AND expires_at<=reserved_at+interval '15 minutes')
);
CREATE TABLE private.privacy_dispatch_burns(
 tenant_id uuid NOT NULL,release_order_id uuid NOT NULL,actor_id uuid NOT NULL,
 burned_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,release_order_id),
 FOREIGN KEY(tenant_id,release_order_id) REFERENCES private.privacy_dispatch_reservations(tenant_id,release_order_id),
 FOREIGN KEY(tenant_id,actor_id) REFERENCES public.tenant_memberships(tenant_id,user_id)
);
CREATE TABLE private.privacy_dispatch_revocations(
 tenant_id uuid NOT NULL,release_order_id uuid NOT NULL,actor_id uuid NOT NULL,
 reason_code text NOT NULL CHECK(reason_code IN ('identity_uncertain','key_compromise','recipient_changed','authority_withdrawn','security_incident','ambiguous_dispatch')),
 evidence_digest text NOT NULL CHECK(evidence_digest ~ '^[a-f0-9]{64}$' AND evidence_digest<>repeat('0',64)),
 revoked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,release_order_id),
 FOREIGN KEY(tenant_id,release_order_id) REFERENCES private.privacy_delivery_authorizations(tenant_id,order_id),
 FOREIGN KEY(tenant_id,actor_id) REFERENCES public.tenant_memberships(tenant_id,user_id)
);
REVOKE ALL ON private.privacy_dispatch_reservations,private.privacy_dispatch_burns,private.privacy_dispatch_revocations FROM PUBLIC,profitpilot_app;
CREATE TRIGGER privacy_dispatch_reservations_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON private.privacy_dispatch_reservations FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();
CREATE TRIGGER privacy_dispatch_burns_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON private.privacy_dispatch_burns FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();
CREATE TRIGGER privacy_dispatch_revocations_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON private.privacy_dispatch_revocations FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();

CREATE FUNCTION private.privacy_dispatch_status(p_tenant uuid,p_case uuid,p_release uuid)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog AS $fn$
DECLARE result jsonb;
BEGIN
 SELECT jsonb_build_object('state',CASE WHEN v.release_order_id IS NOT NULL THEN 'revoked'
 WHEN b.release_order_id IS NOT NULL THEN 'attempt-spent'
 WHEN e.release_order_id IS NOT NULL THEN 'receipt-evidence-recorded'
 WHEN r.expires_at<=clock_timestamp() OR (r.release_order_id IS NULL AND a.authorized_at+interval '15 minutes'<=clock_timestamp()) THEN 'expired'
 WHEN r.release_order_id IS NOT NULL THEN 'reserved' ELSE 'unreserved' END,
 'attemptSpent',b.release_order_id IS NOT NULL,'receiptEvidenceRecorded',e.release_order_id IS NOT NULL,
 'mayTransmit',false,'deliveryVerified',false)
 INTO result FROM private.privacy_delivery_authorizations a
 LEFT JOIN private.privacy_dispatch_reservations r ON r.tenant_id=a.tenant_id AND r.release_order_id=a.order_id
 LEFT JOIN private.privacy_dispatch_burns b ON b.tenant_id=a.tenant_id AND b.release_order_id=a.order_id
 LEFT JOIN private.privacy_dispatch_revocations v ON v.tenant_id=a.tenant_id AND v.release_order_id=a.order_id
 LEFT JOIN private.privacy_receipt_evidence e ON e.tenant_id=a.tenant_id AND e.release_order_id=a.order_id
 WHERE a.tenant_id=p_tenant AND a.case_id=p_case AND a.order_id=p_release;
 IF result IS NULL THEN RAISE EXCEPTION 'Dispatch unavailable' USING ERRCODE='42501'; END IF;
 RETURN result;
END $fn$;

-- Exact signed action, not a transport permission. The trusted offline procedure
-- must verify the challenge, signing key, recipient and current entitlement.
-- All actions serialize on the immutable release authorization row.
CREATE FUNCTION private.record_privacy_dispatch(
 p_tenant uuid,p_case uuid,p_release uuid,p_action text,p_challenge text,p_signer text,p_deadline bigint,p_reason text,p_evidence text,p_scope text,
 p_auth bigint,p_iat bigint,p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog SET timezone='UTC' AS $fn$
DECLARE actor uuid; a private.privacy_delivery_authorizations%ROWTYPE; r private.privacy_dispatch_reservations%ROWTYPE;
 o private.security_work_orders%ROWTYPE; d private.security_work_decisions%ROWTYPE; c private.security_work_consumptions%ROWTYPE; at_time timestamptz;
BEGIN
 IF p_action IS NULL OR p_action NOT IN ('privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke')
 OR p_case IS NULL OR p_release IS NULL
 OR p_scope IS DISTINCT FROM encode(public.digest(convert_to('profitpilot-privacy-dispatch-v1'||E'\n'||p_case||E'\n'||p_release||E'\n'||p_action||E'\n'||coalesce(p_challenge,'')||E'\n'||coalesce(p_signer,'')||E'\n'||coalesce(p_deadline::text,'')||E'\n'||coalesce(p_reason,'')||E'\n'||coalesce(p_evidence,''),'UTF8'),'sha256'),'hex')
 THEN RAISE EXCEPTION 'Dispatch action denied' USING ERRCODE='42501'; END IF;
 actor:=private.sensitive_api_actor(p_tenant,p_release,p_action,p_scope,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 SELECT * INTO a FROM private.privacy_delivery_authorizations WHERE tenant_id=p_tenant AND case_id=p_case AND order_id=p_release FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Dispatch action denied' USING ERRCODE='42501'; END IF;
 PERFORM private.sensitive_api_fresh(p_auth,p_expires);
 IF p_action='privacy_dispatch_revoke' THEN
  IF p_challenge IS NOT NULL OR p_signer IS NOT NULL OR p_deadline IS NOT NULL OR p_reason IS NULL
  OR p_reason NOT IN ('identity_uncertain','key_compromise','recipient_changed','authority_withdrawn','security_incident','ambiguous_dispatch')
  OR p_evidence IS NULL OR p_evidence !~ '^[a-f0-9]{64}$' OR p_evidence=repeat('0',64)
  THEN RAISE EXCEPTION 'Dispatch revocation denied' USING ERRCODE='42501'; END IF;
  INSERT INTO private.privacy_dispatch_revocations(tenant_id,release_order_id,actor_id,reason_code,evidence_digest)
  VALUES(p_tenant,p_release,actor,p_reason,p_evidence);
 ELSE
  IF p_reason IS NOT NULL OR p_evidence IS NOT NULL OR p_challenge IS NULL OR p_challenge !~ '^[a-f0-9]{64}$' OR p_challenge=repeat('0',64)
  OR p_signer IS NULL OR p_signer !~ '^[a-f0-9]{64}$' OR p_signer=repeat('0',64) OR p_signer IN (a.sender_key_digest,a.recipient_key_digest)
  OR p_deadline IS NULL OR p_deadline NOT BETWEEN 1 AND 4102444800
  OR EXISTS(SELECT 1 FROM private.privacy_dispatch_revocations WHERE tenant_id=p_tenant AND release_order_id=p_release)
  OR EXISTS(SELECT 1 FROM private.privacy_receipt_evidence WHERE tenant_id=p_tenant AND release_order_id=p_release)
  THEN RAISE EXCEPTION 'Dispatch action denied' USING ERRCODE='42501'; END IF;
  SELECT * INTO o FROM private.security_work_orders WHERE tenant_id=p_tenant AND id=p_release;
  SELECT * INTO d FROM private.security_work_decisions WHERE tenant_id=p_tenant AND order_id=p_release;
  SELECT * INTO c FROM private.security_work_consumptions WHERE tenant_id=p_tenant AND order_id=p_release;
  IF o.requested_by IS DISTINCT FROM actor OR c.consumed_by IS DISTINCT FROM actor OR d.decision IS DISTINCT FROM 'approved'
  OR d.decided_by IS NULL OR d.decided_by=actor OR o.scope_digest IS DISTINCT FROM a.scope_digest
  THEN RAISE EXCEPTION 'Dispatch authority denied' USING ERRCODE='42501'; END IF;
  PERFORM 1 FROM public.tenant_memberships m JOIN public.users u ON u.id=m.user_id
   WHERE m.tenant_id=p_tenant AND m.user_id=d.decided_by AND m.status='active' AND m.role IN ('owner','admin') AND u.status='active' FOR SHARE OF m,u;
  IF NOT FOUND OR EXISTS(SELECT 1 FROM private.identity_session_cutoffs WHERE user_id=d.decided_by AND revoked_through>=d.auth_time)
   OR EXISTS(SELECT 1 FROM private.revoked_identity_sessions WHERE user_id=d.decided_by AND session_digest=d.session_digest)
  THEN RAISE EXCEPTION 'Dispatch approval revoked' USING ERRCODE='42501'; END IF;
  at_time:=clock_timestamp();
  IF d.expires_at<=at_time OR to_timestamp(p_deadline)<=at_time OR to_timestamp(p_deadline)>a.authorized_at+interval '30 minutes'
  THEN RAISE EXCEPTION 'Dispatch expired' USING ERRCODE='42501'; END IF;
  IF p_action='privacy_dispatch_reserve' THEN
   IF at_time>=a.authorized_at+interval '15 minutes' OR to_timestamp(p_deadline)>at_time+interval '15 minutes'
   THEN RAISE EXCEPTION 'Dispatch reservation expired' USING ERRCODE='42501'; END IF;
   INSERT INTO private.privacy_dispatch_reservations(tenant_id,release_order_id,challenge_digest,receipt_key_digest,expires_at,reserved_at,actor_id)
   VALUES(p_tenant,p_release,p_challenge,p_signer,to_timestamp(p_deadline),at_time,actor);
  ELSE
   SELECT * INTO r FROM private.privacy_dispatch_reservations WHERE tenant_id=p_tenant AND release_order_id=p_release;
   IF NOT FOUND OR r.actor_id IS DISTINCT FROM actor OR r.challenge_digest IS DISTINCT FROM p_challenge
   OR r.receipt_key_digest IS DISTINCT FROM p_signer OR r.expires_at IS DISTINCT FROM to_timestamp(p_deadline) OR r.expires_at<=at_time
   THEN RAISE EXCEPTION 'Dispatch reservation denied' USING ERRCODE='42501'; END IF;
   INSERT INTO private.privacy_dispatch_burns(tenant_id,release_order_id,actor_id,burned_at) VALUES(p_tenant,p_release,actor,at_time);
  END IF;
 END IF;
 PERFORM private.sensitive_api_fresh(p_auth,p_expires);
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id)
 VALUES(p_tenant,actor,p_action,'privacy_rights_case',p_case);
 RETURN private.privacy_dispatch_status(p_tenant,p_case,p_release);
END $fn$;
REVOKE ALL ON FUNCTION private.privacy_dispatch_status(uuid,uuid,uuid),
 private.record_privacy_dispatch(uuid,uuid,uuid,text,text,text,bigint,text,text,text,bigint,bigint,text,bigint,text,text,text) FROM PUBLIC,profitpilot_app;
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
  ) all_entries LIMIT 100001
 ), hashes AS (SELECT kind,encode(hash,'hex') AS h FROM entries)
 SELECT count(*),CASE WHEN count(*)<=100000 THEN encode(public.digest(convert_to('profitpilot-sensitive-recovery-v8:'||coalesce(string_agg(kind||':'||h,',' ORDER BY kind COLLATE "C",h COLLATE "C"),''),'UTF8'),'sha256'),'hex') END
 INTO total,result FROM hashes;
 IF total>100000 OR result IS NULL THEN RAISE EXCEPTION 'Sensitive recovery inventory exceeds reviewed capacity' USING ERRCODE='54000'; END IF;
 RETURN result;
END $fn$;

REVOKE ALL ON FUNCTION private.sensitive_recovery_fingerprint() FROM PUBLIC,profitpilot_app;
CREATE OR REPLACE FUNCTION private.verify_security_catalog()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT digest=private.security_catalog_digest() FROM private.security_catalog_baseline WHERE revision=60),false)
$fn$;
INSERT INTO private.security_catalog_baseline(singleton,revision,digest) VALUES(true,60,private.security_catalog_digest());
COMMIT;

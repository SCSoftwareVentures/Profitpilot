-- Private evidence reconciliation; not a delivery or identity assertion.
BEGIN;
DO $check$ BEGIN
 IF private.verify_security_catalog() IS DISTINCT FROM true THEN RAISE EXCEPTION 'Prior security catalog does not verify'; END IF;
END $check$;
CREATE TABLE private.privacy_receipt_evidence(
 tenant_id uuid NOT NULL,case_id uuid NOT NULL,release_order_id uuid NOT NULL,review_order_id uuid NOT NULL,
 challenge_digest text NOT NULL CHECK(challenge_digest ~ '^[a-f0-9]{64}$' AND challenge_digest<>repeat('0',64)),
 receipt_digest text NOT NULL CHECK(receipt_digest ~ '^[a-f0-9]{64}$' AND receipt_digest<>repeat('0',64)),
 receipt_key_digest text NOT NULL CHECK(receipt_key_digest ~ '^[a-f0-9]{64}$' AND receipt_key_digest<>repeat('0',64)),
 verification_evidence_digest text NOT NULL CHECK(verification_evidence_digest ~ '^[a-f0-9]{64}$' AND verification_evidence_digest<>repeat('0',64)),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,release_order_id),UNIQUE(tenant_id,review_order_id),UNIQUE(tenant_id,challenge_digest),UNIQUE(tenant_id,receipt_digest),
 FOREIGN KEY(tenant_id,release_order_id) REFERENCES private.privacy_delivery_authorizations(tenant_id,order_id),
 FOREIGN KEY(tenant_id,case_id) REFERENCES private.privacy_rights_cases(tenant_id,id),
 FOREIGN KEY(tenant_id,review_order_id) REFERENCES private.security_work_consumptions(tenant_id,order_id),
 CHECK(release_order_id<>review_order_id AND challenge_digest<>receipt_digest)
);
REVOKE ALL ON private.privacy_receipt_evidence FROM PUBLIC,profitpilot_app;
CREATE TRIGGER privacy_receipt_evidence_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON private.privacy_receipt_evidence
 FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();

-- The verified offline receipt and independent identity/key verification
-- must be retained separately; these digests alone never prove delivery.
CREATE FUNCTION private.privacy_receipt_scope(p_tenant uuid,p_case uuid,p_release uuid,p_review uuid,p_challenge text,p_receipt text,p_signer text,p_evidence text)
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
 IF EXISTS(SELECT 1 FROM private.privacy_receipt_evidence WHERE tenant_id=p_tenant AND release_order_id=p_release)
 THEN RAISE EXCEPTION 'Receipt already reconciled' USING ERRCODE='23505'; END IF;
 RETURN encode(public.digest(convert_to(jsonb_build_array('profitpilot-privacy-receipt-evidence-v1',p_tenant,p_case,p_release,p_review,a.scope_digest,a.envelope_digest,a.response_digest,a.sender_key_digest,a.recipient_key_digest,a.authorized_at,p_challenge,p_receipt,p_signer,p_evidence)::text,'UTF8'),'sha256'),'hex');
END $fn$;

CREATE FUNCTION private.record_privacy_receipt_evidence(
 p_tenant uuid,p_case uuid,p_release uuid,p_review uuid,p_challenge text,p_receipt text,p_signer text,p_evidence text,p_scope text,p_step text,
 p_auth bigint,p_iat bigint,p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE actor uuid;
BEGIN
 actor:=private.security_work_actor(p_tenant,p_review,'privileged_operation',p_scope,p_step,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 IF private.privacy_receipt_scope(p_tenant,p_case,p_release,p_review,p_challenge,p_receipt,p_signer,p_evidence) IS DISTINCT FROM p_scope
 THEN RAISE EXCEPTION 'Privacy receipt scope changed' USING ERRCODE='42501'; END IF;
 PERFORM private.record_security_work(p_tenant,p_review,'privileged_operation',p_scope,p_step,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 IF p_step='consume' THEN
  INSERT INTO private.privacy_receipt_evidence(tenant_id,case_id,release_order_id,review_order_id,challenge_digest,receipt_digest,receipt_key_digest,verification_evidence_digest)
  VALUES(p_tenant,p_case,p_release,p_review,p_challenge,p_receipt,p_signer,p_evidence);
  INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id)
  VALUES(p_tenant,actor,'privacy_receipt_evidence_recorded','privacy_rights_case',p_case);
 END IF;
END $fn$;
REVOKE ALL ON FUNCTION private.privacy_receipt_scope(uuid,uuid,uuid,uuid,text,text,text,text),
 private.record_privacy_receipt_evidence(uuid,uuid,uuid,uuid,text,text,text,text,text,text,bigint,bigint,text,bigint,text,text,text) FROM PUBLIC,profitpilot_app;

CREATE OR REPLACE FUNCTION private.privacy_delivery_order_summary(p_tenant uuid,p_case uuid,p_order uuid)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE result jsonb;
BEGIN
 SELECT jsonb_build_object('caseId',q.case_id,'orderId',q.order_id,'scopeDigest',q.scope_digest,
 'status',CASE WHEN a.order_id IS NOT NULL THEN 'release-authorized' WHEN d.decision='rejected' THEN 'rejected'
 WHEN d.expires_at<=clock_timestamp() OR (d.order_id IS NULL AND w.requested_at+interval '24 hours'<=clock_timestamp()) THEN 'expired'
 WHEN d.decision='approved' THEN 'approved' ELSE 'requested' END,
 'releaseAuthorizedAt',a.authorized_at,'receiptEvidenceRecorded',e.release_order_id IS NOT NULL,'deliveryVerified',false)
 INTO result FROM private.privacy_delivery_requests q
 JOIN private.security_work_orders w ON w.tenant_id=q.tenant_id AND w.id=q.order_id
 LEFT JOIN private.security_work_decisions d ON d.tenant_id=q.tenant_id AND d.order_id=q.order_id
 LEFT JOIN private.privacy_delivery_authorizations a ON a.tenant_id=q.tenant_id AND a.order_id=q.order_id AND a.case_id=q.case_id
 LEFT JOIN private.privacy_receipt_evidence e ON e.tenant_id=q.tenant_id AND e.release_order_id=q.order_id AND e.case_id=q.case_id
 WHERE q.tenant_id=p_tenant AND q.case_id=p_case AND q.order_id=p_order;
 IF result IS NULL THEN RAISE EXCEPTION 'Privacy delivery order unavailable' USING ERRCODE='42501'; END IF;
 RETURN result;
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
  ) all_entries LIMIT 100001
 ), hashes AS (SELECT kind,encode(hash,'hex') AS h FROM entries)
 SELECT count(*),CASE WHEN count(*)<=100000 THEN encode(public.digest(convert_to('profitpilot-sensitive-recovery-v6:'||coalesce(string_agg(kind||':'||h,',' ORDER BY kind COLLATE "C",h COLLATE "C"),''),'UTF8'),'sha256'),'hex') END
 INTO total,result FROM hashes;
 IF total>100000 OR result IS NULL THEN RAISE EXCEPTION 'Sensitive recovery inventory exceeds reviewed capacity' USING ERRCODE='54000'; END IF;
 RETURN result;
END $fn$;

REVOKE ALL ON FUNCTION private.sensitive_recovery_fingerprint() FROM PUBLIC,profitpilot_app;
CREATE OR REPLACE FUNCTION private.verify_security_catalog()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT digest=private.security_catalog_digest() FROM private.security_catalog_baseline WHERE revision=58),false)
$fn$;
INSERT INTO private.security_catalog_baseline(singleton,revision,digest) VALUES(true,58,private.security_catalog_digest());
COMMIT;

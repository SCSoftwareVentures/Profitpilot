-- Assisted response authorization: no document storage, transport or erasure.
BEGIN;
DO $check$ BEGIN
 IF private.verify_security_catalog() IS DISTINCT FROM true THEN RAISE EXCEPTION 'Prior security catalog does not verify'; END IF;
END $check$;
CREATE TABLE private.privacy_delivery_authorizations(
 tenant_id uuid NOT NULL,case_id uuid NOT NULL,order_id uuid NOT NULL,
 recipient_type text NOT NULL CHECK(recipient_type IN ('self','assisted_subject','authorized_representative','former_user')),
 recipient_key_digest text NOT NULL CHECK(recipient_key_digest ~ '^[a-f0-9]{64}$' AND recipient_key_digest<>repeat('0',64)),
 sender_key_digest text NOT NULL CHECK(sender_key_digest ~ '^[a-f0-9]{64}$' AND sender_key_digest<>repeat('0',64)),
 authority_digest text NOT NULL CHECK(authority_digest ~ '^[a-f0-9]{64}$' AND authority_digest<>repeat('0',64)),
 redaction_digest text NOT NULL CHECK(redaction_digest ~ '^[a-f0-9]{64}$' AND redaction_digest<>repeat('0',64)),
 response_digest text NOT NULL CHECK(response_digest ~ '^[a-f0-9]{64}$' AND response_digest<>repeat('0',64)),
 envelope_digest text NOT NULL CHECK(envelope_digest ~ '^[a-f0-9]{64}$' AND envelope_digest<>repeat('0',64)),
 scope_digest text NOT NULL CHECK(scope_digest ~ '^[a-f0-9]{64}$' AND scope_digest<>repeat('0',64)),
 authorized_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,order_id),UNIQUE(tenant_id,envelope_digest),
 FOREIGN KEY(tenant_id,case_id) REFERENCES private.privacy_rights_outcomes(tenant_id,case_id),
 FOREIGN KEY(tenant_id,order_id) REFERENCES private.security_work_consumptions(tenant_id,order_id),
 CHECK(recipient_key_digest<>sender_key_digest)
);
CREATE INDEX privacy_delivery_case_idx ON private.privacy_delivery_authorizations(tenant_id,case_id);
REVOKE ALL ON private.privacy_delivery_authorizations FROM PUBLIC,profitpilot_app;
CREATE TRIGGER privacy_delivery_authorization_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON private.privacy_delivery_authorizations
 FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();

-- Scope binds the recorded case decision, independently verified recipient
-- authority and key, redaction evidence, plaintext and exact encrypted envelope.
-- Evidence digests are assertions made in an assisted procedure, not themselves
-- proof of identity, legal entitlement, redaction completeness or delivery.
CREATE FUNCTION private.privacy_delivery_scope(
 p_tenant uuid,p_case uuid,p_order uuid,p_type text,p_recipient text,p_sender text,p_authority text,p_redaction text,p_response text,p_envelope text)
RETURNS text LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog AS $fn$
DECLARE c private.privacy_rights_cases%ROWTYPE; o private.privacy_rights_outcomes%ROWTYPE; h text;
BEGIN
 IF p_tenant IS NULL OR p_case IS NULL OR p_order IS NULL OR private.current_tenant_id() IS DISTINCT FROM p_tenant
 OR coalesce(private.current_actor_role(),'') NOT IN ('owner','admin') OR private.lock_tenant_available(p_tenant) IS DISTINCT FROM true
 OR p_type IS NULL OR p_type NOT IN ('self','assisted_subject','authorized_representative','former_user')
 OR p_recipient IS NOT DISTINCT FROM p_sender
 THEN RAISE EXCEPTION 'Privacy delivery denied' USING ERRCODE='42501'; END IF;
 FOREACH h IN ARRAY ARRAY[p_recipient,p_sender,p_authority,p_redaction,p_response,p_envelope] LOOP
  IF h IS NULL OR h !~ '^[a-f0-9]{64}$' OR h=repeat('0',64) THEN RAISE EXCEPTION 'Privacy delivery denied' USING ERRCODE='42501'; END IF;
 END LOOP;
 SELECT * INTO c FROM private.privacy_rights_cases WHERE tenant_id=p_tenant AND id=p_case FOR UPDATE;
 IF NOT FOUND OR (c.channel='self' AND p_type<>'self') OR (c.channel='verified_staff_intake' AND p_type='self')
 THEN RAISE EXCEPTION 'Privacy delivery denied' USING ERRCODE='42501'; END IF;
 SELECT * INTO o FROM private.privacy_rights_outcomes WHERE tenant_id=p_tenant AND case_id=p_case;
 IF NOT FOUND OR o.actor_id=c.opened_by OR o.reason_code='identity_not_verified'
 OR NOT EXISTS(SELECT 1 FROM private.privacy_rights_acknowledgements WHERE tenant_id=p_tenant AND case_id=p_case)
 THEN RAISE EXCEPTION 'Privacy delivery denied' USING ERRCODE='42501'; END IF;
 RETURN encode(public.digest(convert_to(jsonb_build_array('profitpilot-privacy-delivery-v1',p_tenant,p_case,p_order,c.kind,c.channel,c.opened_by,c.authority_digest,o.actor_id,o.status,o.reason_code,o.evidence_digest,p_type,p_recipient,p_sender,p_authority,p_redaction,p_response,p_envelope)::text,'UTF8'),'sha256'),'hex');
END $fn$;

CREATE FUNCTION private.record_privacy_delivery(
 p_tenant uuid,p_case uuid,p_order uuid,p_type text,p_recipient text,p_sender text,p_authority text,p_redaction text,p_response text,p_envelope text,
 p_scope text,p_step text,p_auth bigint,p_iat bigint,p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE actor uuid;
BEGIN
 actor:=private.security_work_actor(p_tenant,p_order,'privileged_operation',p_scope,p_step,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 IF private.privacy_delivery_scope(p_tenant,p_case,p_order,p_type,p_recipient,p_sender,p_authority,p_redaction,p_response,p_envelope) IS DISTINCT FROM p_scope
 THEN RAISE EXCEPTION 'Privacy delivery scope changed' USING ERRCODE='42501'; END IF;
 PERFORM private.record_security_work(p_tenant,p_order,'privileged_operation',p_scope,p_step,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 IF p_step='consume' THEN
  INSERT INTO private.privacy_delivery_authorizations(tenant_id,case_id,order_id,recipient_type,recipient_key_digest,sender_key_digest,authority_digest,redaction_digest,response_digest,envelope_digest,scope_digest)
  VALUES(p_tenant,p_case,p_order,p_type,p_recipient,p_sender,p_authority,p_redaction,p_response,p_envelope,p_scope);
  INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id)
  VALUES(p_tenant,actor,'privacy_response_release_authorized','privacy_rights_case',p_case);
 END IF;
END $fn$;
REVOKE ALL ON FUNCTION private.privacy_delivery_scope(uuid,uuid,uuid,text,text,text,text,text,text,text),
 private.record_privacy_delivery(uuid,uuid,uuid,text,text,text,text,text,text,text,text,text,bigint,bigint,text,bigint,text,text,text) FROM PUBLIC,profitpilot_app;

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
  ) all_entries LIMIT 100001
 ), hashes AS (SELECT kind,encode(hash,'hex') AS h FROM entries)
 SELECT count(*),CASE WHEN count(*)<=100000 THEN encode(public.digest(convert_to('profitpilot-sensitive-recovery-v4:'||coalesce(string_agg(kind||':'||h,',' ORDER BY kind COLLATE "C",h COLLATE "C"),''),'UTF8'),'sha256'),'hex') END
 INTO total,result FROM hashes;
 IF total>100000 OR result IS NULL THEN RAISE EXCEPTION 'Sensitive recovery inventory exceeds reviewed capacity' USING ERRCODE='54000'; END IF;
 RETURN result;
END $fn$;

REVOKE ALL ON FUNCTION private.sensitive_recovery_fingerprint() FROM PUBLIC,profitpilot_app;
CREATE OR REPLACE FUNCTION private.verify_security_catalog()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT digest=private.security_catalog_digest() FROM private.security_catalog_baseline WHERE revision=56),false)
$fn$;
INSERT INTO private.security_catalog_baseline(singleton,revision,digest) VALUES(true,56,private.security_catalog_digest());
COMMIT;

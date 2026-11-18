-- Case-scoped independently reviewed key versions and tenant-wide compromise fence.
-- Pin digests only; no actual private key custody or external identity claims.
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
 IF p_action IS NULL OR p_action NOT IN ('payroll_submit','payroll_read','account_read','account_correct_email','invoice_disposal_preview','privacy_case_request','privacy_case_status','privacy_case_intake','privacy_case_acknowledge','privacy_case_resolve','privacy_case_refuse','payroll_correction_preview','payroll_correction_status','privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status','privacy_key_revoke')
 OR (p_action IN ('privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status','privacy_key_revoke') AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('payroll_correction_preview','payroll_correction_status') AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('privacy_case_intake','privacy_case_acknowledge','privacy_case_resolve','privacy_case_refuse') AND actor_role NOT IN ('owner','admin'))
 OR (p_action='payroll_submit' AND actor_role NOT IN ('owner','admin','analyst'))
 OR (p_action='payroll_read' AND actor_role NOT IN ('owner','admin','reviewer'))
 OR (p_action='invoice_disposal_preview' AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('account_read','account_correct_email') AND p_target<>p_tenant)
 THEN RAISE EXCEPTION 'Sensitive operation denied' USING ERRCODE='42501'; END IF;
 now_s:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 IF p_scope IS NULL OR p_scope !~ '^[a-f0-9]{64}$'
 OR (p_action IN ('account_correct_email','privacy_case_request','privacy_case_intake','privacy_case_resolve','privacy_case_refuse','payroll_correction_preview','privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status','privacy_key_revoke') AND p_scope=repeat('0',64))
 OR (p_action NOT IN ('account_correct_email','privacy_case_request','privacy_case_intake','privacy_case_resolve','privacy_case_refuse','payroll_correction_preview','privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status','privacy_key_revoke') AND p_scope<>repeat('0',64))
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






CREATE TABLE private.privacy_case_key_versions(
 tenant_id uuid NOT NULL,case_id uuid NOT NULL,order_id uuid NOT NULL,previous_order_id uuid,
 recipient_key_digest text NOT NULL CHECK(recipient_key_digest ~ '^[a-f0-9]{64}$' AND recipient_key_digest<>repeat('0',64)),
 sender_key_digest text NOT NULL CHECK(sender_key_digest ~ '^[a-f0-9]{64}$' AND sender_key_digest<>repeat('0',64)),
 receipt_key_digest text NOT NULL CHECK(receipt_key_digest ~ '^[a-f0-9]{64}$' AND receipt_key_digest<>repeat('0',64)),
 evidence_digest text NOT NULL CHECK(evidence_digest ~ '^[a-f0-9]{64}$' AND evidence_digest<>repeat('0',64)),
 activated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,order_id),UNIQUE(tenant_id,case_id,order_id),UNIQUE(tenant_id,case_id,previous_order_id),
 FOREIGN KEY(tenant_id,case_id) REFERENCES private.privacy_rights_cases(tenant_id,id),
 FOREIGN KEY(tenant_id,order_id) REFERENCES private.security_work_consumptions(tenant_id,order_id),
 FOREIGN KEY(tenant_id,case_id,previous_order_id) REFERENCES private.privacy_case_key_versions(tenant_id,case_id,order_id),
 CHECK(previous_order_id IS NULL OR previous_order_id<>order_id),
 CHECK(recipient_key_digest<>sender_key_digest AND receipt_key_digest<>sender_key_digest AND receipt_key_digest<>recipient_key_digest)
);
CREATE UNIQUE INDEX privacy_case_key_root ON private.privacy_case_key_versions(tenant_id,case_id) WHERE previous_order_id IS NULL;
CREATE INDEX privacy_case_key_history ON private.privacy_case_key_versions(tenant_id,case_id);
CREATE TABLE private.privacy_compromised_keys(
 tenant_id uuid NOT NULL REFERENCES public.tenants(id),key_digest text NOT NULL CHECK(key_digest ~ '^[a-f0-9]{64}$' AND key_digest<>repeat('0',64)),
 evidence_digest text NOT NULL CHECK(evidence_digest ~ '^[a-f0-9]{64}$' AND evidence_digest<>repeat('0',64)),
 reason_code text NOT NULL CHECK(reason_code IN ('suspected_compromise','confirmed_compromise','custody_lost','identity_uncertain')),
 actor_id uuid NOT NULL,revoked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,key_digest),
 FOREIGN KEY(tenant_id,actor_id) REFERENCES public.tenant_memberships(tenant_id,user_id)
);
REVOKE ALL ON private.privacy_case_key_versions,private.privacy_compromised_keys FROM PUBLIC,profitpilot_app;
CREATE TRIGGER privacy_case_key_versions_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON private.privacy_case_key_versions FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();
CREATE TRIGGER privacy_compromised_keys_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON private.privacy_compromised_keys FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();

-- A common tenant-specific mutex precedes case/release row locks on every
-- protected new release, key version, dispatch and receipt path.
CREATE FUNCTION private.lock_privacy_key_lifecycle(p_tenant uuid)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
BEGIN
 IF p_tenant IS NULL OR private.current_tenant_id() IS DISTINCT FROM p_tenant
 OR coalesce(private.current_actor_role(),'') NOT IN ('owner','admin')
 OR private.lock_tenant_available(p_tenant) IS DISTINCT FROM true
 THEN RAISE EXCEPTION 'Privacy keys unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('profitpilot-privacy-key-lifecycle:'||p_tenant::text,0));
END $fn$;

CREATE FUNCTION private.assert_privacy_case_keys(p_tenant uuid,p_case uuid,p_recipient text,p_sender text,p_signer text)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE k private.privacy_case_key_versions%ROWTYPE;
BEGIN
 IF EXISTS(SELECT 1 FROM private.privacy_compromised_keys WHERE tenant_id=p_tenant AND key_digest IN (p_recipient,p_sender,p_signer))
 THEN RAISE EXCEPTION 'Privacy key compromised or withdrawn' USING ERRCODE='42501'; END IF;
 SELECT v.* INTO k FROM private.privacy_case_key_versions v WHERE v.tenant_id=p_tenant AND v.case_id=p_case
 AND NOT EXISTS(SELECT 1 FROM private.privacy_case_key_versions n WHERE n.tenant_id=v.tenant_id AND n.case_id=v.case_id AND n.previous_order_id=v.order_id);
 IF FOUND AND (k.recipient_key_digest IS DISTINCT FROM p_recipient OR k.sender_key_digest IS DISTINCT FROM p_sender
 OR (p_signer IS NOT NULL AND k.receipt_key_digest IS DISTINCT FROM p_signer)
 OR EXISTS(SELECT 1 FROM private.privacy_compromised_keys WHERE tenant_id=p_tenant AND key_digest=k.receipt_key_digest))
 THEN RAISE EXCEPTION 'Privacy key version no longer current' USING ERRCODE='42501'; END IF;
 -- Legacy candidates without a registered generation remain synthetic-only.
END $fn$;

CREATE FUNCTION private.privacy_case_key_scope(p_tenant uuid,p_case uuid,p_order uuid,p_previous uuid,p_recipient text,p_sender text,p_signer text,p_evidence text)
RETURNS text LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE h text; current_key private.privacy_case_key_versions%ROWTYPE; case_row private.privacy_rights_cases%ROWTYPE;
BEGIN
 PERFORM private.lock_privacy_key_lifecycle(p_tenant);
 IF p_case IS NULL OR p_order IS NULL OR p_previous=p_order OR p_recipient IS NOT DISTINCT FROM p_sender
 OR p_signer IS NOT DISTINCT FROM p_recipient OR p_signer IS NOT DISTINCT FROM p_sender
 THEN RAISE EXCEPTION 'Privacy key scope denied' USING ERRCODE='42501'; END IF;
 FOREACH h IN ARRAY ARRAY[p_recipient,p_sender,p_signer,p_evidence] LOOP
  IF h IS NULL OR h !~ '^[a-f0-9]{64}$' OR h=repeat('0',64) THEN RAISE EXCEPTION 'Privacy key scope denied' USING ERRCODE='42501'; END IF;
 END LOOP;
 SELECT * INTO case_row FROM private.privacy_rights_cases WHERE tenant_id=p_tenant AND id=p_case FOR UPDATE;
 IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM private.privacy_rights_outcomes WHERE tenant_id=p_tenant AND case_id=p_case AND reason_code<>'identity_not_verified')
 THEN RAISE EXCEPTION 'Privacy key case unavailable' USING ERRCODE='42501'; END IF;
 SELECT v.* INTO current_key FROM private.privacy_case_key_versions v WHERE v.tenant_id=p_tenant AND v.case_id=p_case
 AND NOT EXISTS(SELECT 1 FROM private.privacy_case_key_versions n WHERE n.tenant_id=v.tenant_id AND n.case_id=v.case_id AND n.previous_order_id=v.order_id);
 IF current_key.order_id IS DISTINCT FROM p_previous
 OR (current_key.order_id IS NOT NULL AND ROW(current_key.recipient_key_digest,current_key.sender_key_digest,current_key.receipt_key_digest) IS NOT DISTINCT FROM ROW(p_recipient,p_sender,p_signer))
 OR EXISTS(SELECT 1 FROM private.privacy_compromised_keys WHERE tenant_id=p_tenant AND key_digest IN (p_recipient,p_sender,p_signer))
 -- A fingerprint retired from this case cannot be reintroduced or moved to
 -- another role within this case; unchanged keys may carry forward.
 OR EXISTS(SELECT 1 FROM private.privacy_case_key_versions v WHERE v.tenant_id=p_tenant AND v.case_id=p_case
 AND ((v.recipient_key_digest=p_recipient AND current_key.recipient_key_digest IS DISTINCT FROM p_recipient)
 OR (v.sender_key_digest=p_sender AND current_key.sender_key_digest IS DISTINCT FROM p_sender)
 OR (v.receipt_key_digest=p_signer AND current_key.receipt_key_digest IS DISTINCT FROM p_signer)
 OR v.recipient_key_digest IN (p_sender,p_signer) OR v.sender_key_digest IN (p_recipient,p_signer) OR v.receipt_key_digest IN (p_recipient,p_sender)))
 THEN RAISE EXCEPTION 'Privacy key generation unavailable' USING ERRCODE='42501'; END IF;
 RETURN encode(public.digest(convert_to(jsonb_build_array('profitpilot-privacy-key-version-v1',p_tenant,p_case,p_order,p_previous,case_row.kind,case_row.channel,case_row.opened_by,case_row.authority_digest,p_recipient,p_sender,p_signer,p_evidence)::text,'UTF8'),'sha256'),'hex');
END $fn$;

CREATE FUNCTION private.record_privacy_case_keys(
 p_tenant uuid,p_case uuid,p_order uuid,p_previous uuid,p_recipient text,p_sender text,p_signer text,p_evidence text,p_scope text,p_step text,
 p_auth bigint,p_iat bigint,p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE actor uuid;
BEGIN
 actor:=private.security_work_actor(p_tenant,p_order,'privileged_operation',p_scope,p_step,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 IF private.privacy_case_key_scope(p_tenant,p_case,p_order,p_previous,p_recipient,p_sender,p_signer,p_evidence) IS DISTINCT FROM p_scope
 THEN RAISE EXCEPTION 'Privacy key scope changed' USING ERRCODE='42501'; END IF;
 PERFORM private.record_security_work(p_tenant,p_order,'privileged_operation',p_scope,p_step,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 IF p_step='consume' THEN
  INSERT INTO private.privacy_case_key_versions(tenant_id,case_id,order_id,previous_order_id,recipient_key_digest,sender_key_digest,receipt_key_digest,evidence_digest)
  VALUES(p_tenant,p_case,p_order,p_previous,p_recipient,p_sender,p_signer,p_evidence);
  INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id)
  VALUES(p_tenant,actor,'privacy_key_version_activated','privacy_rights_case',p_case);
 END IF;
END $fn$;

-- Immediate protective revocation, even if the suspect fingerprint has not
-- been enrolled yet. A fingerprint is permanently denied within this tenant.
CREATE FUNCTION private.revoke_privacy_key(
 p_tenant uuid,p_key_digest text,p_reason text,p_evidence text,p_scope text,
 p_auth bigint,p_iat bigint,p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE actor uuid;
BEGIN
 IF p_key_digest IS NULL OR p_key_digest !~ '^[a-f0-9]{64}$' OR p_key_digest=repeat('0',64)
 OR p_evidence IS NULL OR p_evidence !~ '^[a-f0-9]{64}$' OR p_evidence=repeat('0',64)
 OR p_reason IS NULL OR p_reason NOT IN ('suspected_compromise','confirmed_compromise','custody_lost','identity_uncertain')
 OR p_scope IS DISTINCT FROM encode(public.digest(convert_to('profitpilot-privacy-key-revoke-v1'||E'\n'||p_key_digest||E'\n'||p_reason||E'\n'||p_evidence,'UTF8'),'sha256'),'hex')
 THEN RAISE EXCEPTION 'Privacy key revocation denied' USING ERRCODE='42501'; END IF;
 actor:=private.sensitive_api_actor(p_tenant,p_tenant,'privacy_key_revoke',p_scope,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 PERFORM private.lock_privacy_key_lifecycle(p_tenant);
 PERFORM private.sensitive_api_fresh(p_auth,p_expires);
 INSERT INTO private.privacy_compromised_keys(tenant_id,key_digest,reason_code,evidence_digest,actor_id)
 VALUES(p_tenant,p_key_digest,p_reason,p_evidence,actor);
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id)
 VALUES(p_tenant,actor,'privacy_key_revoked','tenant',p_tenant);
END $fn$;
REVOKE ALL ON FUNCTION private.lock_privacy_key_lifecycle(uuid),private.assert_privacy_case_keys(uuid,uuid,text,text,text),
 private.privacy_case_key_scope(uuid,uuid,uuid,uuid,text,text,text,text),
 private.record_privacy_case_keys(uuid,uuid,uuid,uuid,text,text,text,text,text,text,bigint,bigint,text,bigint,text,text,text),
 private.revoke_privacy_key(uuid,text,text,text,text,bigint,bigint,text,bigint,text,text,text) FROM PUBLIC,profitpilot_app;
CREATE OR REPLACE FUNCTION private.privacy_delivery_scope(
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
 PERFORM private.lock_privacy_key_lifecycle(p_tenant);
 PERFORM private.assert_privacy_case_keys(p_tenant,p_case,p_recipient,p_sender,NULL);
 SELECT * INTO c FROM private.privacy_rights_cases WHERE tenant_id=p_tenant AND id=p_case FOR UPDATE;
 IF NOT FOUND OR (c.channel='self' AND p_type<>'self') OR (c.channel='verified_staff_intake' AND p_type='self')
 THEN RAISE EXCEPTION 'Privacy delivery denied' USING ERRCODE='42501'; END IF;
 SELECT * INTO o FROM private.privacy_rights_outcomes WHERE tenant_id=p_tenant AND case_id=p_case;
 IF NOT FOUND OR o.actor_id=c.opened_by OR o.reason_code='identity_not_verified'
 OR NOT EXISTS(SELECT 1 FROM private.privacy_rights_acknowledgements WHERE tenant_id=p_tenant AND case_id=p_case)
 THEN RAISE EXCEPTION 'Privacy delivery denied' USING ERRCODE='42501'; END IF;
 RETURN encode(public.digest(convert_to(jsonb_build_array('profitpilot-privacy-delivery-v1',p_tenant,p_case,p_order,c.kind,c.channel,c.opened_by,c.authority_digest,o.actor_id,o.status,o.reason_code,o.evidence_digest,p_type,p_recipient,p_sender,p_authority,p_redaction,p_response,p_envelope)::text,'UTF8'),'sha256'),'hex');
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
 PERFORM private.lock_privacy_key_lifecycle(p_tenant);
 SELECT * INTO a FROM private.privacy_delivery_authorizations WHERE tenant_id=p_tenant AND case_id=p_case AND order_id=p_release FOR UPDATE;
 IF NOT FOUND OR p_signer IN (a.sender_key_digest,a.recipient_key_digest)
 THEN RAISE EXCEPTION 'Privacy receipt denied' USING ERRCODE='42501'; END IF;
 PERFORM private.assert_privacy_case_keys(p_tenant,p_case,a.recipient_key_digest,a.sender_key_digest,p_signer);
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


CREATE OR REPLACE FUNCTION private.record_privacy_dispatch(
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
 PERFORM private.lock_privacy_key_lifecycle(p_tenant);
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
  PERFORM private.assert_privacy_case_keys(p_tenant,p_case,a.recipient_key_digest,a.sender_key_digest,p_signer);
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
  ) all_entries LIMIT 100001
 ), hashes AS (SELECT kind,encode(hash,'hex') AS h FROM entries)
 SELECT count(*),CASE WHEN count(*)<=100000 THEN encode(public.digest(convert_to('profitpilot-sensitive-recovery-v9:'||coalesce(string_agg(kind||':'||h,',' ORDER BY kind COLLATE "C",h COLLATE "C"),''),'UTF8'),'sha256'),'hex') END
 INTO total,result FROM hashes;
 IF total>100000 OR result IS NULL THEN RAISE EXCEPTION 'Sensitive recovery inventory exceeds reviewed capacity' USING ERRCODE='54000'; END IF;
 RETURN result;
END $fn$;

REVOKE ALL ON FUNCTION private.sensitive_recovery_fingerprint() FROM PUBLIC,profitpilot_app;
CREATE OR REPLACE FUNCTION private.verify_security_catalog()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT digest=private.security_catalog_digest() FROM private.security_catalog_baseline WHERE revision=62),false)
$fn$;
INSERT INTO private.security_catalog_baseline(singleton,revision,digest) VALUES(true,62,private.security_catalog_digest());
COMMIT;

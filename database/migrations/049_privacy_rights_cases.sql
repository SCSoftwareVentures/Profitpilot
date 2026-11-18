-- Privacy rights case lifecycle; no underlying raw personal-data grant.
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
 IF p_action IS NULL OR p_action NOT IN ('payroll_submit','payroll_read','account_read','account_correct_email','invoice_disposal_preview','privacy_case_request','privacy_case_status','privacy_case_intake','privacy_case_acknowledge','privacy_case_resolve','privacy_case_refuse')
 OR (p_action IN ('privacy_case_intake','privacy_case_acknowledge','privacy_case_resolve','privacy_case_refuse') AND actor_role NOT IN ('owner','admin'))
 OR (p_action='payroll_submit' AND actor_role NOT IN ('owner','admin','analyst'))
 OR (p_action='payroll_read' AND actor_role NOT IN ('owner','admin','reviewer'))
 OR (p_action='invoice_disposal_preview' AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('account_read','account_correct_email') AND p_target<>p_tenant)
 THEN RAISE EXCEPTION 'Sensitive operation denied' USING ERRCODE='42501'; END IF;
 now_s:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 IF p_scope IS NULL OR p_scope !~ '^[a-f0-9]{64}$'
 OR (p_action IN ('account_correct_email','privacy_case_request','privacy_case_intake','privacy_case_resolve','privacy_case_refuse') AND p_scope=repeat('0',64))
 OR (p_action NOT IN ('account_correct_email','privacy_case_request','privacy_case_intake','privacy_case_resolve','privacy_case_refuse') AND p_scope<>repeat('0',64))
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

CREATE TABLE private.privacy_rights_cases(
 tenant_id uuid NOT NULL REFERENCES public.tenants(id),
 id uuid NOT NULL,
 kind text NOT NULL CHECK(kind IN ('access','correction','disposal','complaint')),
 channel text NOT NULL CHECK(channel IN ('self','verified_staff_intake')),
 opened_by uuid NOT NULL,
 authority_digest text CHECK(authority_digest ~ '^[a-f0-9]{64}$' AND authority_digest<>repeat('0',64)),
 opened_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),
 FOREIGN KEY(tenant_id,opened_by) REFERENCES public.tenant_memberships(tenant_id,user_id),
 CHECK((channel='self' AND authority_digest IS NULL) OR (channel='verified_staff_intake' AND authority_digest IS NOT NULL))
);
CREATE TABLE private.privacy_rights_acknowledgements(
 tenant_id uuid NOT NULL,case_id uuid NOT NULL,actor_id uuid NOT NULL,
 acknowledged_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,case_id),
 FOREIGN KEY(tenant_id,case_id) REFERENCES private.privacy_rights_cases(tenant_id,id),
 FOREIGN KEY(tenant_id,actor_id) REFERENCES public.tenant_memberships(tenant_id,user_id)
);
CREATE TABLE private.privacy_rights_outcomes(
 tenant_id uuid NOT NULL,case_id uuid NOT NULL,actor_id uuid NOT NULL,
 status text NOT NULL CHECK(status IN ('resolved','refused')),
 reason_code text NOT NULL CHECK(reason_code IN ('fulfilled','partially_fulfilled','lawful_refusal','retention_required','identity_not_verified')),
 evidence_digest text NOT NULL CHECK(evidence_digest ~ '^[a-f0-9]{64}$' AND evidence_digest<>repeat('0',64)),
 decided_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,case_id),
 FOREIGN KEY(tenant_id,case_id) REFERENCES private.privacy_rights_cases(tenant_id,id),
 FOREIGN KEY(tenant_id,actor_id) REFERENCES public.tenant_memberships(tenant_id,user_id),
 CHECK((status='resolved' AND reason_code IN ('fulfilled','partially_fulfilled')) OR (status='refused' AND reason_code IN ('lawful_refusal','retention_required','identity_not_verified')))
);
REVOKE ALL ON private.privacy_rights_cases,private.privacy_rights_acknowledgements,private.privacy_rights_outcomes FROM PUBLIC,profitpilot_app;
CREATE TRIGGER privacy_rights_case_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON private.privacy_rights_cases FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();
CREATE TRIGGER privacy_rights_ack_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON private.privacy_rights_acknowledgements FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();
CREATE TRIGGER privacy_rights_outcome_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON private.privacy_rights_outcomes FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();

-- Scope digest canonicalizes the exact semantic input. No free text,
-- subject identifiers, request documents or response content are stored.
CREATE FUNCTION private.privacy_rights_scope(p_action text,p_kind text,p_reason text,p_evidence text)
RETURNS text LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $fn$
 SELECT encode(public.digest(convert_to('privacy-rights-v1'||E'\n'||p_action||E'\n'||coalesce(p_kind,'')||E'\n'||coalesce(p_reason,'')||E'\n'||coalesce(p_evidence,''),'UTF8'),'sha256'),'hex')
$fn$;

CREATE FUNCTION private.api_privacy_rights_case(
 p_tenant uuid,p_case uuid,p_action text,p_scope text,p_auth bigint,p_iat bigint,
 p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text,
 p_kind text,p_reason text,p_evidence text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE actor uuid; c private.privacy_rights_cases%ROWTYPE; result jsonb; actor_role text; case_count integer;
BEGIN
 IF p_action IS NULL OR p_action NOT IN ('privacy_case_request','privacy_case_status','privacy_case_intake','privacy_case_acknowledge','privacy_case_resolve','privacy_case_refuse') THEN RAISE EXCEPTION 'Privacy case denied' USING ERRCODE='42501'; END IF;
 actor:=private.sensitive_api_actor(p_tenant,p_case,p_action,p_scope,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 actor_role:=private.current_actor_role();
 IF p_action IN ('privacy_case_request','privacy_case_intake') THEN
  IF p_kind IS NULL OR p_kind NOT IN ('access','correction','disposal','complaint') OR p_reason IS NOT NULL
  OR (p_action='privacy_case_request' AND p_evidence IS NOT NULL)
  OR (p_action='privacy_case_intake' AND (p_evidence IS NULL OR p_evidence !~ '^[a-f0-9]{64}$' OR p_evidence=repeat('0',64)))
  OR p_scope IS DISTINCT FROM private.privacy_rights_scope(p_action,p_kind,p_reason,p_evidence)
  THEN RAISE EXCEPTION 'Privacy case input denied' USING ERRCODE='42501'; END IF;
  -- Bound case creation independently of HTTP/IP throttling.
  PERFORM pg_advisory_xact_lock(hashtextextended('privacy-case:'||p_tenant::text,0));
  SELECT count(*) INTO case_count FROM (SELECT 1 FROM private.privacy_rights_cases WHERE tenant_id=p_tenant AND opened_at>clock_timestamp()-interval '1 day' LIMIT 501) q;
  IF case_count>=500 OR (SELECT count(*) FROM (SELECT 1 FROM private.privacy_rights_cases WHERE tenant_id=p_tenant AND opened_by=actor AND opened_at>clock_timestamp()-interval '1 day' LIMIT 51) q)>=50 THEN
   RAISE EXCEPTION 'Privacy case intake capacity reached; use assisted channel' USING ERRCODE='P4501'; END IF;
  INSERT INTO private.privacy_rights_cases(tenant_id,id,kind,channel,opened_by,authority_digest)
  VALUES(p_tenant,p_case,p_kind,CASE WHEN p_action='privacy_case_request' THEN 'self' ELSE 'verified_staff_intake' END,actor,p_evidence);
 ELSE
  SELECT * INTO c FROM private.privacy_rights_cases WHERE tenant_id=p_tenant AND id=p_case FOR UPDATE;
  IF NOT FOUND OR (actor_role NOT IN ('owner','admin') AND (c.channel<>'self' OR c.opened_by<>actor)) THEN
   RAISE EXCEPTION 'Privacy case denied' USING ERRCODE='42501'; END IF;
  IF p_kind IS NOT NULL THEN RAISE EXCEPTION 'Privacy case input denied' USING ERRCODE='42501'; END IF;
  IF p_action IN ('privacy_case_status','privacy_case_acknowledge') THEN
   IF p_reason IS NOT NULL OR p_evidence IS NOT NULL THEN RAISE EXCEPTION 'Privacy case input denied' USING ERRCODE='42501'; END IF;
   IF p_action='privacy_case_acknowledge' THEN
    IF EXISTS(SELECT 1 FROM private.privacy_rights_outcomes WHERE tenant_id=p_tenant AND case_id=p_case) THEN RAISE EXCEPTION 'Privacy case already decided' USING ERRCODE='23505'; END IF;
    INSERT INTO private.privacy_rights_acknowledgements(tenant_id,case_id,actor_id) VALUES(p_tenant,p_case,actor);
   END IF;
  ELSE
   IF c.opened_by=actor OR NOT EXISTS(SELECT 1 FROM private.privacy_rights_acknowledgements WHERE tenant_id=p_tenant AND case_id=p_case)
   OR p_evidence IS NULL OR p_evidence !~ '^[a-f0-9]{64}$' OR p_evidence=repeat('0',64)
   OR p_reason IS NULL OR (p_action='privacy_case_resolve' AND p_reason NOT IN ('fulfilled','partially_fulfilled'))
   OR (p_action='privacy_case_refuse' AND p_reason NOT IN ('lawful_refusal','retention_required','identity_not_verified'))
   OR p_scope IS DISTINCT FROM private.privacy_rights_scope(p_action,p_kind,p_reason,p_evidence)
   THEN RAISE EXCEPTION 'Independent evidenced decision required' USING ERRCODE='42501'; END IF;
   INSERT INTO private.privacy_rights_outcomes(tenant_id,case_id,actor_id,status,reason_code,evidence_digest)
   VALUES(p_tenant,p_case,actor,CASE WHEN p_action='privacy_case_resolve' THEN 'resolved' ELSE 'refused' END,p_reason,p_evidence);
  END IF;
 END IF;
 PERFORM private.sensitive_api_fresh(p_auth,p_expires);
 IF p_action<>'privacy_case_status' THEN
  INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id)
  VALUES(p_tenant,actor,p_action,'privacy_rights_case',p_case);
 END IF;
 SELECT jsonb_build_object('caseId',c2.id,'kind',c2.kind,'status',coalesce(o.status,CASE WHEN a.case_id IS NULL THEN 'received' ELSE 'acknowledged' END),
  'receivedAt',c2.opened_at,'acknowledgedAt',a.acknowledged_at,'decidedAt',o.decided_at,'reasonCode',o.reason_code,
  'internalReviewTarget',c2.opened_at+interval '20 days','escalationDue',o.case_id IS NULL AND clock_timestamp()>=c2.opened_at+interval '20 days')
 INTO result FROM private.privacy_rights_cases c2
 LEFT JOIN private.privacy_rights_acknowledgements a ON a.tenant_id=c2.tenant_id AND a.case_id=c2.id
 LEFT JOIN private.privacy_rights_outcomes o ON o.tenant_id=c2.tenant_id AND o.case_id=c2.id
 WHERE c2.tenant_id=p_tenant AND c2.id=p_case;
 RETURN result;
END $fn$;
CREATE INDEX privacy_rights_case_intake_idx ON private.privacy_rights_cases(tenant_id,opened_at);
REVOKE ALL ON FUNCTION private.privacy_rights_scope(text,text,text,text),private.api_privacy_rights_case(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text,text,text,text) FROM PUBLIC,profitpilot_app;
GRANT EXECUTE ON FUNCTION private.api_privacy_rights_case(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text,text,text,text) TO profitpilot_app;
CREATE OR REPLACE FUNCTION private.verify_security_catalog()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT digest=private.security_catalog_digest() FROM private.security_catalog_baseline WHERE revision=49),false)
$fn$;
INSERT INTO private.security_catalog_baseline(singleton,revision,digest) VALUES(true,49,private.security_catalog_digest());
COMMIT;

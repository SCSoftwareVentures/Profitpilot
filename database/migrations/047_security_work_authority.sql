-- Private, scoped and expiring work authorisation receipts.
-- No privileges, data disclosure or disposal are granted by these receipts.
BEGIN;
DO $check$ BEGIN
 IF private.verify_security_catalog() IS DISTINCT FROM true THEN RAISE EXCEPTION 'Prior security catalog does not verify'; END IF;
END $check$;

CREATE TABLE private.security_work_orders(
 tenant_id uuid NOT NULL REFERENCES public.tenants(id),
 id uuid NOT NULL DEFAULT gen_random_uuid(),
 kind text NOT NULL CHECK(kind IN ('privacy_access','privacy_correction','privacy_disposal','privileged_operation','incident_recovery')),
 scope_digest text NOT NULL CHECK(scope_digest ~ '^[a-f0-9]{64}$' AND scope_digest<>repeat('0',64)),
 requested_by uuid NOT NULL,
 requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),
 FOREIGN KEY(tenant_id,requested_by) REFERENCES public.tenant_memberships(tenant_id,user_id)
);
CREATE TABLE private.security_work_decisions(
 tenant_id uuid NOT NULL,
 order_id uuid NOT NULL,
 decided_by uuid NOT NULL,
 decision text NOT NULL CHECK(decision IN ('approved','rejected')),
 decided_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,order_id),
 FOREIGN KEY(tenant_id,order_id) REFERENCES private.security_work_orders(tenant_id,id),
 FOREIGN KEY(tenant_id,decided_by) REFERENCES public.tenant_memberships(tenant_id,user_id),
 CHECK(expires_at>=decided_at AND expires_at<=decided_at+interval '15 minutes')
);
CREATE TABLE private.security_work_consumptions(
 tenant_id uuid NOT NULL,
 order_id uuid NOT NULL,
 consumed_by uuid NOT NULL,
 consumed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,order_id),
 FOREIGN KEY(tenant_id,order_id) REFERENCES private.security_work_decisions(tenant_id,order_id),
 FOREIGN KEY(tenant_id,consumed_by) REFERENCES public.tenant_memberships(tenant_id,user_id)
);
REVOKE ALL ON private.security_work_orders,private.security_work_decisions,private.security_work_consumptions FROM PUBLIC,profitpilot_app;
CREATE TRIGGER security_work_order_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON private.security_work_orders FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();
CREATE TRIGGER security_work_decision_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON private.security_work_decisions FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();
CREATE TRIGGER security_work_consumption_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON private.security_work_consumptions FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();

-- Trusted service must verify MFA before signing. The domain binds the
-- operation, exact case ID, scope, tenant, actor and session; no raw JWTs.
CREATE FUNCTION private.security_work_actor(
 p_tenant uuid,p_order uuid,p_kind text,p_scope text,p_step text,p_auth bigint,p_iat bigint,
 p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text)
RETURNS uuid LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE actor uuid; subject text; now_s bigint; key_bytes bytea; expected text;
BEGIN
 actor:=private.payroll_review_actor(p_tenant,true);
 IF private.current_actor_role() IS NULL OR private.current_actor_role() NOT IN ('owner','admin') THEN
  RAISE EXCEPTION 'Security work authority denied' USING ERRCODE='42501'; END IF;
 subject:=nullif(current_setting('app.tenant_subject',true),'');
 now_s:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 IF p_order IS NULL OR p_kind NOT IN ('privacy_access','privacy_correction','privacy_disposal','privileged_operation','incident_recovery') OR p_kind IS NULL
 OR p_scope IS NULL OR p_scope !~ '^[a-f0-9]{64}$' OR p_scope=repeat('0',64)
 OR p_step IS NULL OR p_step NOT IN ('request','approve','reject','consume')
 OR p_auth IS NULL OR p_auth<=0 OR p_auth<now_s-300 OR p_auth>now_s+5
 OR p_iat IS NULL OR p_iat<now_s-905 OR p_iat>now_s+5 OR p_auth>p_iat+5
 OR p_session IS NULL OR p_session !~ '^[a-f0-9]{64}$'
 OR p_expires IS NULL OR p_expires<now_s OR p_expires>now_s+30
 OR p_nonce IS NULL OR p_nonce !~ '^[a-f0-9]{32}$'
 OR p_key IS NULL OR p_key !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$'
 OR p_signature IS NULL OR p_signature !~ '^[a-f0-9]{64}$'
 THEN RAISE EXCEPTION 'Security work authority denied' USING ERRCODE='42501'; END IF;
 SELECT secret INTO key_bytes FROM private.tenant_context_keys WHERE key_id=p_key AND active FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Security work authority denied' USING ERRCODE='42501'; END IF;
 expected:=encode(public.hmac(convert_to('profitpilot-security-work-v1'||E'\n'||p_tenant||E'\n'||p_order||E'\n'||p_kind||E'\n'||p_scope||E'\n'||p_step||E'\n'||subject||E'\n'||p_auth||E'\n'||p_iat||E'\n'||p_session||E'\n'||p_expires||E'\n'||p_nonce||E'\n'||p_key,'UTF8'),key_bytes,'sha256'),'hex');
 IF expected IS DISTINCT FROM p_signature
 OR EXISTS(SELECT 1 FROM private.identity_session_cutoffs WHERE user_id=actor AND revoked_through>=p_auth)
 OR EXISTS(SELECT 1 FROM private.revoked_identity_sessions WHERE user_id=actor AND session_digest=p_session)
 THEN RAISE EXCEPTION 'Security work authority denied' USING ERRCODE='42501'; END IF;
 RETURN actor;
END $fn$;

CREATE FUNCTION private.record_security_work(
 p_tenant uuid,p_order uuid,p_kind text,p_scope text,p_step text,p_auth bigint,p_iat bigint,
 p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE actor uuid; o private.security_work_orders%ROWTYPE; d private.security_work_decisions%ROWTYPE; at_time timestamptz;
BEGIN
 actor:=private.security_work_actor(p_tenant,p_order,p_kind,p_scope,p_step,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 IF p_step='request' THEN
  INSERT INTO private.security_work_orders(tenant_id,id,kind,scope_digest,requested_by) VALUES(p_tenant,p_order,p_kind,p_scope,actor);
 ELSE
  SELECT * INTO o FROM private.security_work_orders WHERE tenant_id=p_tenant AND id=p_order FOR UPDATE;
  IF NOT FOUND OR o.kind IS DISTINCT FROM p_kind OR o.scope_digest IS DISTINCT FROM p_scope THEN
   RAISE EXCEPTION 'Security work authority denied' USING ERRCODE='42501'; END IF;
  IF p_step IN ('approve','reject') THEN
   IF o.requested_by=actor OR clock_timestamp()>o.requested_at+interval '24 hours' THEN
    RAISE EXCEPTION 'Independent and timely decision required' USING ERRCODE='42501'; END IF;
   PERFORM 1 FROM public.tenant_memberships m JOIN public.users u ON u.id=m.user_id
    WHERE m.tenant_id=p_tenant AND m.user_id=o.requested_by AND m.status='active' AND m.role IN ('owner','admin') AND u.status='active' FOR SHARE OF m,u;
   IF NOT FOUND THEN RAISE EXCEPTION 'Requester no longer authorised' USING ERRCODE='42501'; END IF;
   at_time:=clock_timestamp();
   INSERT INTO private.security_work_decisions(tenant_id,order_id,decided_by,decision,decided_at,expires_at)
    VALUES(p_tenant,p_order,actor,CASE WHEN p_step='approve' THEN 'approved' ELSE 'rejected' END,at_time,at_time+interval '15 minutes');
  ELSE
   SELECT * INTO d FROM private.security_work_decisions WHERE tenant_id=p_tenant AND order_id=p_order;
   IF NOT FOUND OR d.decision<>'approved' OR d.expires_at<=clock_timestamp() OR o.requested_by<>actor OR d.decided_by=actor THEN
    RAISE EXCEPTION 'Work approval unavailable' USING ERRCODE='42501'; END IF;
   PERFORM 1 FROM public.tenant_memberships m JOIN public.users u ON u.id=m.user_id
    WHERE m.tenant_id=p_tenant AND m.user_id=d.decided_by AND m.status='active' AND m.role IN ('owner','admin') AND u.status='active' FOR SHARE OF m,u;
   IF NOT FOUND THEN RAISE EXCEPTION 'Approver no longer authorised' USING ERRCODE='42501'; END IF;
   IF d.expires_at<=clock_timestamp() THEN RAISE EXCEPTION 'Work approval expired' USING ERRCODE='42501'; END IF;
   INSERT INTO private.security_work_consumptions(tenant_id,order_id,consumed_by) VALUES(p_tenant,p_order,actor);
  END IF;
 END IF;
 IF floor(extract(epoch FROM clock_timestamp()))::bigint>p_expires OR floor(extract(epoch FROM clock_timestamp()))::bigint>p_auth+300 THEN
  RAISE EXCEPTION 'Work attestation expired' USING ERRCODE='42501'; END IF;
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,metadata)
 VALUES(p_tenant,actor,'security_work_'||p_step,'security_work_order',p_order,jsonb_build_object('kind',p_kind,'scopeDigest',p_scope));
END $fn$;
REVOKE ALL ON FUNCTION private.security_work_actor(uuid,uuid,text,text,text,bigint,bigint,text,bigint,text,text,text),private.record_security_work(uuid,uuid,text,text,text,bigint,bigint,text,bigint,text,text,text) FROM PUBLIC,profitpilot_app;

-- More conservative reference classification in both JSON and CSV paths.
-- Preserve existing structured amount/date/UUID exceptions in the caller.
CREATE OR REPLACE FUNCTION private.import_reference_safe(p_value text,p_max integer,p_filename boolean DEFAULT false)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $fn$
BEGIN
 IF p_value IS NULL OR p_max IS NULL OR p_filename IS NULL OR p_max NOT BETWEEN 1 AND 512
 OR char_length(p_value)>p_max OR p_value IS DISTINCT FROM normalize(p_value,NFKC)
 OR p_value IS DISTINCT FROM btrim(p_value)
 OR p_value !~ '^[A-Za-z0-9 ._:/&''()-]*$'
 OR p_value ~ '^[=+@-]'
 OR (p_filename AND (strpos(p_value,'/')>0 OR strpos(p_value,':')>0 OR p_value IN ('.','..')))
 OR p_value ~* '(^|[^A-Za-z0-9])(tfn|tax[ _-]*file|medicare|passport|bank[ _-]*account|bsb|card[ _-]*number|credit[ _-]*card|cvv|cvc|password|access[ _-]*code|payslip|date[ _-]*of[ _-]*birth|dob|driver[ _-]*licen[cs]e|health[ _-]*record|medical[ _-]*record|super[ _-]*member|account[ _-]*number|routing[ _-]*number|api[ _-]*key|secret[ _-]*key|bearer[ _-]*token|private[ _-]*key)([^A-Za-z0-9]|$)'
 OR p_value ~ '[0-9]([ .:/()-]*[0-9]){7,}'
 THEN RETURN false; END IF;
 RETURN true;
END $fn$;
CREATE OR REPLACE FUNCTION private.verify_security_catalog()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT digest=private.security_catalog_digest() FROM private.security_catalog_baseline WHERE revision=47),false)
$fn$;
INSERT INTO private.security_catalog_baseline(singleton,revision,digest) VALUES(true,47,private.security_catalog_digest());
COMMIT;

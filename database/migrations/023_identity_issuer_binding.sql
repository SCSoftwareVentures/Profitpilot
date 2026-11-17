-- Explicit issuer/subject provenance; no trust-on-first-login or automatic backfill.
BEGIN;
ALTER TABLE public.users ADD COLUMN auth_issuer text CHECK(
 auth_issuer IS NULL OR (length(auth_issuer) BETWEEN 9 AND 512 AND auth_issuer ~ '^https://[^[:space:]?#@]+$')
);
CREATE FUNCTION private.immutable_identity_binding() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
BEGIN
 IF NEW.auth_subject IS DISTINCT FROM OLD.auth_subject OR (OLD.auth_issuer IS NOT NULL AND NEW.auth_issuer IS DISTINCT FROM OLD.auth_issuer) THEN
  RAISE EXCEPTION 'Identity binding cannot be changed by ordinary update' USING ERRCODE='55000';
 END IF;
 RETURN NEW;
END
$fn$;
ALTER FUNCTION private.immutable_identity_binding() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.immutable_identity_binding() FROM PUBLIC,profitpilot_app;
CREATE TRIGGER immutable_identity_binding BEFORE UPDATE ON public.users FOR EACH ROW EXECUTE FUNCTION private.immutable_identity_binding();
-- Existing unbound identities must be linked by a trusted provisioning operator after proof of provenance.
-- Only the verified issuer may register/reuse a session for a bound account.
CREATE FUNCTION private.register_bound_auth_session(p_jti text,p_subject text,p_issuer text,p_issued_at timestamptz,p_expires_at timestamptz)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
BEGIN
 IF p_issuer IS NULL THEN RETURN; END IF;
 PERFORM 1 FROM public.users WHERE auth_subject=p_subject AND auth_issuer=p_issuer AND status='active' FOR SHARE;
 IF NOT FOUND THEN RETURN; END IF;
 PERFORM private.register_auth_session(p_jti,p_subject,p_issued_at,p_expires_at);
END
$fn$;
ALTER FUNCTION private.register_bound_auth_session(text,text,text,timestamptz,timestamptz) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.register_bound_auth_session(text,text,text,timestamptz,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.register_bound_auth_session(text,text,text,timestamptz,timestamptz) TO profitpilot_app;
CREATE FUNCTION private.is_bound_auth_session_revoked(p_jti text,p_subject text,p_issuer text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
 SELECT NOT EXISTS(SELECT 1 FROM public.users WHERE auth_subject=p_subject AND auth_issuer=p_issuer AND status='active')
 OR private.is_auth_session_revoked(p_jti,p_subject)
$fn$;
ALTER FUNCTION private.is_bound_auth_session_revoked(text,text,text) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.is_bound_auth_session_revoked(text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.is_bound_auth_session_revoked(text,text,text) TO profitpilot_app;
REVOKE EXECUTE ON FUNCTION private.register_auth_session(text,text,timestamptz,timestamptz),private.is_auth_session_revoked(text,text) FROM profitpilot_app;
-- Unbound legacy user sessions cannot be grandfathered in after migration.
UPDATE private.auth_sessions SET revoked_at=clock_timestamp(),revocation_reason='issuer_binding_required' WHERE revoked_at IS NULL;
-- Old grants were prepared without persisted issuer proof. Never allow execution.
UPDATE private.provider_erasure_grants SET invalidated_at=clock_timestamp() WHERE consumed_at IS NULL AND invalidated_at IS NULL;
CREATE OR REPLACE FUNCTION private.provider_erasure_context(p_user uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
DECLARE account public.users%ROWTYPE;
DECLARE closure private.account_closures%ROWTYPE;
DECLARE membership_item record;
DECLARE fingerprint text;
BEGIN
 SELECT * INTO account FROM public.users WHERE id=p_user AND status='disabled' FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Closed account required'; END IF;
 SELECT * INTO closure FROM private.account_closures WHERE user_id=p_user;
 IF NOT FOUND THEN RAISE EXCEPTION 'Protected closure evidence required'; END IF;
 FOR membership_item IN SELECT tenant_id FROM public.tenant_memberships WHERE user_id=p_user ORDER BY tenant_id LOOP
  PERFORM private.lock_privacy_retention_subject(membership_item.tenant_id,p_user);
 END LOOP;
 PERFORM 1 FROM private.privacy_retention_policies WHERE tenant_id IN (SELECT tenant_id FROM public.tenant_memberships WHERE user_id=p_user) ORDER BY tenant_id FOR SHARE;
 IF EXISTS(SELECT 1 FROM public.tenant_memberships m LEFT JOIN private.privacy_retention_policies p ON p.tenant_id=m.tenant_id
 WHERE m.user_id=p_user AND (m.status='active' OR p.tenant_id IS NULL OR NOT p.enabled OR NOT p.allow_provider_account_erasure))
 OR EXISTS(SELECT 1 FROM private.privacy_retention_holds WHERE subject_user_id=p_user)
 OR EXISTS(SELECT 1 FROM public.privacy_requests WHERE subject_user_id=p_user AND status IN ('requested','identity_verification','under_review','legal_hold')) THEN
  RAISE EXCEPTION 'Retention authorization, hold or outstanding request blocks provider erasure';
 END IF;
 SELECT encode(public.digest(string_agg(p.tenant_id::text||':'||p.revision::text,',' ORDER BY p.tenant_id),'sha256'),'hex') INTO fingerprint
 FROM private.privacy_retention_policies p JOIN public.tenant_memberships m ON m.tenant_id=p.tenant_id WHERE m.user_id=p_user;
 IF fingerprint IS NULL THEN RAISE EXCEPTION 'Explicit retention authorization required'; END IF;
 IF account.auth_issuer IS NULL THEN RAISE EXCEPTION 'Provider issuer mapping requires separate review'; END IF;
 IF account.auth_subject !~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' THEN
  RAISE EXCEPTION 'Provider subject mapping requires separate review';
 END IF;
 RETURN jsonb_build_object('subject',account.auth_subject::uuid,'issuer',account.auth_issuer,'tenantId',closure.tenant_id,'fingerprint',fingerprint);
END
$fn$;
ALTER FUNCTION private.provider_erasure_context(uuid) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.provider_erasure_context(uuid) FROM PUBLIC,profitpilot_app;

CREATE OR REPLACE FUNCTION private.authorize_provider_erasure(p_user uuid,p_issuer text,p_subject uuid,p_consent text,p_approval text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
DECLARE ctx jsonb;
DECLARE grant_id uuid;
BEGIN
 ctx:=private.provider_erasure_context(p_user);
 IF p_subject IS NULL OR p_subject IS DISTINCT FROM (ctx->>'subject')::uuid OR p_issuer IS DISTINCT FROM ctx->>'issuer'
 OR p_issuer !~ '^https://[a-z0-9]{20}\.supabase\.co/auth/v1$'
 OR p_consent IS NULL OR p_approval IS NULL OR length(btrim(p_consent)) NOT BETWEEN 3 AND 500
 OR length(btrim(p_approval)) NOT BETWEEN 3 AND 500 OR btrim(p_consent)=btrim(p_approval) THEN
  RAISE EXCEPTION 'Exact provider mapping, consent and independent approval references required';
 END IF;
 IF EXISTS(SELECT 1 FROM private.provider_erasure_receipts WHERE user_id=p_user) THEN RAISE EXCEPTION 'Provider erasure already recorded'; END IF;
 UPDATE private.provider_erasure_grants SET invalidated_at=clock_timestamp() WHERE user_id=p_user AND consumed_at IS NULL AND invalidated_at IS NULL;
 INSERT INTO private.provider_erasure_grants(user_id,issuer,provider_subject,policy_fingerprint,consent_reference,approval_reference,expires_at)
 VALUES(p_user,p_issuer,p_subject,ctx->>'fingerprint',btrim(p_consent),btrim(p_approval),clock_timestamp()+interval '15 minutes')
 RETURNING id INTO grant_id;
 RETURN grant_id;
END
$fn$;
ALTER FUNCTION private.authorize_provider_erasure(uuid,text,uuid,text,text) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.authorize_provider_erasure(uuid,text,uuid,text,text) FROM PUBLIC,profitpilot_app;

CREATE OR REPLACE FUNCTION private.provider_erasure_target(p_grant uuid,p_issuer text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
DECLARE grant_row private.provider_erasure_grants%ROWTYPE;
DECLARE ctx jsonb;
BEGIN
 SELECT * INTO grant_row FROM private.provider_erasure_grants WHERE id=p_grant;
 IF NOT FOUND THEN RAISE EXCEPTION 'Provider erasure authorization not found'; END IF;
 ctx:=private.provider_erasure_context(grant_row.user_id);
 SELECT * INTO grant_row FROM private.provider_erasure_grants WHERE id=p_grant FOR UPDATE;
 IF grant_row.issuer IS DISTINCT FROM p_issuer OR grant_row.issuer IS DISTINCT FROM ctx->>'issuer' OR grant_row.provider_subject IS DISTINCT FROM (ctx->>'subject')::uuid
 OR grant_row.policy_fingerprint IS DISTINCT FROM ctx->>'fingerprint'
 OR grant_row.consumed_at IS NOT NULL OR grant_row.invalidated_at IS NOT NULL OR grant_row.expires_at<=clock_timestamp()
 OR EXISTS(SELECT 1 FROM private.provider_erasure_receipts WHERE user_id=grant_row.user_id) THEN
  RAISE EXCEPTION 'Provider erasure authorization is invalid, expired or mismatched';
 END IF;
 RETURN jsonb_build_object('grantId',grant_row.id,'subject',grant_row.provider_subject,'issuer',grant_row.issuer,'tenantId',ctx->>'tenantId','userId',grant_row.user_id);
END
$fn$;
ALTER FUNCTION private.provider_erasure_target(uuid,text) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.provider_erasure_target(uuid,text) FROM PUBLIC,profitpilot_app;

COMMIT;

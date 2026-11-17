-- Operator-only authorization and evidence for an external identity deletion.
-- No provider operation is executed by this migration.
BEGIN;
ALTER TABLE private.privacy_retention_policies ADD COLUMN allow_provider_account_erasure boolean NOT NULL DEFAULT false;
CREATE TABLE private.provider_erasure_grants(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 user_id uuid NOT NULL REFERENCES private.account_closures(user_id),
 issuer text NOT NULL CHECK(issuer ~ '^https://[a-z0-9]{20}\.supabase\.co/auth/v1$'),
 provider_subject uuid NOT NULL,
 policy_fingerprint text NOT NULL,
 consent_reference text NOT NULL CHECK(length(btrim(consent_reference)) BETWEEN 3 AND 500),
 approval_reference text NOT NULL CHECK(length(btrim(approval_reference)) BETWEEN 3 AND 500),
 approved_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz NOT NULL,
 invalidated_at timestamptz,
 consumed_at timestamptz,
 CHECK(consent_reference<>approval_reference),
 CHECK(expires_at>approved_at)
);
CREATE TABLE private.provider_erasure_receipts(
 id uuid PRIMARY KEY REFERENCES private.provider_erasure_grants(id),
 user_id uuid NOT NULL UNIQUE REFERENCES private.account_closures(user_id),
 tenant_id uuid NOT NULL REFERENCES public.tenants(id),
 verified_at timestamptz NOT NULL,
 verification text NOT NULL CHECK(verification='provider_user_not_found')
);
ALTER TABLE private.provider_erasure_grants OWNER TO profitpilot_context_owner;
ALTER TABLE private.provider_erasure_receipts OWNER TO profitpilot_context_owner;
REVOKE ALL ON private.provider_erasure_grants,private.provider_erasure_receipts FROM PUBLIC,profitpilot_app;

-- Locks and checks all historical tenant obligations, not merely the initiating tenant.
CREATE FUNCTION private.provider_erasure_context(p_user uuid) RETURNS jsonb
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
 IF account.auth_subject !~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' THEN
  RAISE EXCEPTION 'Provider subject mapping requires separate review';
 END IF;
 RETURN jsonb_build_object('subject',account.auth_subject::uuid,'tenantId',closure.tenant_id,'fingerprint',fingerprint);
END
$fn$;
ALTER FUNCTION private.provider_erasure_context(uuid) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.provider_erasure_context(uuid) FROM PUBLIC,profitpilot_app;

CREATE FUNCTION private.authorize_provider_erasure(p_user uuid,p_issuer text,p_subject uuid,p_consent text,p_approval text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
DECLARE ctx jsonb;
DECLARE grant_id uuid;
BEGIN
 ctx:=private.provider_erasure_context(p_user);
 IF p_subject IS NULL OR p_subject IS DISTINCT FROM (ctx->>'subject')::uuid OR p_issuer IS NULL
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

CREATE FUNCTION private.provider_erasure_target(p_grant uuid,p_issuer text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
DECLARE grant_row private.provider_erasure_grants%ROWTYPE;
DECLARE ctx jsonb;
BEGIN
 SELECT * INTO grant_row FROM private.provider_erasure_grants WHERE id=p_grant;
 IF NOT FOUND THEN RAISE EXCEPTION 'Provider erasure authorization not found'; END IF;
 ctx:=private.provider_erasure_context(grant_row.user_id);
 SELECT * INTO grant_row FROM private.provider_erasure_grants WHERE id=p_grant FOR UPDATE;
 IF grant_row.issuer IS DISTINCT FROM p_issuer OR grant_row.provider_subject IS DISTINCT FROM (ctx->>'subject')::uuid
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

CREATE FUNCTION private.record_provider_erasure(p_grant uuid,p_issuer text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
DECLARE target jsonb;
BEGIN
 target:=private.provider_erasure_target(p_grant,p_issuer);
 INSERT INTO private.provider_erasure_receipts(id,user_id,tenant_id,verified_at,verification)
 VALUES(p_grant,(target->>'userId')::uuid,(target->>'tenantId')::uuid,clock_timestamp(),'provider_user_not_found');
 UPDATE private.provider_erasure_grants SET consumed_at=clock_timestamp() WHERE id=p_grant;
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata)
 VALUES((target->>'tenantId')::uuid,NULL,'external_identity_erasure_recorded','account_closure',(target->>'userId')::uuid,
 'Operator recorded provider user-not-found verification','{}'::jsonb);
 RETURN jsonb_build_object('providerAbsenceRecorded',true,'completePersonalDataDeletion',false);
END
$fn$;
ALTER FUNCTION private.record_provider_erasure(uuid,text) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.record_provider_erasure(uuid,text) FROM PUBLIC,profitpilot_app;

CREATE FUNCTION private.invalidate_provider_erasure_grants_on_hold() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,private AS $fn$
DECLARE subject_id uuid;
DECLARE tenant_id_value uuid;
BEGIN
 IF TG_OP='DELETE' THEN subject_id:=OLD.subject_user_id;tenant_id_value:=OLD.tenant_id;
 ELSE subject_id:=NEW.subject_user_id;tenant_id_value:=NEW.tenant_id; END IF;
 PERFORM private.lock_privacy_retention_subject(tenant_id_value,subject_id);
 UPDATE private.provider_erasure_grants SET invalidated_at=clock_timestamp() WHERE user_id=subject_id AND consumed_at IS NULL AND invalidated_at IS NULL;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END
$fn$;
ALTER FUNCTION private.invalidate_provider_erasure_grants_on_hold() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.invalidate_provider_erasure_grants_on_hold() FROM PUBLIC,profitpilot_app;
CREATE TRIGGER provider_grants_on_request_hold BEFORE UPDATE OF status ON public.privacy_requests
 FOR EACH ROW WHEN (OLD.status IS DISTINCT FROM NEW.status AND (OLD.status='legal_hold' OR NEW.status='legal_hold'))
 EXECUTE FUNCTION private.invalidate_provider_erasure_grants_on_hold();
CREATE TRIGGER provider_grants_on_subject_hold BEFORE INSERT OR UPDATE OR DELETE ON private.privacy_retention_holds
 FOR EACH ROW EXECUTE FUNCTION private.invalidate_provider_erasure_grants_on_hold();
CREATE OR REPLACE FUNCTION private.privacy_restore_state() RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
 SELECT jsonb_build_object(
 'markers',COALESCE((
 SELECT jsonb_agg(marker ORDER BY kind,id) FROM (
  SELECT 'closure'::text AS kind,c.user_id AS id,
  jsonb_build_object('kind','closure','id',c.user_id,'tenantId',c.tenant_id,'requestId',c.request_id,
   'at',extract(epoch FROM c.closed_at)::text,'emailErased',c.email_erased) AS marker
  FROM private.account_closures c
  UNION ALL
  SELECT 'redaction',r.id,jsonb_build_object('kind','redaction','id',r.id,'tenantId',r.tenant_id,
   'at',extract(epoch FROM r.details_redacted_at)::text)
  FROM public.privacy_requests r WHERE r.details_redacted_at IS NOT NULL
  UNION ALL
  SELECT 'session_cleanup',c.id,jsonb_build_object('kind','session_cleanup','id',c.id,'tenantId',c.tenant_id,'userId',c.user_id,
  'at',extract(epoch FROM c.cleaned_at)::text,'cutoff',extract(epoch FROM c.cutoff)::text)
  FROM private.closed_session_cleanups c
  UNION ALL SELECT 'provider_erasure',e.id,jsonb_build_object('kind','provider_erasure','id',e.id,'tenantId',e.tenant_id,
  'userId',e.user_id,'at',extract(epoch FROM e.verified_at)::text)
  FROM private.provider_erasure_receipts e
 ) m),'[]'::jsonb),
 'violations',COALESCE((
 SELECT jsonb_agg(jsonb_build_object('kind',v.kind,'id',v.id) ORDER BY v.kind,v.id)
 FROM (
  SELECT 'closure_state_mismatch'::text AS kind,c.user_id AS id FROM private.account_closures c
  LEFT JOIN public.users u ON u.id=c.user_id
  LEFT JOIN public.privacy_requests r ON r.id=c.request_id
  WHERE u.id IS NULL OR u.status<>'disabled' OR r.id IS NULL OR r.status<>'fulfilled'
  OR r.request_type<>'account_closure' OR r.subject_user_id<>c.user_id OR r.tenant_id<>c.tenant_id
  OR (c.email_erased AND u.email IS DISTINCT FROM 'erased-'||u.id::text||'@invalid.example')
  OR EXISTS(SELECT 1 FROM public.tenant_memberships m WHERE m.user_id=c.user_id AND m.status='active')
  OR EXISTS(SELECT 1 FROM private.auth_sessions s WHERE s.subject=u.auth_subject AND s.revoked_at IS NULL)
  UNION ALL SELECT 'redaction_state_mismatch',r.id FROM public.privacy_requests r
  WHERE r.details_redacted_at IS NOT NULL AND r.details IS DISTINCT FROM '[Removed under approved retention policy]'
  UNION ALL SELECT 'session_cleanup_mismatch',c.id FROM private.closed_session_cleanups c JOIN public.users u ON u.id=c.user_id
  WHERE EXISTS(SELECT 1 FROM private.auth_sessions s WHERE s.subject=u.auth_subject AND s.expires_at<=c.cutoff AND s.revoked_at<=c.cutoff)
 ) v),'[]'::jsonb))
$fn$;
ALTER FUNCTION private.privacy_restore_state() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.privacy_restore_state() FROM PUBLIC,profitpilot_app;
COMMIT;

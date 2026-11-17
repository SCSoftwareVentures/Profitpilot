-- Explicit retention policy for expired revoked session metadata; no default deletion.
BEGIN;
ALTER TABLE private.privacy_retention_policies ADD COLUMN allow_expired_session_erasure boolean NOT NULL DEFAULT false,
 ADD COLUMN session_retention_days integer NOT NULL DEFAULT 365 CHECK(session_retention_days BETWEEN 1 AND 36500);
CREATE TABLE private.closed_session_cleanups(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 user_id uuid NOT NULL REFERENCES private.account_closures(user_id),
 tenant_id uuid NOT NULL REFERENCES public.tenants(id),
 cleaned_at timestamptz NOT NULL,
 cutoff timestamptz NOT NULL,
 removed_count integer NOT NULL CHECK(removed_count>0),
 authority_reference text NOT NULL CHECK(length(btrim(authority_reference)) BETWEEN 3 AND 500),
 CHECK(cutoff<cleaned_at)
);
ALTER TABLE private.closed_session_cleanups OWNER TO profitpilot_context_owner;
REVOKE ALL ON private.closed_session_cleanups FROM PUBLIC,profitpilot_app;
CREATE FUNCTION private.cleanup_closed_sessions(p_user uuid,p_authority text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
DECLARE account public.users%ROWTYPE;
DECLARE closure private.account_closures%ROWTYPE;
DECLARE membership_item record;
DECLARE keep_days integer;
DECLARE at_time timestamptz;
DECLARE cutoff_time timestamptz;
DECLARE n integer;
DECLARE event_id uuid;
BEGIN
 IF p_authority IS NULL OR length(btrim(p_authority)) NOT BETWEEN 3 AND 500 THEN RAISE EXCEPTION 'Retention authorization reference required'; END IF;
 SELECT * INTO account FROM public.users WHERE id=p_user AND status='disabled' FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Closed account required'; END IF;
 SELECT * INTO closure FROM private.account_closures WHERE user_id=p_user;
 IF NOT FOUND THEN RAISE EXCEPTION 'Protected closure evidence required'; END IF;
 FOR membership_item IN SELECT tenant_id FROM public.tenant_memberships WHERE user_id=p_user ORDER BY tenant_id LOOP
  PERFORM private.lock_privacy_retention_subject(membership_item.tenant_id,p_user);
 END LOOP;
 PERFORM 1 FROM private.privacy_retention_policies WHERE tenant_id IN(SELECT tenant_id FROM public.tenant_memberships WHERE user_id=p_user) ORDER BY tenant_id FOR SHARE;
 IF EXISTS(SELECT 1 FROM public.tenant_memberships m LEFT JOIN private.privacy_retention_policies p ON p.tenant_id=m.tenant_id
 WHERE m.user_id=p_user AND (m.status='active' OR p.tenant_id IS NULL OR NOT p.enabled OR NOT p.allow_expired_session_erasure))
 OR EXISTS(SELECT 1 FROM private.privacy_retention_holds WHERE subject_user_id=p_user)
 OR EXISTS(SELECT 1 FROM public.privacy_requests WHERE subject_user_id=p_user AND status IN ('requested','identity_verification','under_review','legal_hold')) THEN
  RAISE EXCEPTION 'Retention authorization, hold or outstanding request blocks cleanup';
 END IF;
 SELECT max(p.session_retention_days) INTO keep_days FROM private.privacy_retention_policies p
 JOIN public.tenant_memberships m ON m.tenant_id=p.tenant_id WHERE m.user_id=p_user;
 IF keep_days IS NULL THEN RAISE EXCEPTION 'Explicit retention authorization required'; END IF;
 at_time:=clock_timestamp();
 cutoff_time:=at_time-make_interval(days=>keep_days);
 DELETE FROM private.auth_sessions WHERE subject=account.auth_subject AND expires_at<=cutoff_time AND revoked_at<=cutoff_time;
 GET DIAGNOSTICS n=ROW_COUNT;
 IF n=0 THEN RETURN jsonb_build_object('removed',0,'completePersonalDataDeletion',false); END IF;
 INSERT INTO private.closed_session_cleanups(user_id,tenant_id,cleaned_at,cutoff,removed_count,authority_reference)
 VALUES(p_user,closure.tenant_id,at_time,cutoff_time,n,btrim(p_authority)) RETURNING id INTO event_id;
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata)
 VALUES(closure.tenant_id,NULL,'closed_session_metadata_erased','account_closure',p_user,'Expired revoked sessions removed under approved retention policy',
 jsonb_build_object('cleanupId',event_id,'removedCount',n,'cutoff',cutoff_time));
 RETURN jsonb_build_object('removed',n,'cleanupId',event_id,'completePersonalDataDeletion',false);
END
$fn$;
ALTER FUNCTION private.cleanup_closed_sessions(uuid,text) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.cleanup_closed_sessions(uuid,text) FROM PUBLIC,profitpilot_app;
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

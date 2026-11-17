-- Protected restore-state evidence. Operators must quarantine restored databases.
BEGIN;
CREATE FUNCTION private.require_active_privacy_submitter() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
BEGIN
 -- Wait behind closure and recheck account state; no new privacy requests may race closure.
 PERFORM 1 FROM public.users WHERE id=NEW.subject_user_id AND status='active' FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Active privacy requester required' USING ERRCODE='42501'; END IF;
 RETURN NEW;
END
$fn$;
ALTER FUNCTION private.require_active_privacy_submitter() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.require_active_privacy_submitter() FROM PUBLIC,profitpilot_app;
CREATE TRIGGER privacy_active_subject_before_insert BEFORE INSERT ON public.privacy_requests
 FOR EACH ROW EXECUTE FUNCTION private.require_active_privacy_submitter();

CREATE FUNCTION private.preserve_redaction_marker() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
BEGIN
 IF OLD.details_redacted_at IS NOT NULL AND
 (NEW.details IS DISTINCT FROM OLD.details OR NEW.details_redacted_at IS DISTINCT FROM OLD.details_redacted_at
 OR NEW.id IS DISTINCT FROM OLD.id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.subject_user_id IS DISTINCT FROM OLD.subject_user_id) THEN
  RAISE EXCEPTION 'Redacted data must not be restored' USING ERRCODE='55000';
 END IF;
 RETURN NEW;
END
$fn$;
ALTER FUNCTION private.preserve_redaction_marker() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.preserve_redaction_marker() FROM PUBLIC,profitpilot_app;
CREATE TRIGGER preserve_redacted_privacy_details BEFORE UPDATE ON public.privacy_requests
 FOR EACH ROW EXECUTE FUNCTION private.preserve_redaction_marker();

CREATE FUNCTION private.privacy_restore_state() RETURNS jsonb
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
 ) v),'[]'::jsonb))
$fn$;
ALTER FUNCTION private.privacy_restore_state() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.privacy_restore_state() FROM PUBLIC,profitpilot_app;
COMMIT;

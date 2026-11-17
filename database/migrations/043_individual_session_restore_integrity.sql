-- Independent revocation tombstones: retain a token identifier fingerprint, not the bearer token.
BEGIN;
CREATE TABLE private.individual_session_revocation_receipts(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 token_fingerprint bytea NOT NULL UNIQUE CHECK(octet_length(token_fingerprint)=32),
 revoked_at timestamptz NOT NULL CHECK(isfinite(revoked_at)),
 expires_at timestamptz NOT NULL CHECK(isfinite(expires_at))
);
ALTER TABLE private.individual_session_revocation_receipts OWNER TO profitpilot_context_owner;
REVOKE ALL ON private.individual_session_revocation_receipts FROM PUBLIC,profitpilot_app;
INSERT INTO private.individual_session_revocation_receipts(token_fingerprint,revoked_at,expires_at)
 SELECT public.digest(convert_to(jti,'UTF8'),'sha256'),revoked_at,expires_at
 FROM private.auth_sessions WHERE revocation_reason='self_service_revocation' AND revoked_at IS NOT NULL;
CREATE FUNCTION private.record_individual_session_revocation() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
BEGIN
 IF NEW.revocation_reason='self_service_revocation' AND NEW.revoked_at IS NOT NULL THEN
  INSERT INTO private.individual_session_revocation_receipts(token_fingerprint,revoked_at,expires_at)
  VALUES(public.digest(convert_to(NEW.jti,'UTF8'),'sha256'),NEW.revoked_at,NEW.expires_at)
  ON CONFLICT(token_fingerprint) DO NOTHING;
 END IF;
 RETURN NEW;
END
$fn$;
ALTER FUNCTION private.record_individual_session_revocation() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.record_individual_session_revocation() FROM PUBLIC,profitpilot_app;
CREATE TRIGGER individual_session_revocation_evidence AFTER INSERT OR UPDATE OF revoked_at,revocation_reason ON private.auth_sessions
 FOR EACH ROW EXECUTE FUNCTION private.record_individual_session_revocation();
CREATE TRIGGER individual_session_receipt_guard BEFORE UPDATE OR DELETE OR TRUNCATE ON private.individual_session_revocation_receipts
 FOR EACH STATEMENT EXECUTE FUNCTION private.guard_account_session_revocation_receipt();

CREATE OR REPLACE FUNCTION private.accept_bound_access_session(p_jti text,p_subject text,p_issuer text,p_issued_at timestamptz,p_expires_at timestamptz)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
DECLARE n integer;
DECLARE at_time timestamptz:=clock_timestamp();
BEGIN
 IF p_jti IS NULL OR p_jti !~ '^[A-Za-z0-9._~-]{16,128}$' OR p_subject IS NULL OR length(p_subject) NOT BETWEEN 1 AND 512
 OR btrim(p_subject)<>p_subject OR p_subject ~ '[[:cntrl:]]' OR p_issuer IS NULL
 OR p_issued_at IS NULL OR p_expires_at IS NULL OR NOT isfinite(p_issued_at) OR NOT isfinite(p_expires_at)
 OR p_issued_at>at_time+interval '5 seconds' OR p_issued_at<at_time-interval '901 seconds'
 OR p_expires_at<=at_time OR p_expires_at<=p_issued_at OR p_expires_at>p_issued_at+interval '15 minutes' THEN RETURN false; END IF;
 PERFORM 1 FROM public.users WHERE auth_subject=p_subject AND auth_issuer=p_issuer AND status='active' FOR SHARE;
 IF NOT FOUND THEN RETURN false; END IF;
 IF EXISTS(SELECT 1 FROM private.individual_session_revocation_receipts WHERE token_fingerprint=public.digest(convert_to(p_jti,'UTF8'),'sha256')) THEN RETURN false; END IF;
 INSERT INTO private.auth_sessions(jti,subject,issued_at,expires_at,last_seen_at)
 VALUES(p_jti,p_subject,p_issued_at,p_expires_at,at_time)
 ON CONFLICT(jti) DO UPDATE SET last_seen_at=GREATEST(private.auth_sessions.last_seen_at,EXCLUDED.last_seen_at)
 WHERE private.auth_sessions.subject=EXCLUDED.subject
 AND private.auth_sessions.issued_at=EXCLUDED.issued_at
 AND private.auth_sessions.expires_at=EXCLUDED.expires_at
 AND private.auth_sessions.revoked_at IS NULL
 AND private.auth_sessions.expires_at>clock_timestamp();
 GET DIAGNOSTICS n=ROW_COUNT;
 RETURN n=1 AND p_expires_at>clock_timestamp();
END
$fn$;

REVOKE ALL ON FUNCTION private.accept_bound_access_session(text,text,text,timestamptz,timestamptz) FROM PUBLIC,profitpilot_app;

-- Expired sessions do not need a new self-service revocation.
CREATE OR REPLACE FUNCTION private.revoke_auth_session(p_jti text,p_subject text,p_reason text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,private AS $fn$
DECLARE changed integer;
BEGIN
 IF p_reason IS NULL OR length(btrim(p_reason))<3 OR length(p_reason)>256 THEN
  RAISE EXCEPTION 'Invalid session revocation reason' USING ERRCODE='22023';
 END IF;
 UPDATE private.auth_sessions SET revoked_at=clock_timestamp(),revocation_reason=p_reason
 WHERE jti=p_jti AND subject=p_subject AND revoked_at IS NULL AND expires_at>clock_timestamp();
 GET DIAGNOSTICS changed=ROW_COUNT;
 RETURN changed=1;
END
$fn$;
REVOKE ALL ON FUNCTION private.revoke_auth_session(text,text,text) FROM PUBLIC,profitpilot_app;

ALTER FUNCTION private.privacy_restore_state() RENAME TO privacy_restore_state_before_individual_revocation;
CREATE FUNCTION private.privacy_restore_state() RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
 SELECT jsonb_build_object(
  'markers',s.state->'markers'||COALESCE((
   SELECT jsonb_agg(jsonb_build_object('kind','individual_session_revocation','id',r.id,
    'tokenFingerprint',encode(r.token_fingerprint,'hex'),'at',extract(epoch FROM r.revoked_at)::text,
    'expiresAt',extract(epoch FROM r.expires_at)::text) ORDER BY r.id)
   FROM private.individual_session_revocation_receipts r
  ),'[]'::jsonb),
  'violations',s.state->'violations'||COALESCE((
   SELECT jsonb_agg(jsonb_build_object('kind',v.kind,'id',v.id) ORDER BY v.kind,v.id)
   FROM (
    SELECT 'individually_revoked_session_reinstated'::text AS kind,r.id
    FROM private.auth_sessions a JOIN private.individual_session_revocation_receipts r
     ON r.token_fingerprint=public.digest(convert_to(a.jti,'UTF8'),'sha256')
    WHERE a.revoked_at IS DISTINCT FROM r.revoked_at OR a.expires_at IS DISTINCT FROM r.expires_at
      OR a.revocation_reason IS DISTINCT FROM 'self_service_revocation'
   ) v
  ),'[]'::jsonb))
 FROM (SELECT private.privacy_restore_state_before_individual_revocation() AS state) s
$fn$;
ALTER FUNCTION private.privacy_restore_state() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.privacy_restore_state(),private.privacy_restore_state_before_individual_revocation() FROM PUBLIC,profitpilot_app;
COMMIT;

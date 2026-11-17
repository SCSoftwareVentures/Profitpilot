-- ProfitPilot migration 009: server-side access-session registry and revocation.
-- Apply with the migration administrator. Runtime access is through narrowly scoped functions only.
BEGIN;

CREATE TABLE private.auth_sessions (
 jti text PRIMARY KEY CHECK(length(jti) BETWEEN 16 AND 128),
 subject text NOT NULL,
 issued_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 last_seen_at timestamptz NOT NULL DEFAULT now(),
 revoked_at timestamptz,
 revocation_reason text,
 CHECK(expires_at>issued_at),
 CHECK((revoked_at IS NULL)=(revocation_reason IS NULL))
);
ALTER TABLE private.auth_sessions OWNER TO profitpilot_context_owner;
REVOKE ALL ON private.auth_sessions FROM PUBLIC,profitpilot_app;
CREATE INDEX auth_sessions_subject_idx ON private.auth_sessions(subject,expires_at DESC);

CREATE OR REPLACE FUNCTION private.register_auth_session(
 p_jti text,p_subject text,p_issued_at timestamptz,p_expires_at timestamptz
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,private
AS $function$
BEGIN
 IF p_jti IS NULL OR length(p_jti)<16 OR length(p_jti)>128 OR p_subject IS NULL OR length(p_subject)=0
    OR p_expires_at<=p_issued_at OR p_expires_at<=clock_timestamp() THEN
  RAISE EXCEPTION 'Invalid access session registration' USING ERRCODE='22023';
 END IF;
 INSERT INTO private.auth_sessions(jti,subject,issued_at,expires_at,last_seen_at)
 VALUES(p_jti,p_subject,p_issued_at,p_expires_at,clock_timestamp())
 ON CONFLICT(jti) DO UPDATE SET last_seen_at=clock_timestamp()
 WHERE private.auth_sessions.subject=EXCLUDED.subject
   AND private.auth_sessions.issued_at=EXCLUDED.issued_at
   AND private.auth_sessions.expires_at=EXCLUDED.expires_at
   AND private.auth_sessions.revoked_at IS NULL;
END;
$function$;
ALTER FUNCTION private.register_auth_session(text,text,timestamptz,timestamptz) OWNER TO profitpilot_context_owner;

CREATE OR REPLACE FUNCTION private.is_auth_session_revoked(p_jti text,p_subject text)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,private
AS $function$
 SELECT NOT EXISTS(
  SELECT 1 FROM private.auth_sessions s
  WHERE s.jti=p_jti AND s.subject=p_subject
    AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
 )
$function$;
ALTER FUNCTION private.is_auth_session_revoked(text,text) OWNER TO profitpilot_context_owner;

CREATE OR REPLACE FUNCTION private.revoke_auth_session(p_jti text,p_subject text,p_reason text)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,private
AS $function$
DECLARE changed integer;
BEGIN
 IF p_reason IS NULL OR length(btrim(p_reason))<3 OR length(p_reason)>256 THEN
  RAISE EXCEPTION 'Invalid session revocation reason' USING ERRCODE='22023';
 END IF;
 UPDATE private.auth_sessions SET revoked_at=clock_timestamp(),revocation_reason=p_reason
 WHERE jti=p_jti AND subject=p_subject AND revoked_at IS NULL;
 GET DIAGNOSTICS changed=ROW_COUNT;
 RETURN changed=1;
END;
$function$;
ALTER FUNCTION private.revoke_auth_session(text,text,text) OWNER TO profitpilot_context_owner;

CREATE OR REPLACE FUNCTION private.list_auth_sessions(p_subject text)
RETURNS TABLE(jti text,issued_at timestamptz,expires_at timestamptz,last_seen_at timestamptz,revoked_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,private
AS $function$
 SELECT s.jti,s.issued_at,s.expires_at,s.last_seen_at,s.revoked_at
 FROM private.auth_sessions s
 WHERE s.subject=p_subject AND s.expires_at>clock_timestamp()
 ORDER BY s.last_seen_at DESC
$function$;
ALTER FUNCTION private.list_auth_sessions(text) OWNER TO profitpilot_context_owner;

REVOKE ALL ON FUNCTION private.register_auth_session(text,text,timestamptz,timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION private.is_auth_session_revoked(text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION private.revoke_auth_session(text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION private.list_auth_sessions(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.register_auth_session(text,text,timestamptz,timestamptz) TO profitpilot_app;
GRANT EXECUTE ON FUNCTION private.is_auth_session_revoked(text,text) TO profitpilot_app;
GRANT EXECUTE ON FUNCTION private.revoke_auth_session(text,text,text) TO profitpilot_app;
GRANT EXECUTE ON FUNCTION private.list_auth_sessions(text) TO profitpilot_app;

COMMIT;

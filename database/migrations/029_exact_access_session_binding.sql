-- A token identifier must bind to the exact original subject and lifetime.
BEGIN;
CREATE FUNCTION private.accept_bound_access_session(p_jti text,p_subject text,p_issuer text,p_issued_at timestamptz,p_expires_at timestamptz)
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
ALTER FUNCTION private.accept_bound_access_session(text,text,text,timestamptz,timestamptz) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.accept_bound_access_session(text,text,text,timestamptz,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.accept_bound_access_session(text,text,text,timestamptz,timestamptz) TO profitpilot_app;
REVOKE EXECUTE ON FUNCTION private.register_bound_auth_session(text,text,text,timestamptz,timestamptz),private.is_bound_auth_session_revoked(text,text,text) FROM profitpilot_app;
COMMIT;

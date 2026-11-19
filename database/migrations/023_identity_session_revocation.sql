-- Identity session revocation. All API requests must verify a short-lived
-- server-attested session context. No raw access token or session ID is stored.
BEGIN;
CREATE TABLE private.identity_session_cutoffs(
 user_id uuid PRIMARY KEY REFERENCES public.users(id),
 revoked_through bigint NOT NULL CHECK(revoked_through>=0)
);
CREATE TABLE private.revoked_identity_sessions(
 user_id uuid NOT NULL REFERENCES public.users(id),
 session_digest text NOT NULL CHECK(session_digest ~ '^[a-f0-9]{64}$'),
 revoked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(user_id,session_digest)
);
CREATE TABLE private.identity_security_events(
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 user_id uuid NOT NULL REFERENCES public.users(id),
 action text NOT NULL CHECK(action IN ('revoke_all','revoke_session','disable','enable')),
 authority_ref text NOT NULL,
 operator_name text NOT NULL DEFAULT session_user,
 occurred_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON private.identity_session_cutoffs,private.revoked_identity_sessions,private.identity_security_events FROM PUBLIC,profitpilot_app;

CREATE FUNCTION private.session_authorized(p_subject text,p_auth bigint,p_iat bigint,p_digest text,p_expires bigint,p_nonce text,p_key text,p_signature text)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE uid uuid; secret_value bytea; expected text; now_s bigint;
BEGIN
 now_s:=floor(extract(epoch FROM statement_timestamp()))::bigint;
 IF p_subject IS NULL OR char_length(p_subject) NOT BETWEEN 1 AND 255 OR p_subject ~ '[[:cntrl:]]'
 OR p_auth IS NULL OR p_auth<=0 OR p_iat IS NULL OR p_auth>p_iat+5 OR p_iat>now_s+5 OR p_iat<now_s-905
 OR p_digest IS NULL OR p_digest !~ '^[a-f0-9]{64}$'
 OR p_expires IS NULL OR p_expires<now_s OR p_expires>now_s+60
 OR p_nonce IS NULL OR p_nonce !~ '^[a-f0-9]{32}$'
 OR p_key IS NULL OR p_key !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$'
 OR p_signature IS NULL OR p_signature !~ '^[a-f0-9]{64}$' THEN RETURN false; END IF;
 SELECT secret INTO secret_value FROM private.tenant_context_keys WHERE key_id=p_key AND active;
 IF NOT FOUND THEN RETURN false; END IF;
 expected:=encode(public.hmac(convert_to('profitpilot-session-v1'||E'\n'||p_subject||E'\n'||p_auth||E'\n'||p_iat||E'\n'||p_digest||E'\n'||p_expires||E'\n'||p_nonce||E'\n'||p_key,'UTF8'),secret_value,'sha256'),'hex');
 IF expected<>p_signature THEN RETURN false; END IF;
 SELECT id INTO uid FROM public.users WHERE auth_subject=p_subject AND status='active';
 IF NOT FOUND THEN RETURN false; END IF;
 RETURN NOT EXISTS(SELECT 1 FROM private.identity_session_cutoffs WHERE user_id=uid AND revoked_through>=p_auth)
 AND NOT EXISTS(SELECT 1 FROM private.revoked_identity_sessions WHERE user_id=uid AND session_digest=p_digest);
END $fn$;
REVOKE ALL ON FUNCTION private.session_authorized(text,bigint,bigint,text,bigint,text,text,text) FROM PUBLIC,profitpilot_app;
GRANT EXECUTE ON FUNCTION private.session_authorized(text,bigint,bigint,text,bigint,text,text,text) TO profitpilot_app;

CREATE FUNCTION private.revoke_identity_access(p_user uuid,p_action text,p_ref text,p_digest text DEFAULT NULL)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
BEGIN
 IF p_ref IS NULL OR p_ref !~ '^[A-Za-z][A-Za-z0-9_-]{2,63}$' OR p_action IS NULL
 OR p_action NOT IN ('revoke_all','revoke_session','disable','enable') THEN RAISE EXCEPTION 'Invalid identity action'; END IF;
 PERFORM 1 FROM public.users WHERE id=p_user FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Identity not found'; END IF;
 IF p_action='revoke_session' THEN
  IF p_digest IS NULL OR p_digest !~ '^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'Invalid session digest'; END IF;
  INSERT INTO private.revoked_identity_sessions(user_id,session_digest) VALUES(p_user,p_digest) ON CONFLICT DO NOTHING;
 ELSE
  IF p_digest IS NOT NULL THEN RAISE EXCEPTION 'Unexpected session digest'; END IF;
  INSERT INTO private.identity_session_cutoffs(user_id,revoked_through)
    VALUES(p_user,floor(extract(epoch FROM clock_timestamp()))::bigint)
    ON CONFLICT(user_id) DO UPDATE SET revoked_through=greatest(private.identity_session_cutoffs.revoked_through,EXCLUDED.revoked_through);
  IF p_action='disable' THEN UPDATE public.users SET status='disabled' WHERE id=p_user;
  ELSIF p_action='enable' THEN UPDATE public.users SET status='active' WHERE id=p_user; END IF;
 END IF;
 INSERT INTO private.identity_security_events(user_id,action,authority_ref) VALUES(p_user,p_action,p_ref);
END $fn$;
REVOKE ALL ON FUNCTION private.revoke_identity_access(uuid,text,text,text) FROM PUBLIC,profitpilot_app;

-- Direct administrator status changes also invalidate prior authentication;
-- disabling and re-enabling an account cannot revive old sessions.
CREATE FUNCTION private.invalidate_changed_identity()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
BEGIN
 IF NEW.status IS DISTINCT FROM OLD.status OR NEW.auth_subject IS DISTINCT FROM OLD.auth_subject THEN
  INSERT INTO private.identity_session_cutoffs(user_id,revoked_through)
   VALUES(NEW.id,floor(extract(epoch FROM clock_timestamp()))::bigint)
   ON CONFLICT(user_id) DO UPDATE SET revoked_through=greatest(private.identity_session_cutoffs.revoked_through,EXCLUDED.revoked_through);
 END IF;
 RETURN NEW;
END $fn$;
REVOKE ALL ON FUNCTION private.invalidate_changed_identity() FROM PUBLIC,profitpilot_app;
CREATE TRIGGER identity_change_session_cutoff AFTER UPDATE ON public.users
 FOR EACH ROW EXECUTE FUNCTION private.invalidate_changed_identity();
COMMIT;

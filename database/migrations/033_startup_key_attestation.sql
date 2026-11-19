-- Prove that the API and database share an active signing key without
-- exposing the secret. Separate domain from all tenant/session attestations.
BEGIN;
CREATE FUNCTION private.verify_startup_signing_key(p_key text,p_time bigint,p_nonce text,p_proof text)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE material bytea; now_s bigint;
BEGIN
 now_s:=floor(extract(epoch FROM statement_timestamp()))::bigint;
 IF session_user<>'profitpilot_app' OR p_key IS NULL OR p_key !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$'
 OR p_time IS NULL OR p_time<now_s-30 OR p_time>now_s+5
 OR p_nonce IS NULL OR p_nonce !~ '^[a-f0-9]{32}$'
 OR p_proof IS NULL OR p_proof !~ '^[a-f0-9]{64}$' THEN RETURN false; END IF;
 SELECT secret INTO material FROM private.tenant_context_keys WHERE key_id=p_key AND active;
 IF NOT FOUND THEN RETURN false; END IF;
 RETURN p_proof=encode(public.hmac(convert_to('profitpilot-startup-v1'||E'\n'||p_key||E'\n'||p_time::text||E'\n'||p_nonce,'UTF8'),material,'sha256'),'hex');
END $fn$;
REVOKE ALL ON FUNCTION private.verify_startup_signing_key(text,bigint,text,text) FROM PUBLIC,profitpilot_app;
GRANT EXECUTE ON FUNCTION private.verify_startup_signing_key(text,bigint,text,text) TO profitpilot_app;
COMMIT;

-- SQL session operations require an exact attestation from the verified-token server.
BEGIN;
CREATE FUNCTION private.verified_session_operation(p_key text,p_body text,p_proof text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
DECLARE secret_value bytea; expected text; data jsonb; action_value text; subject_value text; target_value text; items jsonb;
BEGIN
 IF p_key IS NULL OR p_key !~ '^[A-Za-z0-9._-]{1,128}$' OR p_body IS NULL OR octet_length(p_body)>8192
 OR p_proof IS NULL OR p_proof !~ '^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'Invalid session attestation' USING ERRCODE='42501';END IF;
 SELECT secret INTO secret_value FROM private.tenant_context_keys WHERE key_id=p_key AND active;
 IF secret_value IS NULL THEN RAISE EXCEPTION 'Invalid session attestation' USING ERRCODE='42501';END IF;
 expected:=encode(public.hmac(convert_to('profitpilot-session-op-v1'||E'\n'||txid_current()::text||E'\n'||pg_backend_pid()::text||E'\n'||p_key||E'\n'||p_body,'UTF8'),secret_value,'sha256'),'hex');
 IF expected IS DISTINCT FROM p_proof THEN RAISE EXCEPTION 'Invalid session attestation' USING ERRCODE='42501';END IF;
 data:=p_body::jsonb;action_value:=data->>'action';subject_value:=data->>'subject';target_value:=data->>'target';
 IF action_value IS NULL OR action_value NOT IN ('admit','list','revoke')
 OR (action_value='revoke' AND (target_value IS NULL OR target_value !~ '^[A-Za-z0-9._~-]{16,128}$'))
 OR (action_value<>'revoke' AND target_value IS NOT NULL)
 OR jsonb_typeof(data->'issuedAt') IS DISTINCT FROM 'number' OR jsonb_typeof(data->'expiresAt') IS DISTINCT FROM 'number'
 THEN RAISE EXCEPTION 'Invalid session operation' USING ERRCODE='22023';END IF;
 IF NOT private.accept_bound_access_session(data->>'jti',subject_value,data->>'issuer',to_timestamp((data->>'issuedAt')::bigint),to_timestamp((data->>'expiresAt')::bigint))
 THEN RETURN jsonb_build_object('accepted',false);END IF;
 IF action_value='admit' THEN RETURN jsonb_build_object('accepted',true);END IF;
 IF action_value='revoke' THEN
  RETURN jsonb_build_object('accepted',true,'revoked',private.revoke_auth_session(target_value,subject_value,'self_service_revocation'));
 END IF;
 SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY s.last_seen_at DESC,s.jti),'[]'::jsonb) INTO items
 FROM (SELECT * FROM private.list_auth_sessions(subject_value) ORDER BY last_seen_at DESC,jti LIMIT 101) s;
 RETURN jsonb_build_object('accepted',true,'items',CASE WHEN jsonb_array_length(items)>100 THEN items-100 ELSE items END,'truncated',jsonb_array_length(items)>100);
END
$fn$;
ALTER FUNCTION private.verified_session_operation(text,text,text) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.verified_session_operation(text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.verified_session_operation(text,text,text) TO profitpilot_app;
REVOKE EXECUTE ON FUNCTION private.accept_bound_access_session(text,text,text,timestamptz,timestamptz),private.list_auth_sessions(text),private.revoke_auth_session(text,text,text) FROM PUBLIC,profitpilot_app;
COMMIT;

-- Account-wide local session revocation with a durable authentication watermark.
BEGIN;
CREATE TABLE private.account_session_revocations (
 user_id uuid PRIMARY KEY REFERENCES public.users(id) ON DELETE RESTRICT,
 revoked_through_epoch bigint NOT NULL CHECK(revoked_through_epoch>=0)
);
ALTER TABLE private.account_session_revocations OWNER TO profitpilot_context_owner;
REVOKE ALL ON private.account_session_revocations FROM PUBLIC,profitpilot_app;
CREATE OR REPLACE FUNCTION private.verified_session_operation(p_key text,p_body text,p_proof text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
DECLARE secret_value bytea; expected text; data jsonb; action_value text; subject_value text; target_value text; items jsonb; account_id uuid; cutoff bigint; auth_epoch bigint; issued_epoch bigint; changed integer; now_epoch bigint;
BEGIN
 IF p_key IS NULL OR p_key !~ '^[A-Za-z0-9._-]{1,128}$' OR p_body IS NULL OR octet_length(p_body)>8192
 OR p_proof IS NULL OR p_proof !~ '^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'Invalid session attestation' USING ERRCODE='42501';END IF;
 SELECT secret INTO secret_value FROM private.tenant_context_keys WHERE key_id=p_key AND active;
 IF secret_value IS NULL THEN RAISE EXCEPTION 'Invalid session attestation' USING ERRCODE='42501';END IF;
 expected:=encode(public.hmac(convert_to('profitpilot-session-op-v1'||E'\n'||txid_current()::text||E'\n'||pg_backend_pid()::text||E'\n'||p_key||E'\n'||p_body,'UTF8'),secret_value,'sha256'),'hex');
 IF expected IS DISTINCT FROM p_proof THEN RAISE EXCEPTION 'Invalid session attestation' USING ERRCODE='42501';END IF;
 data:=p_body::jsonb;action_value:=data->>'action';subject_value:=data->>'subject';target_value:=data->>'target';
 IF action_value IS NULL OR action_value NOT IN ('admit','list','revoke','revoke_all')
 OR (action_value='revoke' AND (target_value IS NULL OR target_value !~ '^[A-Za-z0-9._~-]{16,128}$'))
 OR (action_value<>'revoke' AND target_value IS NOT NULL)
 OR jsonb_typeof(data->'issuedAt') IS DISTINCT FROM 'number' OR jsonb_typeof(data->'expiresAt') IS DISTINCT FROM 'number'
 THEN RAISE EXCEPTION 'Invalid session operation' USING ERRCODE='22023';END IF;
 -- Lock account before inspecting the watermark; revocation uses an exclusive lock.
 issued_epoch:=(data->>'issuedAt')::bigint;
 IF jsonb_typeof(data->'authTime')='number' THEN auth_epoch:=(data->>'authTime')::bigint; END IF;
 IF action_value='revoke_all' THEN
  SELECT id INTO account_id FROM public.users WHERE auth_subject=subject_value AND auth_issuer=data->>'issuer' AND status='active' FOR UPDATE;
 ELSE
  SELECT id INTO account_id FROM public.users WHERE auth_subject=subject_value AND auth_issuer=data->>'issuer' AND status='active' FOR SHARE;
 END IF;
 IF account_id IS NULL THEN RETURN jsonb_build_object('accepted',false); END IF;
 SELECT revoked_through_epoch INTO cutoff FROM private.account_session_revocations WHERE user_id=account_id;
 now_epoch:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 IF cutoff IS NOT NULL AND (issued_epoch<=cutoff OR auth_epoch IS NULL OR auth_epoch<=cutoff OR auth_epoch>issued_epoch OR auth_epoch>now_epoch) THEN
  RETURN jsonb_build_object('accepted',false);
 END IF;
 IF action_value='revoke_all' AND (data->'stepUpVerified' IS DISTINCT FROM 'true'::jsonb OR auth_epoch IS NULL OR auth_epoch>issued_epoch OR auth_epoch>now_epoch OR auth_epoch<now_epoch-900) THEN
  RAISE EXCEPTION 'Fresh verified MFA required for account-wide revocation' USING ERRCODE='42501';
 END IF;
 IF NOT private.accept_bound_access_session(data->>'jti',subject_value,data->>'issuer',to_timestamp((data->>'issuedAt')::bigint),to_timestamp((data->>'expiresAt')::bigint))
 THEN RETURN jsonb_build_object('accepted',false);END IF;
 IF action_value='admit' THEN RETURN jsonb_build_object('accepted',true);END IF;
 IF action_value='revoke_all' THEN
  cutoff:=floor(extract(epoch FROM clock_timestamp()))::bigint;
  INSERT INTO private.account_session_revocations(user_id,revoked_through_epoch)
  VALUES(account_id,cutoff) ON CONFLICT(user_id) DO UPDATE
  SET revoked_through_epoch=GREATEST(private.account_session_revocations.revoked_through_epoch,EXCLUDED.revoked_through_epoch)
  RETURNING revoked_through_epoch INTO cutoff;
  UPDATE private.auth_sessions SET revoked_at=clock_timestamp(),revocation_reason='account_wide_revocation'
  WHERE subject=subject_value AND revoked_at IS NULL;
  GET DIAGNOSTICS changed=ROW_COUNT;
  RETURN jsonb_build_object('accepted',true,'revokedCount',changed,'revokedThroughEpoch',cutoff,'providerRevocationConfirmed',false);
 END IF;
 IF action_value='revoke' THEN
  RETURN jsonb_build_object('accepted',true,'revoked',private.revoke_auth_session(target_value,subject_value,'self_service_revocation'));
 END IF;
 SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY s.last_seen_at DESC,s.jti),'[]'::jsonb) INTO items
 FROM (SELECT * FROM private.list_auth_sessions(subject_value) ORDER BY last_seen_at DESC,jti LIMIT 101) s;
 RETURN jsonb_build_object('accepted',true,'items',CASE WHEN jsonb_array_length(items)>100 THEN items-100 ELSE items END,'truncated',jsonb_array_length(items)>100);
END
$fn$;

REVOKE ALL ON FUNCTION private.verified_session_operation(text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.verified_session_operation(text,text,text) TO profitpilot_app;
COMMIT;

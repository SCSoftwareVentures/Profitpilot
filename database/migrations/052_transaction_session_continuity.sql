-- Revalidate the exact admitted access token at the start of each tenant operation.
BEGIN;
CREATE FUNCTION private.assert_admitted_tenant_session(p_body text,p_proof text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
DECLARE secret_value bytea; expected text; claims jsonb; actor uuid; cutoff bigint; issued bigint; expires bigint; auth_epoch bigint; now_epoch bigint; session_key text;
BEGIN
 IF p_body IS NULL OR octet_length(p_body)>8192 OR p_proof IS NULL OR p_proof !~ '^[a-f0-9]{64}$'
 THEN RAISE EXCEPTION 'Invalid transaction session attestation' USING ERRCODE='42501'; END IF;
 SELECT secret INTO secret_value FROM private.tenant_context_keys WHERE key_id=current_setting('app.tenant_key_id',true) AND active;
 expected:=encode(public.hmac(convert_to('profitpilot-tenant-session-v1'||E'\n'||txid_current()::text||E'\n'||pg_backend_pid()::text||E'\n'||current_setting('app.tenant_nonce',true)||E'\n'||p_body,'UTF8'),secret_value,'sha256'),'hex');
 IF secret_value IS NULL OR expected IS DISTINCT FROM p_proof THEN RAISE EXCEPTION 'Invalid transaction session attestation' USING ERRCODE='42501'; END IF;
 claims:=p_body::jsonb;
 IF jsonb_typeof(claims) IS DISTINCT FROM 'object' OR claims->>'subject' IS DISTINCT FROM current_setting('app.tenant_subject',true)
 OR claims->>'tenantId' IS DISTINCT FROM current_setting('app.tenant_id',true) OR claims->>'jti' !~ '^[A-Za-z0-9._~-]{16,128}$'
 OR jsonb_typeof(claims->'issuedAt') IS DISTINCT FROM 'number' OR jsonb_typeof(claims->'expiresAt') IS DISTINCT FROM 'number'
 THEN RETURN false; END IF;
 issued:=(claims->>'issuedAt')::bigint; expires:=(claims->>'expiresAt')::bigint;
 IF jsonb_typeof(claims->'authTime')='number' THEN auth_epoch:=(claims->>'authTime')::bigint; END IF;
 now_epoch:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 IF issued>now_epoch+5 OR expires<=now_epoch OR expires<=issued OR expires-issued>900 THEN RETURN false; END IF;
 IF current_setting('transaction_read_only')='on' THEN
  SELECT id INTO actor FROM public.users WHERE auth_subject=claims->>'subject' AND auth_issuer=claims->>'issuer' AND status='active';
 ELSE
  SELECT id INTO actor FROM public.users WHERE auth_subject=claims->>'subject' AND auth_issuer=claims->>'issuer' AND status='active' FOR SHARE;
 END IF;
 IF actor IS NULL THEN RETURN false; END IF;
 SELECT revoked_through_epoch INTO cutoff FROM private.account_session_revocations WHERE user_id=actor;
 IF cutoff IS NOT NULL AND (issued<=cutoff OR auth_epoch IS NULL OR auth_epoch<=cutoff OR auth_epoch>issued OR auth_epoch>now_epoch) THEN RETURN false; END IF;
 IF EXISTS(SELECT 1 FROM private.individual_session_revocation_receipts r WHERE r.token_fingerprint=public.digest(convert_to(claims->>'jti','UTF8'),'sha256')) THEN RETURN false; END IF;
 IF current_setting('transaction_read_only')='on' THEN
  SELECT jti INTO session_key FROM private.auth_sessions WHERE jti=claims->>'jti' AND subject=claims->>'subject' AND issued_at=to_timestamp(issued) AND expires_at=to_timestamp(expires) AND revoked_at IS NULL;
 ELSE
  SELECT jti INTO session_key FROM private.auth_sessions WHERE jti=claims->>'jti' AND subject=claims->>'subject' AND issued_at=to_timestamp(issued) AND expires_at=to_timestamp(expires) AND revoked_at IS NULL FOR SHARE;
 END IF;
 RETURN session_key IS NOT NULL AND expires>floor(extract(epoch FROM clock_timestamp()))::bigint;
END
$fn$;
ALTER FUNCTION private.assert_admitted_tenant_session(text,text) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.assert_admitted_tenant_session(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.assert_admitted_tenant_session(text,text) TO profitpilot_app;
COMMIT;

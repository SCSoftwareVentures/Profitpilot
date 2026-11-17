-- Bind every signed tenant context to this database transaction and backend.
-- All existing RLS policies retain the same function OID through CREATE OR REPLACE.
BEGIN;
CREATE OR REPLACE FUNCTION private.current_tenant_id()
RETURNS uuid LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,private
AS $function$
DECLARE
 v_tenant uuid; v_subject text; v_expires bigint; v_nonce text;
 v_key_id text; v_signature text; v_secret bytea; v_payload text; v_expected text;
BEGIN
 v_tenant:=nullif(current_setting('app.tenant_id',true),'')::uuid;
 v_subject:=nullif(current_setting('app.tenant_subject',true),'');
 v_expires:=nullif(current_setting('app.tenant_expires',true),'')::bigint;
 v_nonce:=nullif(current_setting('app.tenant_nonce',true),'');
 v_key_id:=nullif(current_setting('app.tenant_key_id',true),'');
 v_signature:=lower(nullif(current_setting('app.tenant_signature',true),''));
 IF v_tenant IS NULL OR v_subject IS NULL OR v_expires IS NULL OR v_nonce IS NULL OR v_key_id IS NULL OR v_signature IS NULL THEN RETURN NULL; END IF;
 IF v_expires < floor(extract(epoch FROM statement_timestamp()))::bigint OR v_expires > floor(extract(epoch FROM statement_timestamp()))::bigint+60 THEN RETURN NULL; END IF;
 IF v_nonce !~ '^[a-f0-9]{32}$' OR v_signature !~ '^[a-f0-9]{64}$' THEN RETURN NULL; END IF;
 SELECT secret INTO v_secret FROM private.tenant_context_keys WHERE key_id=v_key_id AND active=true;
 IF v_secret IS NULL THEN RETURN NULL; END IF;
 v_payload:='profitpilot-tenant-context-v2'||E'\n'||txid_current()::text||E'\n'||pg_backend_pid()::text||E'\n'||v_tenant::text||E'\n'||v_subject||E'\n'||v_expires::text||E'\n'||v_nonce||E'\n'||v_key_id;
 v_expected:=encode(public.hmac(convert_to(v_payload,'UTF8'),v_secret,'sha256'),'hex');
 IF v_expected<>v_signature THEN RETURN NULL; END IF;
 IF NOT EXISTS(SELECT 1 FROM public.tenant_memberships tm JOIN public.users u ON u.id=tm.user_id JOIN public.tenants t ON t.id=tm.tenant_id WHERE tm.tenant_id=v_tenant AND u.auth_subject=v_subject AND tm.status='active' AND u.status='active' AND t.status='active') THEN RETURN NULL; END IF;
 RETURN v_tenant;
EXCEPTION WHEN OTHERS THEN RETURN NULL;
END;
$function$;

REVOKE ALL ON FUNCTION private.current_tenant_id() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.current_tenant_id() TO profitpilot_app;
COMMIT;

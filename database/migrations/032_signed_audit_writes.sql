-- Audit events require a signed, transaction-bound server attestation.
BEGIN;
CREATE FUNCTION private.append_verified_audit(p_body text,p_proof text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
DECLARE data jsonb; tenant uuid; actor uuid; secret_value bytea; expected text; permission text; kind text;
BEGIN
 tenant:=private.current_tenant_id();actor:=private.current_user_id();
 IF tenant IS NULL OR actor IS NULL OR p_body IS NULL OR octet_length(p_body)>65536
  OR p_proof IS NULL OR p_proof !~ '^[a-f0-9]{64}$' THEN
  RAISE EXCEPTION 'Invalid audit attestation' USING ERRCODE='42501'; END IF;
 SELECT secret INTO secret_value FROM private.tenant_context_keys
 WHERE key_id=current_setting('app.tenant_key_id',true) AND active;
 IF secret_value IS NULL THEN RAISE EXCEPTION 'Invalid audit attestation' USING ERRCODE='42501'; END IF;
 expected:=encode(public.hmac(convert_to('profitpilot-audit-write-v1'||E'\n'||current_setting('app.tenant_nonce',true)||E'\n'||p_body,'UTF8'),secret_value,'sha256'),'hex');
 IF expected IS DISTINCT FROM p_proof THEN RAISE EXCEPTION 'Invalid audit attestation' USING ERRCODE='42501'; END IF;
 data:=p_body::jsonb;
 IF data->>'tenantId' IS DISTINCT FROM tenant::text OR data->>'actorId' IS DISTINCT FROM actor::text
  OR jsonb_typeof(data->'metadata') IS DISTINCT FROM 'object'
  OR length(btrim(coalesce(data->>'reason',''))) NOT BETWEEN 3 AND 2000 THEN
  RAISE EXCEPTION 'Invalid audit actor or evidence' USING ERRCODE='42501'; END IF;
 SELECT v.permission,v.kind INTO permission,kind FROM (VALUES
  ('member_permission_override_set','security.permissions.manage','tenant_membership_permission_override'),
  ('member_permission_override_removed','security.permissions.manage','tenant_membership_permission_override'),
  ('privacy_request_submitted','privacy.requests.submit','privacy_request'),
  ('shared_overhead_proposed','matching.decide','match_review'),
  ('invoice_match_decision','matching.decide','match_review'),
  ('invoice_batch_prepared','matching.decide','import_batch'),
  ('calculation_created','calculations.create','calculation_run'),
  ('payroll_source_row_decision','payroll.rows.decide','mapping_decision'),
  ('payroll_pool_reconciled','payroll.pools.reconcile','payroll_pool'),
  ('payroll_allocation_drafted','payroll.allocations.draft','allocation_run'),
  ('payroll_allocation_confirmed','payroll.allocations.confirm','allocation_run')
 ) v(action,permission,kind) WHERE v.action=data->>'action';
 IF permission IS NULL OR data->>'objectType' IS DISTINCT FROM kind
  OR private.has_scoped_permission(tenant,permission) IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'Audit action not permitted' USING ERRCODE='42501'; END IF;
 INSERT INTO public.audit_events(id,tenant_id,actor_user_id,action,object_type,object_id,reason,metadata)
 VALUES((data->>'id')::uuid,tenant,actor,data->>'action',kind,(data->>'objectId')::uuid,data->>'reason',data->'metadata');
END
$fn$;
ALTER FUNCTION private.append_verified_audit(text,text) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.append_verified_audit(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.append_verified_audit(text,text) TO profitpilot_app;
REVOKE INSERT ON public.audit_events FROM profitpilot_app,PUBLIC;
COMMIT;

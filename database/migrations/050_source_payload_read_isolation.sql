-- Raw source payloads may only be read via a signed, batch- and purpose-bound operation.
BEGIN;
REVOKE SELECT ON public.raw_import_rows FROM PUBLIC,profitpilot_app;
GRANT SELECT(id,tenant_id,batch_id,row_number,created_at) ON public.raw_import_rows TO profitpilot_app;
GRANT SELECT ON public.raw_import_rows,public.import_batches TO profitpilot_context_owner;
CREATE FUNCTION private.read_source_rows(p_tenant uuid,p_batch uuid,p_purpose text,p_auth_time bigint,p_proof text)
RETURNS TABLE(id uuid,tenant_id uuid,batch_id uuid,row_number integer,payload jsonb)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
DECLARE actor uuid; secret_value bytea; expected text; item public.import_batches%ROWTYPE; needs_mfa boolean;
BEGIN
 IF private.current_tenant_id() IS DISTINCT FROM p_tenant OR p_batch IS NULL OR p_tenant IS NULL OR p_proof IS NULL OR p_proof !~ '^[a-f0-9]{64}$'
 THEN RAISE EXCEPTION 'Source read attestation required' USING ERRCODE='42501'; END IF;
 actor:=private.current_user_id();
 IF actor IS NULL THEN RAISE EXCEPTION 'Source read actor required' USING ERRCODE='42501'; END IF;
 IF p_purpose IS NULL OR p_purpose NOT IN ('compare','validate','payroll_reconcile','invoice_prepare','reconcile')
 THEN RAISE EXCEPTION 'Source read purpose denied' USING ERRCODE='42501'; END IF;
 needs_mfa:=p_purpose IN ('payroll_reconcile','invoice_prepare','reconcile');
 IF needs_mfa THEN
  PERFORM private.assert_privacy_step_up(p_tenant,p_batch,'source_read:'||p_purpose,p_auth_time,p_proof);
 ELSE
  IF p_auth_time IS DISTINCT FROM 0 THEN RAISE EXCEPTION 'Invalid source read attestation' USING ERRCODE='42501'; END IF;
  SELECT k.secret INTO secret_value FROM private.tenant_context_keys k WHERE k.key_id=current_setting('app.tenant_key_id',true) AND k.active;
  IF secret_value IS NULL THEN RAISE EXCEPTION 'Invalid source read attestation' USING ERRCODE='42501'; END IF;
  expected:=encode(public.hmac(convert_to('profitpilot-privacy-step-up-v1'||E'\n'||p_tenant::text||E'\n'||actor::text||E'\n'||p_batch::text||E'\n'||'source_read:'||p_purpose||E'\n0\n'||current_setting('app.tenant_nonce',true),'UTF8'),secret_value,'sha256'),'hex');
  IF expected IS DISTINCT FROM p_proof THEN RAISE EXCEPTION 'Invalid source read attestation' USING ERRCODE='42501'; END IF;
 END IF;
 SELECT * INTO item FROM public.import_batches b WHERE b.tenant_id=p_tenant AND b.id=p_batch;
 IF NOT FOUND THEN RETURN; END IF;
 IF (CASE p_purpose
  WHEN 'compare' THEN item.created_by=actor AND private.has_scoped_permission(p_tenant,'imports.rows.write') IS TRUE AND item.status IN ('uploaded','review','validating')
  WHEN 'validate' THEN private.has_scoped_permission(p_tenant,'imports.validate') IS TRUE AND item.status IN ('uploaded','review','validating')
  WHEN 'payroll_reconcile' THEN item.source_type='payroll' AND item.created_by<>actor AND item.status='review' AND private.has_scoped_permission(p_tenant,'payroll.pools.reconcile') IS TRUE
  WHEN 'invoice_prepare' THEN item.source_type IN ('customer_invoice','supplier_invoice') AND item.created_by<>actor AND item.status='review' AND private.has_scoped_permission(p_tenant,'matching.decide') IS TRUE
  WHEN 'reconcile' THEN private.has_scoped_permission(p_tenant,'matching.decide') IS TRUE AND private.has_scoped_permission(p_tenant,'payroll.allocations.read') IS TRUE
  ELSE false END) IS DISTINCT FROM true
 THEN RAISE EXCEPTION 'Source read purpose or permission denied' USING ERRCODE='42501'; END IF;
 RETURN QUERY SELECT r.id,r.tenant_id,r.batch_id,r.row_number,r.payload FROM public.raw_import_rows r
 WHERE r.tenant_id=p_tenant AND r.batch_id=p_batch ORDER BY r.row_number LIMIT 201;
END
$fn$;
ALTER FUNCTION private.read_source_rows(uuid,uuid,text,bigint,text) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.read_source_rows(uuid,uuid,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.read_source_rows(uuid,uuid,text,bigint,text) TO profitpilot_app;
COMMIT;

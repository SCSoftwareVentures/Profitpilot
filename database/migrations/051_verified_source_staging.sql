-- Complete source ingestion only through a signed, bounded, atomic staging function.
BEGIN;
REVOKE INSERT ON public.raw_import_rows FROM PUBLIC,profitpilot_app;
REVOKE INSERT(tenant_id,batch_id,row_number,payload) ON public.raw_import_rows FROM PUBLIC,profitpilot_app;
GRANT INSERT(tenant_id,batch_id,row_number,payload) ON public.raw_import_rows TO profitpilot_context_owner;

CREATE FUNCTION private.valid_source_payload(p_type text,p_row jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $fn$
DECLARE field record; cap integer; cell text;
BEGIN
 IF p_type NOT IN ('payroll','customer_invoice','supplier_invoice') OR jsonb_typeof(p_row) IS DISTINCT FROM 'object' OR p_row='{}'::jsonb THEN RETURN false; END IF;
 FOR field IN SELECT key,value FROM jsonb_each(p_row) LOOP
  cap:=CASE WHEN p_type='payroll' THEN CASE field.key WHEN 'source_ref' THEN 120 WHEN 'cost_component' THEN 120 WHEN 'amount' THEN 32 WHEN 'currency' THEN 16 WHEN 'period_start' THEN 32 WHEN 'period_end' THEN 32 END
  ELSE CASE field.key WHEN 'invoice_id' THEN 80 WHEN 'site' THEN 120 WHEN 'date' THEN 32 WHEN 'amount' THEN 32 WHEN 'currency' THEN 16 WHEN 'tax_basis' THEN 32 WHEN 'contract_id' THEN 64 WHEN 'site_id' THEN 64 WHEN 'service_start' THEN 32 WHEN 'service_end' THEN 32 WHEN 'description' THEN 500 WHEN 'line_number' THEN 16 END END;
  IF cap IS NULL THEN RETURN false; END IF;
  IF field.key='line_number' AND jsonb_typeof(field.value)='number' THEN
   IF (field.value::text)::numeric<0 OR (field.value::text)::numeric>9999999 OR trunc((field.value::text)::numeric)<>(field.value::text)::numeric THEN RETURN false; END IF;
  ELSE
   IF jsonb_typeof(field.value) IS DISTINCT FROM 'string' THEN RETURN false; END IF;
   cell:=field.value #>> '{}';
   IF length(cell)>cap OR cell ~ '[[:cntrl:]]' THEN RETURN false; END IF;
  END IF;
 END LOOP;
 RETURN true;
END
$fn$;
ALTER FUNCTION private.valid_source_payload(text,jsonb) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.valid_source_payload(text,jsonb) FROM PUBLIC,profitpilot_app;

CREATE FUNCTION private.stage_verified_source_rows(p_tenant uuid,p_batch uuid,p_body text,p_auth_time bigint,p_proof text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
DECLARE actor uuid; item public.import_batches%ROWTYPE; data jsonb; rows_data jsonb; mode_value text; action_value text; secret_value bytea; expected text; n integer; prior_count integer; prior_rows jsonb;
BEGIN
 IF private.current_tenant_id() IS DISTINCT FROM p_tenant OR p_tenant IS NULL OR p_batch IS NULL
 OR p_body IS NULL OR octet_length(p_body)>262144 OR p_proof IS NULL OR p_proof !~ '^[a-f0-9]{64}$'
 THEN RAISE EXCEPTION 'Source staging attestation required' USING ERRCODE='42501'; END IF;
 actor:=private.current_user_id();
 IF actor IS NULL OR private.has_scoped_permission(p_tenant,'imports.rows.write') IS DISTINCT FROM true THEN RAISE EXCEPTION 'Source staging permission required' USING ERRCODE='42501'; END IF;
 data:=p_body::jsonb;
 mode_value:=data->>'mode'; rows_data:=data->'rows';
 IF jsonb_typeof(data) IS DISTINCT FROM 'object' OR mode_value IS NULL OR mode_value NOT IN ('json','csv') OR jsonb_typeof(rows_data) IS DISTINCT FROM 'array'
 THEN RAISE EXCEPTION 'Invalid source staging body' USING ERRCODE='22023'; END IF;
 action_value:='source_stage:'||mode_value||':'||encode(public.digest(convert_to(p_body,'UTF8'),'sha256'),'hex');
 IF mode_value='csv' THEN
  PERFORM private.assert_privacy_step_up(p_tenant,p_batch,action_value,p_auth_time,p_proof);
 ELSE
  IF p_auth_time IS DISTINCT FROM 0 THEN RAISE EXCEPTION 'Invalid source staging attestation' USING ERRCODE='42501'; END IF;
  SELECT k.secret INTO secret_value FROM private.tenant_context_keys k WHERE k.key_id=current_setting('app.tenant_key_id',true) AND k.active;
  expected:=encode(public.hmac(convert_to('profitpilot-privacy-step-up-v1'||E'\n'||p_tenant::text||E'\n'||actor::text||E'\n'||p_batch::text||E'\n'||action_value||E'\n0\n'||current_setting('app.tenant_nonce',true),'UTF8'),secret_value,'sha256'),'hex');
  IF secret_value IS NULL OR expected IS DISTINCT FROM p_proof THEN RAISE EXCEPTION 'Invalid source staging attestation' USING ERRCODE='42501'; END IF;
 END IF;
 SELECT * INTO item FROM public.import_batches b WHERE b.tenant_id=p_tenant AND b.id=p_batch FOR UPDATE;
 IF NOT FOUND THEN RETURN jsonb_build_object('status',404,'error','Import batch not found'); END IF;
 IF item.created_by<>actor THEN RETURN jsonb_build_object('status',403,'error','Only the original importer may stage rows'); END IF;
 IF item.status NOT IN ('uploaded','review','validating') THEN RETURN jsonb_build_object('status',409,'error','Import batch is not open'); END IF;
 PERFORM private.lock_privacy_retention_subject(p_tenant,actor);
 IF EXISTS(SELECT 1 FROM private.source_ingestion_restrictions r WHERE r.tenant_id=p_tenant AND r.user_id=actor AND r.released_at IS NULL)
 THEN RAISE EXCEPTION 'Source ingestion is restricted' USING ERRCODE='PPR01'; END IF;
 IF mode_value='csv' AND ((data->>'checksum') IS DISTINCT FROM item.file_sha256
 OR lower(right(item.file_name,4))<>'.csv' OR length(item.file_name) NOT BETWEEN 5 AND 254
 OR position('/' in item.file_name)>0 OR position(chr(92) in item.file_name)>0 OR item.file_name ~ '[[:cntrl:]]')
 THEN RETURN jsonb_build_object('status',422,'error','CSV checksum or registered filename is invalid'); END IF;
 IF mode_value='json' AND data->>'checksum' IS NOT NULL THEN RAISE EXCEPTION 'JSON submission cannot certify source bytes' USING ERRCODE='22023'; END IF;
 n:=jsonb_array_length(rows_data);
 IF n NOT BETWEEN 1 AND 200 OR EXISTS(SELECT 1 FROM jsonb_array_elements(rows_data) r(value) WHERE NOT private.valid_source_payload(item.source_type,r.value))
 THEN RETURN jsonb_build_object('status',422,'error','Source rows contain unsupported fields or excessive data'); END IF;
 SELECT count(*)::integer,jsonb_agg(r.payload ORDER BY r.row_number) INTO prior_count,prior_rows FROM public.raw_import_rows r WHERE r.tenant_id=p_tenant AND r.batch_id=p_batch;
 IF prior_count>0 THEN
  IF prior_rows IS DISTINCT FROM rows_data OR mode_value='csv' THEN RETURN jsonb_build_object('status',409,'error','Source batch already staged'); END IF;
  RETURN jsonb_build_object('status',201,'inserted',0,'received',n,'duplicates',n);
 END IF;
 INSERT INTO public.raw_import_rows(tenant_id,batch_id,row_number,payload)
 SELECT p_tenant,p_batch,r.ord::integer,r.value FROM jsonb_array_elements(rows_data) WITH ORDINALITY r(value,ord);
 UPDATE public.import_batches SET status='review' WHERE tenant_id=p_tenant AND id=p_batch;
 IF mode_value='csv' THEN
  INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata)
  VALUES(p_tenant,actor,'import_csv_staged','import_batch',p_batch,'CSV bytes matched declared source checksum',
  jsonb_build_object('sha256',item.file_sha256,'rowCount',n,'rawFilePersisted',false));
 END IF;
 RETURN jsonb_build_object('status',201,'inserted',n,'received',n,'duplicates',0);
END
$fn$;
ALTER FUNCTION private.stage_verified_source_rows(uuid,uuid,text,bigint,text) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.stage_verified_source_rows(uuid,uuid,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.stage_verified_source_rows(uuid,uuid,text,bigint,text) TO profitpilot_app;
COMMIT;

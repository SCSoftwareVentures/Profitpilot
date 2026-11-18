-- Real PostgreSQL synthetic correction acceptance; all changes roll back.
BEGIN;
DO $test$
DECLARE t uuid:=gen_random_uuid(); owner_id uuid:=gen_random_uuid(); admin_id uuid:=gen_random_uuid(); analyst_id uuid:=gen_random_uuid();
 biz uuid:=gen_random_uuid(); site uuid:=gen_random_uuid(); contract_id_value uuid:=gen_random_uuid(); old_calc uuid:=gen_random_uuid();
 batches uuid[]:=ARRAY[gen_random_uuid(),gen_random_uuid()]; pools uuid[]:=ARRAY[gen_random_uuid(),gen_random_uuid()];
 runs uuid[]:=ARRAY[gen_random_uuid(),gen_random_uuid()]; proposals uuid[]:=ARRAY[NULL::uuid,NULL::uuid]; digests text[]:=ARRAY[NULL::text,NULL::text];
 raw_id uuid; source_id uuid; amt numeric(14,2); ix integer; work_id uuid:=gen_random_uuid(); scope_hash text; correction_evidence text:=repeat('c',64);
 who text; actor uuid; phase text; now_s bigint; expiry bigint; nonce text; confirm_nonce text; key_id_value text; key_bytes bytea; session_hash text; context_sig text; proof text; confirmation text; total numeric; current_digest text;
BEGIN
 INSERT INTO public.tenants(id,legal_name) VALUES(t,'Synthetic payroll supersession');
 INSERT INTO public.users(id,auth_subject,email) VALUES(owner_id,'ci-correction-'||owner_id,'owner@example.invalid'),(admin_id,'ci-correction-'||admin_id,'admin@example.invalid'),(analyst_id,'ci-correction-'||analyst_id,'analyst@example.invalid');
 INSERT INTO public.tenant_memberships(tenant_id,user_id,role) VALUES(t,owner_id,'owner'),(t,admin_id,'admin'),(t,analyst_id,'analyst');
 INSERT INTO public.businesses(id,tenant_id,name) VALUES(biz,t,'Synthetic business');
 INSERT INTO public.sites(id,tenant_id,business_id,name) VALUES(site,t,biz,'Synthetic site');
 INSERT INTO public.contracts(id,tenant_id,business_id,customer_name) VALUES(contract_id_value,t,biz,'Synthetic customer');
 FOR ix IN 1..2 LOOP
  raw_id:=gen_random_uuid();source_id:=gen_random_uuid();amt:=CASE ix WHEN 1 THEN 0.30 ELSE 0.50 END;
  INSERT INTO public.import_batches(id,tenant_id,source_type,source_period_start,source_period_end,permission_ref,status,file_sha256,file_name,created_by)
  VALUES(batches[ix],t,'payroll','2026-11-01','2026-11-14','Synthetic authority','accepted',encode(public.digest(batches[ix]::text,'sha256'),'hex'),'synthetic.csv',analyst_id);
  INSERT INTO public.raw_import_rows(id,tenant_id,batch_id,row_number,payload) VALUES(raw_id,t,batches[ix],1,jsonb_build_object('source_row_key','row-a','amount',amt::text,'currency','AUD'));
  INSERT INTO public.payroll_pools(id,tenant_id,batch_id,period_start,period_end,total_amount,currency,source_ref) VALUES(pools[ix],t,batches[ix],'2026-11-01','2026-11-14',amt,'AUD','source-a');
  INSERT INTO public.payroll_source_rows(id,tenant_id,payroll_pool_id,raw_import_row_id,source_row_key,row_sha256,amount,currency)
  VALUES(source_id,t,pools[ix],raw_id,'row-a',encode(public.digest('row-a'||E'\n'||amt::text||E'\n'||'AUD','sha256'),'hex'),amt,'AUD');
  INSERT INTO public.allocation_runs(id,tenant_id,payroll_pool_id,method_version,status,direct_amount,residual_amount) VALUES(runs[ix],t,pools[ix],'synthetic-v1','review',amt,0);
  INSERT INTO public.allocation_lines(tenant_id,allocation_run_id,site_id,bucket_type,amount,source_ref,payroll_source_row_id)
  VALUES(t,runs[ix],site,'direct',amt,'evidence-a',source_id);
 END LOOP;
 SELECT key_id,secret INTO key_id_value,key_bytes FROM private.tenant_context_keys WHERE active ORDER BY key_id LIMIT 1;
 FOREACH phase IN ARRAY ARRAY['submit','old_confirm','request','approve','consume'] LOOP
  actor:=CASE phase WHEN 'submit' THEN analyst_id WHEN 'approve' THEN admin_id ELSE owner_id END;
  who:='ci-correction-'||actor;
  now_s:=floor(extract(epoch FROM clock_timestamp()))::bigint;expiry:=now_s+20;
  nonce:=encode(public.gen_random_bytes(16),'hex');confirm_nonce:=encode(public.gen_random_bytes(16),'hex');
  session_hash:=encode(public.digest(actor::text,'sha256'),'hex');
  context_sig:=encode(public.hmac(convert_to(t::text||E'\n'||who||E'\n'||expiry||E'\n'||nonce||E'\n'||key_id_value,'UTF8'),key_bytes,'sha256'),'hex');
  PERFORM set_config('app.tenant_id',t::text,true),set_config('app.tenant_subject',who,true),set_config('app.tenant_expires',expiry::text,true),set_config('app.tenant_nonce',nonce,true),set_config('app.tenant_key_id',key_id_value,true),set_config('app.tenant_signature',context_sig,true);
  IF phase='submit' THEN
   FOR ix IN 1..2 LOOP
    proposals[ix]:=private.submit_payroll_proposal(t,runs[ix]);
    SELECT evidence_digest INTO current_digest FROM private.payroll_proposal_reviews WHERE tenant_id=t AND id=proposals[ix];
    digests[ix]:=current_digest;
   END LOOP;
  ELSIF phase='old_confirm' THEN
   confirmation:=encode(public.hmac(convert_to('profitpilot-payroll-confirm-v1'||E'\n'||t||E'\n'||proposals[1]||E'\n'||digests[1]||E'\n'||who||E'\n'||now_s||E'\n'||now_s||E'\n'||session_hash||E'\n'||expiry||E'\n'||confirm_nonce||E'\n'||key_id_value,'UTF8'),key_bytes,'sha256'),'hex');
   PERFORM private.confirm_payroll_proposal_attested(t,proposals[1],digests[1],now_s,now_s,session_hash,expiry,confirm_nonce,key_id_value,confirmation);
   SELECT amount INTO total FROM private.site_payroll_summary(t,site,'2026-11-01','2026-11-14');
   IF total<>0.30 THEN RAISE EXCEPTION 'Original payroll summary incorrect'; END IF;
   INSERT INTO public.calculation_runs(id,tenant_id,contract_id,site_id,period_start,period_end,formula_version,inputs,outputs,completeness,created_by)
   VALUES(old_calc,t,contract_id_value,site,'2026-11-01','2026-11-14','0.1.0','{}','{}','incomplete',owner_id);
  ELSE
   IF phase='request' THEN scope_hash:=private.payroll_correction_scope(t,runs[1],proposals[2],'source_correction',correction_evidence); END IF;
   proof:=encode(public.hmac(convert_to('profitpilot-security-work-v1'||E'\n'||t||E'\n'||work_id||E'\n'||'privileged_operation'||E'\n'||scope_hash||E'\n'||phase||E'\n'||who||E'\n'||now_s||E'\n'||now_s||E'\n'||session_hash||E'\n'||expiry||E'\n'||nonce||E'\n'||key_id_value,'UTF8'),key_bytes,'sha256'),'hex');
   confirmation:=encode(public.hmac(convert_to('profitpilot-payroll-confirm-v1'||E'\n'||t||E'\n'||proposals[2]||E'\n'||digests[2]||E'\n'||who||E'\n'||now_s||E'\n'||now_s||E'\n'||session_hash||E'\n'||expiry||E'\n'||confirm_nonce||E'\n'||key_id_value,'UTF8'),key_bytes,'sha256'),'hex');
   IF phase='request' THEN
    PERFORM private.request_payroll_correction(t,work_id,runs[1],proposals[2],'source_correction',correction_evidence,scope_hash,now_s,now_s,session_hash,expiry,nonce,key_id_value,proof);
    BEGIN
     PERFORM private.confirm_payroll_proposal_attested(t,proposals[2],digests[2],now_s,now_s,session_hash,expiry,confirm_nonce,key_id_value,confirmation);
     RAISE EXCEPTION 'Ordinary confirmation bypassed replacement reservation';
    EXCEPTION WHEN insufficient_privilege THEN NULL; END;
    IF EXISTS(SELECT 1 FROM private.payroll_confirmation_receipts WHERE tenant_id=t AND allocation_run_id=runs[2]) THEN RAISE EXCEPTION 'Partial confirmation survived'; END IF;
   ELSIF phase='approve' THEN
    PERFORM private.record_security_work(t,work_id,'privileged_operation',scope_hash,'approve',now_s,now_s,session_hash,expiry,nonce,key_id_value,proof);
   ELSE
    BEGIN
     PERFORM private.execute_payroll_correction(t,work_id,scope_hash,now_s,now_s,session_hash,expiry,nonce,key_id_value,proof,confirm_nonce,repeat('f',64));
     RAISE EXCEPTION 'Forged replacement confirmation accepted';
    EXCEPTION WHEN insufficient_privilege THEN NULL; END;
    IF EXISTS(SELECT 1 FROM private.payroll_supersessions WHERE tenant_id=t) OR EXISTS(SELECT 1 FROM private.security_work_consumptions WHERE tenant_id=t AND order_id=work_id) THEN RAISE EXCEPTION 'Partial correction survived'; END IF;
    IF private.execute_payroll_correction(t,work_id,scope_hash,now_s,now_s,session_hash,expiry,nonce,key_id_value,proof,confirm_nonce,confirmation) IS DISTINCT FROM runs[2] THEN RAISE EXCEPTION 'Wrong correction'; END IF;
    SELECT amount INTO total FROM private.site_payroll_summary(t,site,'2026-11-01','2026-11-14');
    IF total<>0.50 THEN RAISE EXCEPTION 'Superseded payroll double-counted'; END IF;
    IF (private.payroll_api_summary(t,proposals[1])->>'status') IS DISTINCT FROM 'superseded' THEN RAISE EXCEPTION 'Old proposal not flagged'; END IF;
    BEGIN PERFORM private.read_calculation_summary(t,old_calc); RAISE EXCEPTION 'Stale calculation read allowed'; EXCEPTION WHEN SQLSTATE 'P4502' THEN NULL; END;
    BEGIN PERFORM private.export_calculation_summary(t,old_calc,'internal_review'); RAISE EXCEPTION 'Stale calculation export allowed'; EXCEPTION WHEN SQLSTATE 'P4502' THEN NULL; END;
    BEGIN PERFORM private.execute_payroll_correction(t,work_id,scope_hash,now_s,now_s,session_hash,expiry,nonce,key_id_value,proof,confirm_nonce,confirmation);
     RAISE EXCEPTION 'Correction replay accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
   END IF;
  END IF;
 END LOOP;
 IF (SELECT count(*) FROM private.payroll_confirmation_receipts WHERE tenant_id=t)<>2
 OR (SELECT count(*) FROM private.payroll_supersessions WHERE tenant_id=t AND old_run_id=runs[1] AND new_run_id=runs[2])<>1
 OR private.verify_audit_chain(t) IS DISTINCT FROM true THEN RAISE EXCEPTION 'Correction receipts or audit missing'; END IF;
 BEGIN UPDATE public.payroll_pools SET total_amount=0 WHERE id=pools[1]; RAISE EXCEPTION 'Original evidence mutable'; EXCEPTION WHEN object_not_in_prerequisite_state THEN NULL; END;
 BEGIN DELETE FROM private.payroll_supersessions WHERE tenant_id=t; RAISE EXCEPTION 'Correction ledger mutable'; EXCEPTION WHEN object_not_in_prerequisite_state THEN NULL; END;
 IF has_function_privilege('profitpilot_app','private.execute_payroll_correction(uuid,uuid,text,bigint,bigint,text,bigint,text,text,text,text,text)','EXECUTE')
 OR has_any_column_privilege('profitpilot_app','private.payroll_supersessions','SELECT,INSERT,UPDATE,REFERENCES') THEN RAISE EXCEPTION 'Correction internals exposed'; END IF;
 RAISE NOTICE 'Atomic payroll supersession, bypass denial, rollback, replay, stale-report fence, audit and original evidence immutability checks passed';
END $test$;
-- Check deferred link to the new confirmation receipt before rolling back.
SET CONSTRAINTS ALL IMMEDIATE;
ROLLBACK;

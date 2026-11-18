-- Private intake fixture, synthetic only.
BEGIN;
DO $test$
DECLARE t uuid:=gen_random_uuid(); a uuid:=gen_random_uuid(); v uuid:=gen_random_uuid(); b uuid:=gen_random_uuid(); p uuid:=gen_random_uuid(); o uuid:=gen_random_uuid(); ns uuid:=gen_random_uuid();
 key1 text:='ppr_'||repeat('a',64);key2 text:='ppr_'||repeat('b',64); rows jsonb; file_hash text; scope_hash text;
 e text:=repeat('c',64); policy text:=repeat('d',64); control_hash text:=repeat('e',64); actor uuid; phase text; step text; who text; now_s bigint; expires bigint; nonce text; key_id_value text; secret_value bytea; session_hash text; context_sig text; proof text;
BEGIN
 INSERT INTO public.tenants(id,legal_name) VALUES(t,'Synthetic minimized payroll intake');
 INSERT INTO public.users(id,auth_subject,email) VALUES(a,'ci-payroll-intake-'||a,'synthetic@example.invalid'),(v,'ci-payroll-intake-'||v,'synthetic@example.invalid');
 INSERT INTO public.tenant_memberships(tenant_id,user_id,role) VALUES(t,a,'owner'),(t,v,'admin');
 rows:=jsonb_build_array(jsonb_build_object('source_row_key',key1,'amount','0.10','currency','AUD'),jsonb_build_object('source_row_key',key2,'amount','0.20','currency','AUD'));
 file_hash:=encode(public.digest(convert_to('source_row_key,amount,currency'||E'\n'||key1||',0.10,AUD'||E'\n'||key2||',0.20,AUD'||E'\n','UTF8'),'sha256'),'hex');
 INSERT INTO public.import_batches(id,tenant_id,source_type,source_period_start,source_period_end,permission_ref,status,file_sha256,file_name,created_by)
 VALUES(b,t,'payroll','2026-11-01','2026-11-14','reviewed-payroll-authority','registered',file_hash,'minimized-payroll-v1.csv',a);
 SELECT key_id,secret INTO key_id_value,secret_value FROM private.tenant_context_keys WHERE active ORDER BY key_id LIMIT 1;
 FOREACH phase IN ARRAY ARRAY['request','self','approve','consume'] LOOP
  actor:=CASE phase WHEN 'approve' THEN v ELSE a END;step:=CASE phase WHEN 'self' THEN 'approve' ELSE phase END;
  who:='ci-payroll-intake-'||actor;now_s:=floor(extract(epoch FROM clock_timestamp()))::bigint;expires:=now_s+20;
  nonce:=encode(public.gen_random_bytes(16),'hex');session_hash:=encode(public.digest(actor::text,'sha256'),'hex');
  context_sig:=encode(public.hmac(convert_to(t::text||E'\n'||who||E'\n'||expires||E'\n'||nonce||E'\n'||key_id_value,'UTF8'),secret_value,'sha256'),'hex');
  PERFORM set_config('app.tenant_id',t::text,true),set_config('app.tenant_subject',who,true),set_config('app.tenant_expires',expires::text,true),set_config('app.tenant_nonce',nonce,true),set_config('app.tenant_key_id',key_id_value,true),set_config('app.tenant_signature',context_sig,true);
  scope_hash:=private.payroll_intake_scope(t,b,p,o,ns,'0.30',2,e,policy,control_hash,rows);
  proof:=encode(public.hmac(convert_to('profitpilot-security-work-v1'||E'\n'||t||E'\n'||o||E'\n'||'privileged_operation'||E'\n'||scope_hash||E'\n'||step||E'\n'||who||E'\n'||now_s||E'\n'||now_s||E'\n'||session_hash||E'\n'||expires||E'\n'||nonce||E'\n'||key_id_value,'UTF8'),secret_value,'sha256'),'hex');
  BEGIN PERFORM private.payroll_intake_scope(t,b,p,o,ns,'0.31',2,e,policy,control_hash,rows);RAISE EXCEPTION 'False control total accepted';EXCEPTION WHEN check_violation THEN NULL;END;
  BEGIN PERFORM private.payroll_intake_scope(t,b,p,o,ns,'0.30',2,e,policy,control_hash,jsonb_set(rows,'{0,employee}',to_jsonb('synthetic'::text)));RAISE EXCEPTION 'Personal column admitted';EXCEPTION WHEN check_violation THEN NULL;END;
  BEGIN PERFORM private.payroll_intake_scope(t,b,p,o,ns,'0.30',2,e,policy,control_hash,jsonb_build_array(rows->1,rows->0));RAISE EXCEPTION 'Reordered file accepted';EXCEPTION WHEN check_violation THEN NULL;END;
  BEGIN PERFORM private.record_payroll_intake(t,b,p,o,ns,'0.30',2,e,repeat('f',64),control_hash,rows,scope_hash,step,now_s,now_s,session_hash,expires,nonce,key_id_value,proof);RAISE EXCEPTION 'Evidence substitution accepted';EXCEPTION WHEN insufficient_privilege THEN NULL;END;
  IF phase='self' THEN
   BEGIN PERFORM private.record_payroll_intake(t,b,p,o,ns,'0.30',2,e,policy,control_hash,rows,scope_hash,step,now_s,now_s,session_hash,expires,nonce,key_id_value,proof);RAISE EXCEPTION 'Self approval accepted';EXCEPTION WHEN insufficient_privilege THEN NULL;END;
  ELSE
   PERFORM private.record_payroll_intake(t,b,p,o,ns,'0.30',2,e,policy,control_hash,rows,scope_hash,step,now_s,now_s,session_hash,expires,nonce,key_id_value,proof);
   IF phase<>'consume' AND EXISTS(SELECT 1 FROM public.raw_import_rows WHERE tenant_id=t AND batch_id=b) THEN RAISE EXCEPTION 'Premature rows persisted';END IF;
  END IF;
 END LOOP;
 IF (SELECT status FROM public.import_batches WHERE tenant_id=t AND id=b)<>'accepted'
 OR (SELECT count(*) FROM public.payroll_source_rows WHERE tenant_id=t AND payroll_pool_id=p)<>2
 OR (SELECT sum(amount) FROM public.payroll_source_rows WHERE tenant_id=t AND payroll_pool_id=p)<>0.30
 OR NOT EXISTS(SELECT 1 FROM private.payroll_intake_receipts WHERE tenant_id=t AND batch_id=b AND pool_id=p AND file_digest=file_hash)
 OR EXISTS(SELECT 1 FROM public.allocation_runs WHERE tenant_id=t AND payroll_pool_id=p)
 OR private.verify_audit_chain(t) IS DISTINCT FROM true THEN RAISE EXCEPTION 'Intake atomicity/reconciliation failure';END IF;
 BEGIN PERFORM private.record_payroll_intake(t,b,p,o,ns,'0.30',2,e,policy,control_hash,rows,scope_hash,step,now_s,now_s,session_hash,expires,nonce,key_id_value,proof);RAISE EXCEPTION 'Replay admitted';EXCEPTION WHEN check_violation THEN NULL;END;
 BEGIN UPDATE public.raw_import_rows SET payload='{}' WHERE tenant_id=t AND batch_id=b;RAISE EXCEPTION 'Raw source mutable';EXCEPTION WHEN object_not_in_prerequisite_state THEN NULL;END;
 BEGIN UPDATE public.payroll_pools SET total_amount=100 WHERE tenant_id=t AND id=p;RAISE EXCEPTION 'Pool mutable';EXCEPTION WHEN object_not_in_prerequisite_state THEN NULL;END;
 BEGIN INSERT INTO public.raw_import_rows(tenant_id,batch_id,row_number,payload) VALUES(t,b,3,'{}');RAISE EXCEPTION 'Late appended source';EXCEPTION WHEN object_not_in_prerequisite_state THEN NULL;END;
 IF has_function_privilege('profitpilot_app','private.record_payroll_intake(uuid,uuid,uuid,uuid,uuid,text,integer,text,text,text,jsonb,text,text,bigint,bigint,text,bigint,text,text,text)','EXECUTE')
 OR has_any_column_privilege('profitpilot_app','private.payroll_intake_receipts','SELECT,INSERT,UPDATE,REFERENCES') THEN RAISE EXCEPTION 'Restricted intake exposed';END IF;
 RAISE NOTICE 'Reviewed minimized payroll intake: exact file hash, totals, independent approval, immutability and runtime denial passed';
END $test$;
\if :{?persist_recovery_fixture}
 \if :persist_recovery_fixture
  COMMIT;
 \else
  ROLLBACK;
 \endif
\else
 ROLLBACK;
\endif

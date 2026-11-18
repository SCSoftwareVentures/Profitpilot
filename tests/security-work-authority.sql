-- Synthetic only; all rows rolled back.
BEGIN;
DO $test$
DECLARE t uuid:=gen_random_uuid(); other_t uuid:=gen_random_uuid(); a uuid:=gen_random_uuid(); b uuid:=gen_random_uuid(); r uuid:=gen_random_uuid();
 work_id uuid:=gen_random_uuid(); batch uuid:=gen_random_uuid(); who text; actor_id uuid; step text; scope_hash text:=repeat('b',64); kind text:='privacy_access';
 key_id_value text; key_bytes bytea; now_s bigint; expiry bigint; nonce text; sig text; session_hash text; context_sig text; approver_session text;
BEGIN
 INSERT INTO public.tenants(id,legal_name) VALUES(t,'Synthetic work authorisation'),(other_t,'Synthetic other');
 INSERT INTO public.users(id,auth_subject,email) VALUES(a,'ci-work-a-'||a,'synthetic@example.invalid'),(b,'ci-work-b-'||b,'synthetic@example.invalid'),(r,'ci-work-reader-'||r,'synthetic@example.invalid');
 INSERT INTO public.tenant_memberships(tenant_id,user_id,role) VALUES(t,a,'owner'),(t,b,'admin'),(t,r,'read_only'),(other_t,b,'admin');
 INSERT INTO public.import_batches(id,tenant_id,source_type,source_period_start,source_period_end,permission_ref,status,file_sha256,file_name,created_by)
 VALUES(batch,t,'customer_invoice','2026-11-01','2026-11-14','Synthetic authority','rejected',encode(public.digest(batch::text,'sha256'),'hex'),'synthetic.csv',a);
 INSERT INTO public.raw_import_rows(tenant_id,batch_id,row_number,payload) VALUES(t,batch,1,'{"invoice_id":"INV-1"}');
 PERFORM private.approve_import_disposal(t,batch,clock_timestamp()-interval '1 day','CI_WORK_DISPOSAL');
 SELECT key_id,secret INTO key_id_value,key_bytes FROM private.tenant_context_keys WHERE active ORDER BY key_id LIMIT 1;
 IF key_id_value IS NULL THEN RAISE EXCEPTION 'Missing CI authority'; END IF;
 FOREACH kind IN ARRAY ARRAY['privacy_access','privacy_disposal'] LOOP
 work_id:=gen_random_uuid(); scope_hash:=repeat('b',64);
 FOREACH step IN ARRAY ARRAY['request','self','reader','approve','consume'] LOOP
  actor_id:=CASE step WHEN 'approve' THEN b WHEN 'reader' THEN r ELSE a END;
  who:=CASE actor_id WHEN a THEN 'ci-work-a-'||a WHEN b THEN 'ci-work-b-'||b ELSE 'ci-work-reader-'||r END;
  now_s:=floor(extract(epoch FROM clock_timestamp()))::bigint; expiry:=now_s+20;
  nonce:=encode(public.gen_random_bytes(16),'hex');
  session_hash:=encode(public.digest(actor_id::text,'sha256'),'hex');
  context_sig:=encode(public.hmac(convert_to(t::text||E'\n'||who||E'\n'||expiry||E'\n'||nonce||E'\n'||key_id_value,'UTF8'),key_bytes,'sha256'),'hex');
  PERFORM set_config('app.tenant_id',t::text,true),set_config('app.tenant_subject',who,true),
   set_config('app.tenant_expires',expiry::text,true),set_config('app.tenant_nonce',nonce,true),
   set_config('app.tenant_key_id',key_id_value,true),set_config('app.tenant_signature',context_sig,true);
  IF kind='privacy_disposal' AND step='request' THEN scope_hash:=private.invoice_disposal_work_scope(t,batch); END IF;
  sig:=encode(public.hmac(convert_to('profitpilot-security-work-v1'||E'\n'||t||E'\n'||work_id||E'\n'||kind||E'\n'||scope_hash||E'\n'||CASE WHEN step IN ('self','reader') THEN 'approve' ELSE step END||E'\n'||who||E'\n'||now_s||E'\n'||now_s||E'\n'||session_hash||E'\n'||expiry||E'\n'||nonce||E'\n'||key_id_value,'UTF8'),key_bytes,'sha256'),'hex');
  IF step='request' THEN
   PERFORM private.record_security_work(t,work_id,kind,scope_hash,step,now_s,now_s,session_hash,expiry,nonce,key_id_value,sig);
  ELSIF step IN ('self','reader') THEN
   BEGIN PERFORM private.record_security_work(t,work_id,kind,scope_hash,'approve',now_s,now_s,session_hash,expiry,nonce,key_id_value,sig);
    RAISE EXCEPTION 'Unauthorised approval accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
  ELSIF step='approve' THEN
   BEGIN PERFORM private.record_security_work(t,work_id,kind,repeat('c',64),step,now_s,now_s,session_hash,expiry,nonce,key_id_value,sig);
    RAISE EXCEPTION 'Scope tampering accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
   BEGIN PERFORM private.record_security_work(other_t,work_id,kind,scope_hash,step,now_s,now_s,session_hash,expiry,nonce,key_id_value,sig);
    RAISE EXCEPTION 'Cross-tenant approval accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
   PERFORM private.record_security_work(t,work_id,kind,scope_hash,step,now_s,now_s,session_hash,expiry,nonce,key_id_value,sig);
   approver_session:=session_hash;
  ELSE
   BEGIN
    INSERT INTO private.revoked_identity_sessions(user_id,session_digest) VALUES(b,approver_session);
    PERFORM private.record_security_work(t,work_id,kind,scope_hash,step,now_s,now_s,session_hash,expiry,nonce,key_id_value,sig);
    RAISE EXCEPTION 'Revoked approval accepted';
   EXCEPTION WHEN insufficient_privilege THEN NULL; END;
   IF kind='privacy_disposal' THEN
    IF private.execute_attested_invoice_disposal(t,work_id,batch,scope_hash,now_s,now_s,session_hash,expiry,nonce,key_id_value,sig)<>1 THEN
     RAISE EXCEPTION 'Attested staging disposal failed'; END IF;
    IF EXISTS(SELECT 1 FROM public.import_batches WHERE tenant_id=t AND id=batch)
    OR NOT EXISTS(SELECT 1 FROM private.import_disposal_tombstones WHERE tenant_id=t AND batch_id=batch) THEN RAISE EXCEPTION 'Disposal tombstone missing'; END IF;
   ELSE
    PERFORM private.record_security_work(t,work_id,kind,scope_hash,step,now_s,now_s,session_hash,expiry,nonce,key_id_value,sig);
   END IF;
   BEGIN PERFORM private.record_security_work(t,work_id,kind,scope_hash,step,now_s,now_s,session_hash,expiry,nonce,key_id_value,sig);
    RAISE EXCEPTION 'Consumed approval replayed'; EXCEPTION WHEN unique_violation THEN NULL; END;
  END IF;
 END LOOP;
 IF (SELECT count(*) FROM private.security_work_consumptions WHERE tenant_id=t AND order_id=work_id)<>1
 OR (SELECT count(*) FROM public.audit_events WHERE tenant_id=t AND object_id=work_id)<>3
 OR private.verify_audit_chain(t) IS DISTINCT FROM true THEN RAISE EXCEPTION 'Work audit or atomicity failed'; END IF;
 END LOOP;
 BEGIN DELETE FROM private.security_work_orders WHERE tenant_id=t; RAISE EXCEPTION 'Work history deletion accepted'; EXCEPTION WHEN object_not_in_prerequisite_state THEN NULL; END;
 IF has_function_privilege('profitpilot_app','private.record_security_work(uuid,uuid,text,text,text,bigint,bigint,text,bigint,text,text,text)','EXECUTE')
 OR has_any_column_privilege('profitpilot_app','private.security_work_orders','SELECT,INSERT,UPDATE,REFERENCES') THEN RAISE EXCEPTION 'Work ledger exposed to runtime'; END IF;
 IF private.import_reference_safe('date of birth',128,false) OR private.import_reference_safe('driver licence',128,false)
 OR private.import_reference_safe('medical record',128,false) OR private.import_reference_safe('ＡＢＣ',128,false)
 OR private.import_reference_safe(' API key',128,false) OR NOT private.import_reference_safe('INV-123',128,false)
 THEN RAISE EXCEPTION 'DLP regression'; END IF;
 RAISE NOTICE 'Security work authorisation, cross-tenant denial, revoked approval, replay, audit and DLP checks passed';
END $test$;
ROLLBACK;

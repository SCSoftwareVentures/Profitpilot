-- Synthetic assisted response authority; never uses real documents or keys.
BEGIN;
DO $test$
DECLARE t uuid:=gen_random_uuid(); other_t uuid:=gen_random_uuid(); a uuid:=gen_random_uuid(); b uuid:=gen_random_uuid(); r uuid:=gen_random_uuid();
 case_id_value uuid:=gen_random_uuid(); blocked_case uuid:=gen_random_uuid(); pending_case uuid:=gen_random_uuid(); order_id_value uuid:=gen_random_uuid();
 who text; actor uuid; phase text; actual_step text; scope_hash text; recipient text:=repeat('a',64); sender text:=repeat('b',64);
 authority text:=repeat('c',64); redaction text:=repeat('d',64); response_hash text:=repeat('e',64); envelope text:=repeat('f',64);
 now_s bigint; expires bigint; nonce text; session_hash text; context_sig text; proof text; key_id_value text; key_bytes bytea; approver_session text; receipt_review uuid; saved_fingerprint text;
BEGIN
 INSERT INTO public.tenants(id,legal_name) VALUES(t,'Synthetic assisted privacy delivery'),(other_t,'Synthetic other privacy delivery');
 INSERT INTO public.users(id,auth_subject,email) VALUES(a,'ci-delivery-'||a,'owner@example.invalid'),(b,'ci-delivery-'||b,'admin@example.invalid'),(r,'ci-delivery-'||r,'reader@example.invalid');
 INSERT INTO public.tenant_memberships(tenant_id,user_id,role) VALUES(t,a,'owner'),(t,b,'admin'),(t,r,'read_only'),(other_t,b,'admin');
 INSERT INTO private.privacy_rights_cases(tenant_id,id,kind,channel,opened_by,authority_digest) VALUES
  (t,case_id_value,'access','verified_staff_intake',a,authority),(t,blocked_case,'access','verified_staff_intake',a,authority),(t,pending_case,'access','self',r,NULL);
 INSERT INTO private.privacy_rights_acknowledgements(tenant_id,case_id,actor_id) VALUES(t,case_id_value,a),(t,blocked_case,a);
 INSERT INTO private.privacy_rights_outcomes(tenant_id,case_id,actor_id,status,reason_code,evidence_digest) VALUES
  (t,case_id_value,b,'resolved','fulfilled',response_hash),(t,blocked_case,b,'refused','identity_not_verified',response_hash);
 SELECT key_id,secret INTO key_id_value,key_bytes FROM private.tenant_context_keys WHERE active ORDER BY key_id LIMIT 1;
 FOREACH phase IN ARRAY ARRAY['request','self','reader','approve','consume'] LOOP
  actor:=CASE phase WHEN 'approve' THEN b WHEN 'reader' THEN r ELSE a END;
  actual_step:=CASE WHEN phase IN ('self','reader') THEN 'approve' ELSE phase END;
  who:='ci-delivery-'||actor;
  now_s:=floor(extract(epoch FROM clock_timestamp()))::bigint;expires:=now_s+20;
  nonce:=encode(public.gen_random_bytes(16),'hex');session_hash:=encode(public.digest(actor::text,'sha256'),'hex');
  context_sig:=encode(public.hmac(convert_to(t::text||E'\n'||who||E'\n'||expires||E'\n'||nonce||E'\n'||key_id_value,'UTF8'),key_bytes,'sha256'),'hex');
  PERFORM set_config('app.tenant_id',t::text,true),set_config('app.tenant_subject',who,true),set_config('app.tenant_expires',expires::text,true),set_config('app.tenant_nonce',nonce,true),set_config('app.tenant_key_id',key_id_value,true),set_config('app.tenant_signature',context_sig,true);
  IF phase='request' THEN
   BEGIN PERFORM private.privacy_delivery_scope(t,blocked_case,order_id_value,'authorized_representative',recipient,sender,authority,redaction,response_hash,envelope); RAISE EXCEPTION 'Unverified recipient admitted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
   BEGIN PERFORM private.privacy_delivery_scope(t,pending_case,order_id_value,'self',recipient,sender,authority,redaction,response_hash,envelope); RAISE EXCEPTION 'No decision admitted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
   BEGIN PERFORM private.privacy_delivery_scope(t,case_id_value,order_id_value,'self',recipient,sender,authority,redaction,response_hash,envelope); RAISE EXCEPTION 'Wrong recipient type admitted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
   scope_hash:=private.privacy_delivery_scope(t,case_id_value,order_id_value,'authorized_representative',recipient,sender,authority,redaction,response_hash,envelope);
  END IF;
  proof:=encode(public.hmac(convert_to('profitpilot-security-work-v1'||E'\n'||t||E'\n'||order_id_value||E'\n'||'privileged_operation'||E'\n'||scope_hash||E'\n'||actual_step||E'\n'||who||E'\n'||now_s||E'\n'||now_s||E'\n'||session_hash||E'\n'||expires||E'\n'||nonce||E'\n'||key_id_value,'UTF8'),key_bytes,'sha256'),'hex');
  IF phase IN ('self','reader') THEN
   BEGIN PERFORM private.record_privacy_delivery(t,case_id_value,order_id_value,'authorized_representative',recipient,sender,authority,redaction,response_hash,envelope,scope_hash,actual_step,now_s,now_s,session_hash,expires,nonce,key_id_value,proof);
    RAISE EXCEPTION 'Non-independent or unprivileged approval accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
  ELSE
   BEGIN PERFORM private.record_privacy_delivery(t,case_id_value,order_id_value,'authorized_representative',repeat('1',64),sender,authority,redaction,response_hash,envelope,scope_hash,actual_step,now_s,now_s,session_hash,expires,nonce,key_id_value,proof);
    RAISE EXCEPTION 'Substituted recipient key accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
   BEGIN PERFORM private.record_privacy_delivery(t,case_id_value,order_id_value,'authorized_representative',recipient,sender,authority,redaction,response_hash,repeat('2',64),scope_hash,actual_step,now_s,now_s,session_hash,expires,nonce,key_id_value,proof);
    RAISE EXCEPTION 'Substituted envelope accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
   BEGIN PERFORM private.record_privacy_delivery(other_t,case_id_value,order_id_value,'authorized_representative',recipient,sender,authority,redaction,response_hash,envelope,scope_hash,actual_step,now_s,now_s,session_hash,expires,nonce,key_id_value,proof);
    RAISE EXCEPTION 'Cross tenant delivery accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
   IF phase='consume' THEN
    BEGIN INSERT INTO private.revoked_identity_sessions(user_id,session_digest) VALUES(b,approver_session);
     PERFORM private.record_privacy_delivery(t,case_id_value,order_id_value,'authorized_representative',recipient,sender,authority,redaction,response_hash,envelope,scope_hash,actual_step,now_s,now_s,session_hash,expires,nonce,key_id_value,proof);
     RAISE EXCEPTION 'Revoked approval accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
   END IF;
   PERFORM private.record_privacy_delivery(t,case_id_value,order_id_value,'authorized_representative',recipient,sender,authority,redaction,response_hash,envelope,scope_hash,actual_step,now_s,now_s,session_hash,expires,nonce,key_id_value,proof);
   IF phase='approve' THEN approver_session:=session_hash; END IF;
   IF phase<>'consume' AND EXISTS(SELECT 1 FROM private.privacy_delivery_authorizations WHERE tenant_id=t AND order_id=order_id_value) THEN RAISE EXCEPTION 'Premature response authority'; END IF;
  END IF;
 END LOOP;
 IF (SELECT count(*) FROM private.privacy_delivery_authorizations WHERE tenant_id=t AND order_id=order_id_value AND case_id=case_id_value AND envelope_digest=envelope)<>1
 OR NOT EXISTS(SELECT 1 FROM public.audit_events WHERE tenant_id=t AND object_id=case_id_value AND action='privacy_response_release_authorized')
 OR private.verify_audit_chain(t) IS DISTINCT FROM true THEN RAISE EXCEPTION 'Missing release authority or audit'; END IF;
 BEGIN PERFORM private.record_privacy_delivery(t,case_id_value,order_id_value,'authorized_representative',recipient,sender,authority,redaction,response_hash,envelope,scope_hash,'consume',now_s,now_s,session_hash,expires,nonce,key_id_value,proof); RAISE EXCEPTION 'Release replay accepted'; EXCEPTION WHEN unique_violation THEN NULL; END;
 BEGIN DELETE FROM private.privacy_delivery_authorizations WHERE tenant_id=t; RAISE EXCEPTION 'Release record mutable'; EXCEPTION WHEN object_not_in_prerequisite_state THEN NULL; END;
 IF has_function_privilege('profitpilot_app','private.record_privacy_delivery(uuid,uuid,uuid,text,text,text,text,text,text,text,text,text,bigint,bigint,text,bigint,text,text,text)','EXECUTE')
 OR has_any_column_privilege('profitpilot_app','private.privacy_delivery_authorizations','SELECT,INSERT,UPDATE,REFERENCES') THEN RAISE EXCEPTION 'Privacy release internals exposed'; END IF;
 RAISE NOTICE 'Assisted privacy release, identity gate, exact recipient/envelope scope, independent approval, revocation, replay and privilege checks passed';

 -- Reconcile verified-offline evidence as a separate dual-reviewed work order.
 -- Synthetic digests do not claim actual cryptographic receipt or delivery.
 receipt_review:=gen_random_uuid();
 saved_fingerprint:=private.sensitive_recovery_fingerprint();
 FOREACH phase IN ARRAY ARRAY['request','self','approve','consume'] LOOP
  actor:=CASE phase WHEN 'approve' THEN b ELSE a END;
  actual_step:=CASE WHEN phase='self' THEN 'approve' ELSE phase END;
  who:='ci-delivery-'||actor;
  now_s:=floor(extract(epoch FROM clock_timestamp()))::bigint;expires:=now_s+20;
  nonce:=encode(public.gen_random_bytes(16),'hex');session_hash:=encode(public.digest(actor::text,'sha256'),'hex');
  context_sig:=encode(public.hmac(convert_to(t::text||E'\n'||who||E'\n'||expires||E'\n'||nonce||E'\n'||key_id_value,'UTF8'),key_bytes,'sha256'),'hex');
  PERFORM set_config('app.tenant_id',t::text,true),set_config('app.tenant_subject',who,true),set_config('app.tenant_expires',expires::text,true),set_config('app.tenant_nonce',nonce,true),set_config('app.tenant_key_id',key_id_value,true),set_config('app.tenant_signature',context_sig,true);
  scope_hash:=private.privacy_receipt_scope(t,case_id_value,order_id_value,receipt_review,repeat('1',64),repeat('2',64),repeat('3',64),repeat('4',64));
  proof:=encode(public.hmac(convert_to('profitpilot-security-work-v1'||E'\n'||t||E'\n'||receipt_review||E'\n'||'privileged_operation'||E'\n'||scope_hash||E'\n'||actual_step||E'\n'||who||E'\n'||now_s||E'\n'||now_s||E'\n'||session_hash||E'\n'||expires||E'\n'||nonce||E'\n'||key_id_value,'UTF8'),key_bytes,'sha256'),'hex');
  IF phase='self' THEN
   BEGIN PERFORM private.record_privacy_receipt_evidence(t,case_id_value,order_id_value,receipt_review,repeat('1',64),repeat('2',64),repeat('3',64),repeat('4',64),scope_hash,actual_step,now_s,now_s,session_hash,expires,nonce,key_id_value,proof);
    RAISE EXCEPTION 'Receipt self-approval accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
  ELSE
   BEGIN PERFORM private.record_privacy_receipt_evidence(t,case_id_value,order_id_value,receipt_review,repeat('1',64),repeat('5',64),repeat('3',64),repeat('4',64),scope_hash,actual_step,now_s,now_s,session_hash,expires,nonce,key_id_value,proof);
    RAISE EXCEPTION 'Receipt substitution accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
   BEGIN PERFORM private.record_privacy_receipt_evidence(other_t,case_id_value,order_id_value,receipt_review,repeat('1',64),repeat('2',64),repeat('3',64),repeat('4',64),scope_hash,actual_step,now_s,now_s,session_hash,expires,nonce,key_id_value,proof);
    RAISE EXCEPTION 'Cross tenant receipt accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
   PERFORM private.record_privacy_receipt_evidence(t,case_id_value,order_id_value,receipt_review,repeat('1',64),repeat('2',64),repeat('3',64),repeat('4',64),scope_hash,actual_step,now_s,now_s,session_hash,expires,nonce,key_id_value,proof);
   IF phase<>'consume' AND EXISTS(SELECT 1 FROM private.privacy_receipt_evidence WHERE tenant_id=t AND release_order_id=order_id_value) THEN RAISE EXCEPTION 'Premature receipt evidence'; END IF;
  END IF;
 END LOOP;
 IF (SELECT count(*) FROM private.privacy_receipt_evidence WHERE tenant_id=t AND release_order_id=order_id_value AND review_order_id=receipt_review)<>1
 OR private.sensitive_recovery_fingerprint() IS NOT DISTINCT FROM saved_fingerprint OR private.verify_audit_chain(t) IS DISTINCT FROM true THEN RAISE EXCEPTION 'Receipt evidence or audit missing'; END IF;
 BEGIN PERFORM private.record_privacy_receipt_evidence(t,case_id_value,order_id_value,receipt_review,repeat('1',64),repeat('2',64),repeat('3',64),repeat('4',64),scope_hash,'consume',now_s,now_s,session_hash,expires,nonce,key_id_value,proof);
  RAISE EXCEPTION 'Receipt replay accepted'; EXCEPTION WHEN unique_violation THEN NULL; END;
 BEGIN DELETE FROM private.privacy_receipt_evidence WHERE tenant_id=t; RAISE EXCEPTION 'Receipt evidence mutable'; EXCEPTION WHEN object_not_in_prerequisite_state THEN NULL; END;
 IF has_function_privilege('profitpilot_app','private.record_privacy_receipt_evidence(uuid,uuid,uuid,uuid,text,text,text,text,text,text,bigint,bigint,text,bigint,text,text,text)','EXECUTE')
 OR has_any_column_privilege('profitpilot_app','private.privacy_receipt_evidence','SELECT,INSERT,UPDATE,REFERENCES') THEN RAISE EXCEPTION 'Receipt reconciliation internals exposed'; END IF;
 RAISE NOTICE 'Privacy receipt evidence, independent review, exact scope, replay, recovery and immutability checks passed';

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

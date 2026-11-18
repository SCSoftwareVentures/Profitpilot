-- Synthetic assisted response authority; never uses real documents or keys.
BEGIN;
DO $test$
DECLARE t uuid:=gen_random_uuid(); other_t uuid:=gen_random_uuid(); a uuid:=gen_random_uuid(); b uuid:=gen_random_uuid(); r uuid:=gen_random_uuid();
 case_id_value uuid:=gen_random_uuid(); blocked_case uuid:=gen_random_uuid(); pending_case uuid:=gen_random_uuid(); order_id_value uuid:=gen_random_uuid();
 who text; actor uuid; phase text; actual_step text; scope_hash text; recipient text:=repeat('a',64); sender text:=repeat('b',64);
 authority text:=repeat('c',64); redaction text:=repeat('d',64); response_hash text:=repeat('e',64); envelope text:=repeat('f',64);
 now_s bigint; expires bigint; nonce text; session_hash text; context_sig text; proof text; key_id_value text; key_bytes bytea; approver_session text; receipt_review uuid; saved_fingerprint text; dispatch_deadline bigint; dispatch_challenge text; dispatch_signer text; dispatch_reason text; dispatch_evidence text; dispatch_result jsonb; key_previous uuid; key_order uuid; key_round integer; key_recipient text; key_sender text; key_signer text;
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


 -- Persistent single-use dispatch fence: the fixture uses synthetic digests;
 -- no transport permission is returned even when a reservation is burned.
 dispatch_deadline:=floor(extract(epoch FROM clock_timestamp()))::bigint+120;
 dispatch_challenge:=repeat('1',64);dispatch_signer:=repeat('3',64);
 saved_fingerprint:=private.sensitive_recovery_fingerprint();
 IF private.privacy_dispatch_status(t,case_id_value,order_id_value)->>'state' IS DISTINCT FROM 'unreserved' THEN RAISE EXCEPTION 'Unexpected initial dispatch state'; END IF;
 FOREACH phase IN ARRAY ARRAY['privacy_dispatch_burn','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke'] LOOP
  actor:=a;who:='ci-delivery-'||actor;
  now_s:=floor(extract(epoch FROM clock_timestamp()))::bigint;expires:=now_s+20;
  nonce:=encode(public.gen_random_bytes(16),'hex');session_hash:=encode(public.digest(actor::text,'sha256'),'hex');
  context_sig:=encode(public.hmac(convert_to(t::text||E'\n'||who||E'\n'||expires||E'\n'||nonce||E'\n'||key_id_value,'UTF8'),key_bytes,'sha256'),'hex');
  PERFORM set_config('app.tenant_id',t::text,true),set_config('app.tenant_subject',who,true),set_config('app.tenant_expires',expires::text,true),set_config('app.tenant_nonce',nonce,true),set_config('app.tenant_key_id',key_id_value,true),set_config('app.tenant_signature',context_sig,true);
  IF phase='privacy_dispatch_revoke' THEN
   dispatch_challenge:=NULL;dispatch_signer:=NULL;dispatch_deadline:=NULL;
   dispatch_reason:='ambiguous_dispatch';dispatch_evidence:=repeat('6',64);
  END IF;
  scope_hash:=encode(public.digest(convert_to('profitpilot-privacy-dispatch-v1'||E'\n'||case_id_value||E'\n'||order_id_value||E'\n'||phase||E'\n'||coalesce(dispatch_challenge,'')||E'\n'||coalesce(dispatch_signer,'')||E'\n'||coalesce(dispatch_deadline::text,'')||E'\n'||coalesce(dispatch_reason,'')||E'\n'||coalesce(dispatch_evidence,''),'UTF8'),'sha256'),'hex');
  proof:=encode(public.hmac(convert_to('profitpilot-sensitive-api-v1'||E'\n'||t||E'\n'||order_id_value||E'\n'||phase||E'\n'||scope_hash||E'\n'||who||E'\n'||now_s||E'\n'||now_s||E'\n'||session_hash||E'\n'||expires||E'\n'||nonce||E'\n'||key_id_value,'UTF8'),key_bytes,'sha256'),'hex');
  BEGIN
   PERFORM private.record_privacy_dispatch(other_t,case_id_value,order_id_value,phase,dispatch_challenge,dispatch_signer,dispatch_deadline,dispatch_reason,dispatch_evidence,scope_hash,now_s,now_s,session_hash,expires,nonce,key_id_value,proof);
   RAISE EXCEPTION 'Cross tenant dispatch accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
  IF phase='privacy_dispatch_burn' AND NOT EXISTS(SELECT 1 FROM private.privacy_dispatch_reservations WHERE tenant_id=t AND release_order_id=order_id_value) THEN
   BEGIN
    PERFORM private.record_privacy_dispatch(t,case_id_value,order_id_value,phase,dispatch_challenge,dispatch_signer,dispatch_deadline,dispatch_reason,dispatch_evidence,scope_hash,now_s,now_s,session_hash,expires,nonce,key_id_value,proof);
    RAISE EXCEPTION 'Unreserved dispatch accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
   CONTINUE;
  END IF;
  IF phase='privacy_dispatch_reserve' THEN
   BEGIN
    INSERT INTO private.privacy_dispatch_revocations(tenant_id,release_order_id,actor_id,reason_code,evidence_digest) VALUES(t,order_id_value,a,'identity_uncertain',repeat('7',64));
    BEGIN PERFORM private.record_privacy_dispatch(t,case_id_value,order_id_value,phase,dispatch_challenge,dispatch_signer,dispatch_deadline,NULL,NULL,scope_hash,now_s,now_s,session_hash,expires,nonce,key_id_value,proof);
      RAISE EXCEPTION 'Revoked release reserved'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
    RAISE SQLSTATE 'P7777' USING MESSAGE='Rollback synthetic pre-reservation revocation';
   EXCEPTION WHEN SQLSTATE 'P7777' THEN NULL; END;
   BEGIN
    INSERT INTO private.revoked_identity_sessions(user_id,session_digest) VALUES(b,approver_session);
    PERFORM private.record_privacy_dispatch(t,case_id_value,order_id_value,phase,dispatch_challenge,dispatch_signer,dispatch_deadline,NULL,NULL,scope_hash,now_s,now_s,session_hash,expires,nonce,key_id_value,proof);
    RAISE EXCEPTION 'Revoked original approver accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
  END IF;
  IF phase='privacy_dispatch_burn' THEN
   BEGIN
    PERFORM private.record_privacy_dispatch(t,case_id_value,order_id_value,phase,repeat('9',64),dispatch_signer,dispatch_deadline,NULL,NULL,scope_hash,now_s,now_s,session_hash,expires,nonce,key_id_value,proof);
    RAISE EXCEPTION 'Substituted challenge accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
  END IF;
  dispatch_result:=private.record_privacy_dispatch(t,case_id_value,order_id_value,phase,dispatch_challenge,dispatch_signer,dispatch_deadline,dispatch_reason,dispatch_evidence,scope_hash,now_s,now_s,session_hash,expires,nonce,key_id_value,proof);
  IF dispatch_result->>'mayTransmit' IS DISTINCT FROM 'false' OR dispatch_result->>'deliveryVerified' IS DISTINCT FROM 'false'
   OR dispatch_result->>'state' IS DISTINCT FROM (CASE phase WHEN 'privacy_dispatch_reserve' THEN 'reserved' WHEN 'privacy_dispatch_burn' THEN 'attempt-spent' ELSE 'revoked' END)
  THEN RAISE EXCEPTION 'Dispatch state or safety boundary incorrect'; END IF;
  BEGIN
   PERFORM private.record_privacy_dispatch(t,case_id_value,order_id_value,phase,dispatch_challenge,dispatch_signer,dispatch_deadline,dispatch_reason,dispatch_evidence,scope_hash,now_s,now_s,session_hash,expires,nonce,key_id_value,proof);
   RAISE EXCEPTION 'Dispatch action replay accepted'; EXCEPTION WHEN unique_violation THEN NULL; END;
 END LOOP;
 IF private.privacy_dispatch_status(t,case_id_value,order_id_value)->>'attemptSpent' IS DISTINCT FROM 'true'
 OR private.sensitive_recovery_fingerprint() IS NOT DISTINCT FROM saved_fingerprint THEN RAISE EXCEPTION 'Dispatch state or fingerprint missing'; END IF;
 BEGIN DELETE FROM private.privacy_dispatch_burns WHERE tenant_id=t; RAISE EXCEPTION 'Spent attempt mutable'; EXCEPTION WHEN object_not_in_prerequisite_state THEN NULL; END;
 BEGIN DELETE FROM private.privacy_dispatch_revocations WHERE tenant_id=t; RAISE EXCEPTION 'Revocation mutable'; EXCEPTION WHEN object_not_in_prerequisite_state THEN NULL; END;
 IF has_function_privilege('profitpilot_app','private.record_privacy_dispatch(uuid,uuid,uuid,text,text,text,bigint,text,text,text,bigint,bigint,text,bigint,text,text,text)','EXECUTE')
 OR has_any_column_privilege('profitpilot_app','private.privacy_dispatch_reservations','SELECT,INSERT,UPDATE,REFERENCES')
 OR has_any_column_privilege('profitpilot_app','private.privacy_dispatch_burns','SELECT,INSERT,UPDATE,REFERENCES')
 OR has_any_column_privilege('profitpilot_app','private.privacy_dispatch_revocations','SELECT,INSERT,UPDATE,REFERENCES')
 THEN RAISE EXCEPTION 'Dispatch internals exposed'; END IF;
 RAISE NOTICE 'Durable dispatch reserve, burn, revocation, prior approval revocation, replay and recovery fence checks passed';

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


 -- Enrol and rotate a case-specific key generation with exact dual approval.
 -- Only digests are used; no actual key or personal data is in this fixture.
 key_previous:=NULL;key_recipient:=recipient;key_sender:=sender;key_signer:=repeat('3',64);
 FOREACH key_round IN ARRAY ARRAY[1,2] LOOP
  key_order:=gen_random_uuid();
  IF key_round=2 THEN key_recipient:=repeat('8',64);key_signer:=repeat('9',64); END IF;
  FOREACH phase IN ARRAY ARRAY['request','self','approve','consume'] LOOP
   actor:=CASE phase WHEN 'approve' THEN b ELSE a END;
   actual_step:=CASE WHEN phase='self' THEN 'approve' ELSE phase END;
   who:='ci-delivery-'||actor;
   now_s:=floor(extract(epoch FROM clock_timestamp()))::bigint;expires:=now_s+20;
   nonce:=encode(public.gen_random_bytes(16),'hex');session_hash:=encode(public.digest(actor::text,'sha256'),'hex');
   context_sig:=encode(public.hmac(convert_to(t::text||E'\n'||who||E'\n'||expires||E'\n'||nonce||E'\n'||key_id_value,'UTF8'),key_bytes,'sha256'),'hex');
   PERFORM set_config('app.tenant_id',t::text,true),set_config('app.tenant_subject',who,true),set_config('app.tenant_expires',expires::text,true),set_config('app.tenant_nonce',nonce,true),set_config('app.tenant_key_id',key_id_value,true),set_config('app.tenant_signature',context_sig,true);
   scope_hash:=private.privacy_case_key_scope(t,case_id_value,key_order,key_previous,key_recipient,key_sender,key_signer,authority);
   proof:=encode(public.hmac(convert_to('profitpilot-security-work-v1'||E'\n'||t||E'\n'||key_order||E'\n'||'privileged_operation'||E'\n'||scope_hash||E'\n'||actual_step||E'\n'||who||E'\n'||now_s||E'\n'||now_s||E'\n'||session_hash||E'\n'||expires||E'\n'||nonce||E'\n'||key_id_value,'UTF8'),key_bytes,'sha256'),'hex');
   BEGIN
    PERFORM private.record_privacy_case_keys(t,case_id_value,key_order,key_previous,repeat('7',64),key_sender,key_signer,authority,scope_hash,actual_step,now_s,now_s,session_hash,expires,nonce,key_id_value,proof);
    RAISE EXCEPTION 'Substituted key accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
   IF phase='self' THEN
    BEGIN
     PERFORM private.record_privacy_case_keys(t,case_id_value,key_order,key_previous,key_recipient,key_sender,key_signer,authority,scope_hash,actual_step,now_s,now_s,session_hash,expires,nonce,key_id_value,proof);
     RAISE EXCEPTION 'Key self approval accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
   ELSE
    PERFORM private.record_privacy_case_keys(t,case_id_value,key_order,key_previous,key_recipient,key_sender,key_signer,authority,scope_hash,actual_step,now_s,now_s,session_hash,expires,nonce,key_id_value,proof);
    IF phase<>'consume' AND EXISTS(SELECT 1 FROM private.privacy_case_key_versions WHERE tenant_id=t AND order_id=key_order) THEN RAISE EXCEPTION 'Key generation prematurely activated'; END IF;
   END IF;
  END LOOP;
  PERFORM private.assert_privacy_case_keys(t,case_id_value,key_recipient,key_sender,key_signer);
  key_previous:=key_order;
 END LOOP;
 BEGIN PERFORM private.assert_privacy_case_keys(t,case_id_value,recipient,sender,repeat('3',64)); RAISE EXCEPTION 'Retired keys accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM private.privacy_case_key_scope(t,case_id_value,gen_random_uuid(),key_previous,recipient,sender,repeat('3',64),authority); RAISE EXCEPTION 'Retired keys reintroduced'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM private.privacy_delivery_scope(t,case_id_value,gen_random_uuid(),'authorized_representative',recipient,sender,authority,redaction,response_hash,envelope); RAISE EXCEPTION 'Old release keys accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 PERFORM private.privacy_delivery_scope(t,case_id_value,gen_random_uuid(),'authorized_representative',key_recipient,key_sender,authority,redaction,response_hash,envelope);
 -- Immediate irreversible compromise denial. The current recipient key is
 -- revoked after rotation; neither initial enrolment nor a future version may use it.
 saved_fingerprint:=private.sensitive_recovery_fingerprint();
 scope_hash:=encode(public.digest(convert_to('profitpilot-privacy-key-revoke-v1'||E'\n'||key_recipient||E'\n'||'suspected_compromise'||E'\n'||authority,'UTF8'),'sha256'),'hex');
 proof:=encode(public.hmac(convert_to('profitpilot-sensitive-api-v1'||E'\n'||t||E'\n'||t||E'\n'||'privacy_key_revoke'||E'\n'||scope_hash||E'\n'||who||E'\n'||now_s||E'\n'||now_s||E'\n'||session_hash||E'\n'||expires||E'\n'||nonce||E'\n'||key_id_value,'UTF8'),key_bytes,'sha256'),'hex');
 BEGIN PERFORM private.revoke_privacy_key(other_t,key_recipient,'suspected_compromise',authority,scope_hash,now_s,now_s,session_hash,expires,nonce,key_id_value,proof); RAISE EXCEPTION 'Cross-tenant key revocation accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 PERFORM private.revoke_privacy_key(t,key_recipient,'suspected_compromise',authority,scope_hash,now_s,now_s,session_hash,expires,nonce,key_id_value,proof);
 BEGIN PERFORM private.assert_privacy_case_keys(t,case_id_value,key_recipient,key_sender,key_signer); RAISE EXCEPTION 'Compromised key accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM private.privacy_case_key_scope(t,case_id_value,gen_random_uuid(),key_previous,key_recipient,key_sender,repeat('6',64),authority); RAISE EXCEPTION 'Compromised key reused'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM private.revoke_privacy_key(t,key_recipient,'suspected_compromise',authority,scope_hash,now_s,now_s,session_hash,expires,nonce,key_id_value,proof); RAISE EXCEPTION 'Revocation replay accepted'; EXCEPTION WHEN unique_violation THEN NULL; END;
 BEGIN DELETE FROM private.privacy_case_key_versions WHERE tenant_id=t; RAISE EXCEPTION 'Key history mutable'; EXCEPTION WHEN object_not_in_prerequisite_state THEN NULL; END;
 BEGIN DELETE FROM private.privacy_compromised_keys WHERE tenant_id=t; RAISE EXCEPTION 'Compromise history mutable'; EXCEPTION WHEN object_not_in_prerequisite_state THEN NULL; END;
 IF private.sensitive_recovery_fingerprint() IS NOT DISTINCT FROM saved_fingerprint OR private.verify_audit_chain(t) IS DISTINCT FROM true
 OR has_any_column_privilege('profitpilot_app','private.privacy_case_key_versions','SELECT,INSERT,UPDATE,REFERENCES')
 OR has_any_column_privilege('profitpilot_app','private.privacy_compromised_keys','SELECT,INSERT,UPDATE,REFERENCES')
 OR has_function_privilege('profitpilot_app','private.revoke_privacy_key(uuid,text,text,text,text,bigint,bigint,text,bigint,text,text,text)','EXECUTE')
 THEN RAISE EXCEPTION 'Key history, recovery or grants invalid'; END IF;
 RAISE NOTICE 'Privacy key enrollment, independent rotation, retired-key denial, immediate compromise revocation and recovery fence verified';

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

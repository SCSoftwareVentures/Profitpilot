-- Extend local closure to owners with successors and independently approved organizations.
BEGIN;
CREATE OR REPLACE FUNCTION private.closure_eligible(p_tenant uuid,p_subject uuid,p_request uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
 SELECT EXISTS(SELECT 1 FROM public.users WHERE id=p_subject AND status='active')
 AND EXISTS(SELECT 1 FROM public.tenant_memberships WHERE tenant_id=p_tenant AND user_id=p_subject AND status='active')
 AND EXISTS(SELECT 1 FROM public.tenant_memberships m JOIN public.users u ON u.id=m.user_id
  WHERE m.tenant_id=p_tenant AND m.user_id<>p_subject AND m.status='active' AND m.role='owner' AND u.status='active')
 AND NOT EXISTS(SELECT 1 FROM public.privacy_requests WHERE tenant_id=p_tenant AND subject_user_id=p_subject AND id<>p_request
  AND status IN ('requested','identity_verification','under_review','legal_hold'))
 AND NOT EXISTS(SELECT 1 FROM private.privacy_retention_holds WHERE tenant_id=p_tenant AND subject_user_id=p_subject)
 AND NOT EXISTS(SELECT 1 FROM private.account_closures WHERE user_id=p_subject)
$fn$;
ALTER FUNCTION private.closure_eligible(uuid,uuid,uuid) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.closure_eligible(uuid,uuid,uuid) FROM PUBLIC,profitpilot_app;

CREATE OR REPLACE FUNCTION private.approve_account_closure(p_tenant uuid,p_request uuid,p_erase boolean,p_auth_time bigint,p_proof text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
DECLARE actor uuid;
DECLARE item public.privacy_requests%ROWTYPE;
DECLARE policy private.privacy_retention_policies%ROWTYPE;
DECLARE approval private.account_closure_approvals%ROWTYPE;
DECLARE now_at timestamptz;
BEGIN
 actor:=private.assert_privacy_step_up(p_tenant,p_request,'approve_account_closure:'||p_erase::text,p_auth_time,p_proof);
 IF NOT private.can_manage_privacy_requests() THEN RAISE EXCEPTION 'Privacy manager required' USING ERRCODE='42501'; END IF;
 SELECT * INTO item FROM public.privacy_requests WHERE tenant_id=p_tenant AND id=p_request FOR UPDATE;
 IF NOT FOUND THEN RETURN jsonb_build_object('status',404,'error','Privacy request not found'); END IF;
 PERFORM private.lock_privacy_retention_subject(p_tenant,item.subject_user_id);
 now_at:=clock_timestamp();
 IF p_erase IS NULL OR actor=item.subject_user_id OR item.request_type<>'account_closure' OR item.status<>'under_review'
 OR item.account_confirmed_at IS NULL OR item.account_confirmed_at<now_at-interval '24 hours'
 OR NOT private.closure_eligible(p_tenant,item.subject_user_id,p_request) THEN
  RETURN jsonb_build_object('status',409,'error','Closure requires independent approval, eligible account, no holds or outstanding requests');
 END IF;
 IF p_erase THEN
  SELECT * INTO policy FROM private.privacy_retention_policies WHERE tenant_id=p_tenant FOR SHARE;
  IF NOT FOUND OR NOT policy.enabled OR NOT policy.allow_profile_email_erasure THEN
   RETURN jsonb_build_object('status',409,'error','Explicit profile erasure retention authorization required');
  END IF;
 END IF;
 SELECT * INTO approval FROM private.account_closure_approvals WHERE request_id=p_request;
 IF FOUND AND (approval.consumed_at IS NOT NULL OR (approval.invalidated_at IS NULL AND approval.expires_at>now_at
 AND approval.confirmation_at=item.account_confirmed_at AND (NOT approval.erase_email OR EXISTS(
 SELECT 1 FROM private.privacy_retention_policies p WHERE p.tenant_id=p_tenant AND p.enabled AND p.allow_profile_email_erasure AND p.revision=approval.policy_revision)))) THEN
  RETURN jsonb_build_object('status',409,'error','Active closure approval already exists');
 END IF;
 INSERT INTO private.account_closure_approvals(request_id,tenant_id,approved_by,confirmation_at,erase_email,policy_revision,approved_at,expires_at)
 VALUES(p_request,p_tenant,actor,item.account_confirmed_at,p_erase,policy.revision,now_at,now_at+interval '15 minutes')
 ON CONFLICT(request_id) DO UPDATE SET approved_by=EXCLUDED.approved_by,confirmation_at=EXCLUDED.confirmation_at,
 erase_email=EXCLUDED.erase_email,policy_revision=EXCLUDED.policy_revision,approved_at=EXCLUDED.approved_at,expires_at=EXCLUDED.expires_at,invalidated_at=NULL;
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata)
 VALUES(p_tenant,actor,'account_closure_approved','privacy_request',p_request,'Independent account closure approval',
 jsonb_build_object('eraseEmail',p_erase,'expiresAt',now_at+interval '15 minutes'));
 RETURN jsonb_build_object('status',200,'item',jsonb_build_object('requestId',p_request,'eraseEmail',p_erase,'expiresAt',now_at+interval '15 minutes'));
END
$fn$;
ALTER FUNCTION private.approve_account_closure(uuid,uuid,boolean,bigint,text) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.approve_account_closure(uuid,uuid,boolean,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.approve_account_closure(uuid,uuid,boolean,bigint,text) TO profitpilot_app;

CREATE OR REPLACE FUNCTION private.execute_account_closure(p_tenant uuid,p_request uuid,p_erase boolean,p_auth_time bigint,p_proof text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
DECLARE actor uuid;
DECLARE item public.privacy_requests%ROWTYPE;
DECLARE approval private.account_closure_approvals%ROWTYPE;
DECLARE policy private.privacy_retention_policies%ROWTYPE;
DECLARE account public.users%ROWTYPE;
DECLARE now_at timestamptz;
DECLARE sessions_terminated integer;
DECLARE m record;
DECLARE matched_grants integer;
DECLARE all_grants integer;
BEGIN
 actor:=private.assert_privacy_step_up(p_tenant,p_request,'execute_account_closure:'||p_erase::text,p_auth_time,p_proof);
 SELECT * INTO item FROM public.privacy_requests WHERE tenant_id=p_tenant AND id=p_request AND subject_user_id=actor FOR UPDATE;
 IF NOT FOUND THEN RETURN jsonb_build_object('status',404,'error','Privacy request not found'); END IF;
 SELECT * INTO approval FROM private.account_closure_approvals WHERE tenant_id=p_tenant AND request_id=p_request;
 IF NOT FOUND OR p_erase IS NULL OR approval.erase_email IS DISTINCT FROM p_erase OR approval.consumed_at IS NOT NULL OR approval.invalidated_at IS NOT NULL
 OR item.request_type<>'account_closure' OR item.status<>'under_review' OR item.account_confirmed_at IS NULL
 OR approval.confirmation_at IS DISTINCT FROM item.account_confirmed_at OR p_auth_time<=floor(extract(epoch FROM approval.approved_at))::bigint THEN
  RETURN jsonb_build_object('status',409,'error','Unused matching approval and new requester MFA required');
 END IF;
 -- Block new session registration and competing membership provisioning while closing.
 SELECT * INTO account FROM public.users WHERE id=actor FOR UPDATE;
 -- Serialise competing closures within every affected tenant, then lock each subject hold.
 PERFORM pg_advisory_xact_lock(hashtextextended('account-close-global-v2',0));
 PERFORM 1 FROM public.tenant_memberships WHERE user_id=actor FOR UPDATE;
 PERFORM 1 FROM public.privacy_requests WHERE subject_user_id=actor ORDER BY id FOR UPDATE;
 IF p_erase THEN PERFORM 1 FROM private.privacy_retention_policies WHERE tenant_id IN (SELECT tenant_id FROM public.tenant_memberships WHERE user_id=actor) ORDER BY tenant_id FOR SHARE; END IF;
 FOR m IN SELECT tenant_id FROM public.tenant_memberships WHERE user_id=actor ORDER BY tenant_id LOOP
  PERFORM private.lock_privacy_retention_subject(m.tenant_id,actor);
 END LOOP;
 IF p_erase THEN
  SELECT * INTO policy FROM private.privacy_retention_policies WHERE tenant_id=p_tenant FOR SHARE;
  IF NOT FOUND OR NOT policy.enabled OR NOT policy.allow_profile_email_erasure OR policy.revision IS DISTINCT FROM approval.policy_revision THEN
   RETURN jsonb_build_object('status',409,'error','Profile erasure authorization changed');
  END IF;
 END IF;
 now_at:=clock_timestamp();
 -- Every active membership needs its own reviewed, independent, fresh approval.
 -- Historical memberships cannot authorize global email erasure without an explicit policy.
 IF EXISTS(SELECT 1 FROM public.tenant_memberships m JOIN public.tenants t ON t.id=m.tenant_id
 WHERE m.user_id=actor AND m.status='active' AND (t.status<>'active' OR NOT EXISTS(
 SELECT 1 FROM public.tenant_memberships o JOIN public.users ou ON ou.id=o.user_id
 WHERE o.tenant_id=m.tenant_id AND o.user_id<>actor AND o.role='owner' AND o.status='active' AND ou.status='active')))
 OR EXISTS(SELECT 1 FROM private.privacy_retention_holds h WHERE h.subject_user_id=actor)
 OR EXISTS(SELECT 1 FROM public.privacy_requests r WHERE r.subject_user_id=actor AND r.status IN ('requested','identity_verification','under_review','legal_hold')
 AND (r.request_type<>'account_closure' OR r.status<>'under_review' OR NOT EXISTS(
 SELECT 1 FROM public.tenant_memberships m WHERE m.user_id=actor AND m.tenant_id=r.tenant_id AND m.status='active')))
 OR (p_erase AND EXISTS(SELECT 1 FROM public.tenant_memberships m WHERE m.user_id=actor AND m.status<>'active')) THEN
  RETURN jsonb_build_object('status',409,'error','Other outstanding obligations or ownership prevents global closure');
 END IF;
 SELECT count(*) INTO all_grants FROM public.tenant_memberships WHERE user_id=actor AND status='active';
 SELECT count(DISTINCT r.tenant_id) INTO matched_grants FROM public.privacy_requests r
 JOIN private.account_closure_approvals a ON a.request_id=r.id AND a.tenant_id=r.tenant_id
 JOIN public.tenant_memberships m ON m.tenant_id=r.tenant_id AND m.user_id=actor AND m.status='active'
 JOIN public.tenant_memberships manager ON manager.tenant_id=r.tenant_id AND manager.user_id=a.approved_by
 JOIN public.users manager_user ON manager_user.id=manager.user_id
 WHERE r.subject_user_id=actor AND r.request_type='account_closure' AND r.status='under_review'
 AND r.account_confirmed_at IS NOT NULL AND r.account_confirmed_at>=now_at-interval '24 hours'
 AND a.confirmation_at=r.account_confirmed_at AND a.erase_email=p_erase
 AND a.consumed_at IS NULL AND a.invalidated_at IS NULL AND a.expires_at>now_at
 AND p_auth_time>floor(extract(epoch FROM a.approved_at))::bigint
 AND manager.user_id<>actor AND manager.status='active' AND manager.role IN ('owner','admin') AND manager_user.status='active'
 AND (NOT p_erase OR EXISTS(SELECT 1 FROM private.privacy_retention_policies p WHERE p.tenant_id=r.tenant_id
 AND p.enabled AND p.allow_profile_email_erasure AND p.revision=a.policy_revision));
 IF matched_grants<>all_grants OR (SELECT count(*) FROM public.privacy_requests WHERE subject_user_id=actor AND request_type='account_closure' AND status='under_review')<>all_grants THEN RETURN jsonb_build_object('status',409,'error','Every active organization must independently approve matching closure scope before new MFA'); END IF;
 IF approval.expires_at<=now_at OR item.account_confirmed_at<now_at-interval '24 hours'
 OR NOT private.closure_eligible(p_tenant,actor,p_request)
 OR NOT EXISTS(SELECT 1 FROM public.tenant_memberships m JOIN public.users u ON u.id=m.user_id
 WHERE m.tenant_id=p_tenant AND m.user_id=approval.approved_by AND m.status='active' AND u.status='active' AND m.role IN ('owner','admin') AND m.user_id<>actor) THEN
  RETURN jsonb_build_object('status',409,'error','Closure eligibility, approval or retention check failed');
 END IF;
 UPDATE private.auth_sessions SET revoked_at=now_at,revocation_reason='account_closed'
 WHERE subject=account.auth_subject AND revoked_at IS NULL;
 GET DIAGNOSTICS sessions_terminated=ROW_COUNT;
 -- Lock and update every reviewed closure request in the same transaction.
 UPDATE private.account_closure_approvals a SET consumed_at=now_at
 FROM public.privacy_requests r WHERE r.id=a.request_id AND r.subject_user_id=actor AND r.request_type='account_closure' AND r.status='under_review'
 AND a.consumed_at IS NULL AND a.invalidated_at IS NULL AND a.expires_at>now_at;
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata)
 SELECT r.tenant_id,actor,'account_closure_membership_revoked','privacy_request',r.id,'Local account closure across approved organizations','{}'::jsonb
 FROM public.privacy_requests r WHERE r.subject_user_id=actor AND r.request_type='account_closure' AND r.status='under_review' ORDER BY r.tenant_id;
 UPDATE public.privacy_requests SET status='fulfilled',resolved_at=now_at,updated_at=now_at,
 resolution_summary='ProfitPilot local account closed; external provider and retained records are not erased.'
 WHERE subject_user_id=actor AND request_type='account_closure' AND status='under_review';
 UPDATE public.tenant_memberships SET status='revoked' WHERE user_id=actor AND status='active';
 UPDATE public.users SET status='disabled',email=CASE WHEN p_erase THEN 'erased-'||id::text||'@invalid.example' ELSE email END WHERE id=actor;
 INSERT INTO private.account_closures(user_id,tenant_id,request_id,closed_at,email_erased,policy_revision)
 VALUES(actor,p_tenant,p_request,now_at,p_erase,approval.policy_revision);
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata)
 VALUES(p_tenant,actor,'account_closed','privacy_request',p_request,'Local account closed and sessions revoked',
 jsonb_build_object('emailErased',p_erase,'sessionsRevoked',sessions_terminated,'providerAccountErased',false));
 RETURN jsonb_build_object('status',200,'item',jsonb_build_object('requestId',p_request,'accountClosed',true,'localSessionsRevoked',sessions_terminated,
 'profileEmailErased',p_erase,'providerAccountErased',false,'completePersonalDataDeletion',false));
END
$fn$;
ALTER FUNCTION private.execute_account_closure(uuid,uuid,boolean,bigint,text) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.execute_account_closure(uuid,uuid,boolean,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.execute_account_closure(uuid,uuid,boolean,bigint,text) TO profitpilot_app;
COMMIT;

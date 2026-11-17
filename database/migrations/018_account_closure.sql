-- Local account closure, revocation and optional policy-authorized profile email removal.
BEGIN;
ALTER TABLE public.privacy_requests DROP CONSTRAINT privacy_requests_request_type_check;
ALTER TABLE public.privacy_requests ADD CONSTRAINT privacy_requests_request_type_check
 CHECK(request_type IN ('access','correction','export','deletion','restriction','account_closure'));
ALTER TABLE private.privacy_retention_policies ADD COLUMN allow_profile_email_erasure boolean NOT NULL DEFAULT false;
GRANT UPDATE(status,email) ON public.users TO profitpilot_context_owner;
GRANT UPDATE(status) ON public.tenant_memberships TO profitpilot_context_owner;
CREATE TABLE private.account_closures(
 user_id uuid PRIMARY KEY REFERENCES public.users(id) ON DELETE RESTRICT,
 tenant_id uuid NOT NULL,
 request_id uuid NOT NULL UNIQUE REFERENCES public.privacy_requests(id) ON DELETE RESTRICT,
 closed_at timestamptz NOT NULL,
 email_erased boolean NOT NULL,
 policy_revision uuid,
 FOREIGN KEY(tenant_id,user_id) REFERENCES public.tenant_memberships(tenant_id,user_id) ON DELETE RESTRICT,
 CHECK(NOT email_erased OR policy_revision IS NOT NULL)
);
CREATE TABLE private.account_closure_approvals(
 request_id uuid PRIMARY KEY REFERENCES public.privacy_requests(id) ON DELETE RESTRICT,
 tenant_id uuid NOT NULL,
 approved_by uuid NOT NULL,
 confirmation_at timestamptz NOT NULL,
 erase_email boolean NOT NULL,
 policy_revision uuid,
 approved_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 consumed_at timestamptz,
 invalidated_at timestamptz,
 FOREIGN KEY(tenant_id,approved_by) REFERENCES public.tenant_memberships(tenant_id,user_id),
 CHECK(NOT erase_email OR policy_revision IS NOT NULL),
 CHECK(expires_at>approved_at),
 CHECK(consumed_at IS NULL OR (consumed_at>=approved_at AND consumed_at<expires_at))
);
ALTER TABLE private.account_closures OWNER TO profitpilot_context_owner;
ALTER TABLE private.account_closure_approvals OWNER TO profitpilot_context_owner;
REVOKE ALL ON private.account_closures,private.account_closure_approvals FROM PUBLIC,profitpilot_app;

CREATE FUNCTION private.prevent_closed_account_reactivation() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,private AS $fn$
BEGIN
 IF EXISTS(SELECT 1 FROM private.account_closures c WHERE c.user_id=OLD.id AND
 (NEW.status<>'disabled' OR NEW.auth_subject IS DISTINCT FROM OLD.auth_subject OR NEW.id IS DISTINCT FROM OLD.id
 OR (c.email_erased AND NEW.email IS DISTINCT FROM OLD.email))) THEN
  RAISE EXCEPTION 'Closed account cannot be reactivated or restore erased profile' USING ERRCODE='55000';
 END IF;
 RETURN NEW;
END
$fn$;
ALTER FUNCTION private.prevent_closed_account_reactivation() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.prevent_closed_account_reactivation() FROM PUBLIC,profitpilot_app;
CREATE TRIGGER closed_account_guard BEFORE UPDATE ON public.users FOR EACH ROW EXECUTE FUNCTION private.prevent_closed_account_reactivation();

CREATE FUNCTION private.prevent_closed_membership_activation() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,private AS $fn$
BEGIN
 -- Serialize membership activation with closure's user-row lock, also for administrative provisioning.
 PERFORM 1 FROM public.users WHERE id=NEW.user_id FOR SHARE;
 IF NEW.status='active' AND EXISTS(SELECT 1 FROM private.account_closures c WHERE c.user_id=NEW.user_id) THEN
  RAISE EXCEPTION 'Closed account membership cannot be activated' USING ERRCODE='55000';
 END IF;
 RETURN NEW;
END
$fn$;
ALTER FUNCTION private.prevent_closed_membership_activation() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.prevent_closed_membership_activation() FROM PUBLIC,profitpilot_app;
CREATE TRIGGER closed_membership_guard BEFORE INSERT OR UPDATE ON public.tenant_memberships
 FOR EACH ROW EXECUTE FUNCTION private.prevent_closed_membership_activation();

CREATE FUNCTION private.invalidate_closure_grants_on_hold() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
DECLARE tenant_value uuid;
DECLARE subject_value uuid;
BEGIN
 IF TG_OP='DELETE' THEN tenant_value:=OLD.tenant_id;subject_value:=OLD.subject_user_id;
 ELSE tenant_value:=NEW.tenant_id;subject_value:=NEW.subject_user_id; END IF;
 PERFORM private.lock_privacy_retention_subject(tenant_value,subject_value);
 UPDATE private.account_closure_approvals a SET invalidated_at=clock_timestamp()
 WHERE a.tenant_id=tenant_value AND a.consumed_at IS NULL AND a.invalidated_at IS NULL
 AND EXISTS(SELECT 1 FROM public.privacy_requests r WHERE r.id=a.request_id AND r.tenant_id=tenant_value AND r.subject_user_id=subject_value);
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END
$fn$;
ALTER FUNCTION private.invalidate_closure_grants_on_hold() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.invalidate_closure_grants_on_hold() FROM PUBLIC,profitpilot_app;
CREATE TRIGGER closure_request_hold_invalidation BEFORE UPDATE OF status ON public.privacy_requests
 FOR EACH ROW WHEN (OLD.status IS DISTINCT FROM NEW.status AND (OLD.status='legal_hold' OR NEW.status='legal_hold'))
 EXECUTE FUNCTION private.invalidate_closure_grants_on_hold();
CREATE TRIGGER closure_subject_hold_invalidation BEFORE INSERT OR UPDATE OR DELETE ON private.privacy_retention_holds
 FOR EACH ROW EXECUTE FUNCTION private.invalidate_closure_grants_on_hold();

CREATE FUNCTION private.closure_eligible(p_tenant uuid,p_subject uuid,p_request uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
 SELECT EXISTS(SELECT 1 FROM public.users WHERE id=p_subject AND status='active')
 AND (SELECT count(*) FROM public.tenant_memberships WHERE user_id=p_subject)=1
 AND EXISTS(SELECT 1 FROM public.tenant_memberships WHERE tenant_id=p_tenant AND user_id=p_subject AND status='active' AND role<>'owner')
 AND EXISTS(SELECT 1 FROM public.tenant_memberships m JOIN public.users u ON u.id=m.user_id
  WHERE m.tenant_id=p_tenant AND m.user_id<>p_subject AND m.status='active' AND m.role='owner' AND u.status='active')
 AND NOT EXISTS(SELECT 1 FROM public.privacy_requests WHERE tenant_id=p_tenant AND subject_user_id=p_subject AND id<>p_request
  AND status IN ('requested','identity_verification','under_review','legal_hold'))
 AND NOT EXISTS(SELECT 1 FROM private.privacy_retention_holds WHERE tenant_id=p_tenant AND subject_user_id=p_subject)
 AND NOT EXISTS(SELECT 1 FROM private.account_closures WHERE user_id=p_subject)
$fn$;
ALTER FUNCTION private.closure_eligible(uuid,uuid,uuid) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.closure_eligible(uuid,uuid,uuid) FROM PUBLIC,profitpilot_app;

CREATE FUNCTION private.approve_account_closure(p_tenant uuid,p_request uuid,p_erase boolean,p_auth_time bigint,p_proof text)
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

CREATE FUNCTION private.execute_account_closure(p_tenant uuid,p_request uuid,p_erase boolean,p_auth_time bigint,p_proof text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
DECLARE actor uuid;
DECLARE item public.privacy_requests%ROWTYPE;
DECLARE approval private.account_closure_approvals%ROWTYPE;
DECLARE policy private.privacy_retention_policies%ROWTYPE;
DECLARE account public.users%ROWTYPE;
DECLARE now_at timestamptz;
DECLARE sessions_terminated integer;
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
 PERFORM 1 FROM public.tenant_memberships WHERE user_id=actor FOR UPDATE;
 PERFORM private.lock_privacy_retention_subject(p_tenant,actor);
 IF p_erase THEN
  SELECT * INTO policy FROM private.privacy_retention_policies WHERE tenant_id=p_tenant FOR SHARE;
  IF NOT FOUND OR NOT policy.enabled OR NOT policy.allow_profile_email_erasure OR policy.revision IS DISTINCT FROM approval.policy_revision THEN
   RETURN jsonb_build_object('status',409,'error','Profile erasure authorization changed');
  END IF;
 END IF;
 now_at:=clock_timestamp();
 IF approval.expires_at<=now_at OR item.account_confirmed_at<now_at-interval '24 hours'
 OR NOT private.closure_eligible(p_tenant,actor,p_request)
 OR NOT EXISTS(SELECT 1 FROM public.tenant_memberships m JOIN public.users u ON u.id=m.user_id
 WHERE m.tenant_id=p_tenant AND m.user_id=approval.approved_by AND m.status='active' AND u.status='active' AND m.role IN ('owner','admin') AND m.user_id<>actor) THEN
  RETURN jsonb_build_object('status',409,'error','Closure eligibility, approval or retention check failed');
 END IF;
 UPDATE private.auth_sessions SET revoked_at=now_at,revocation_reason='account_closed'
 WHERE subject=account.auth_subject AND revoked_at IS NULL;
 GET DIAGNOSTICS sessions_terminated=ROW_COUNT;
 UPDATE public.privacy_requests SET status='fulfilled',resolved_at=now_at,updated_at=now_at,
 resolution_summary='ProfitPilot local account closed; external provider and retained records are not erased.'
 WHERE id=p_request AND tenant_id=p_tenant;
 UPDATE private.account_closure_approvals SET consumed_at=now_at WHERE request_id=p_request;
 UPDATE public.tenant_memberships SET status='revoked' WHERE user_id=actor AND tenant_id=p_tenant;
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
CREATE OR REPLACE FUNCTION private.register_auth_session(
 p_jti text,p_subject text,p_issued_at timestamptz,p_expires_at timestamptz
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,private
AS $function$
BEGIN
 IF p_jti IS NULL OR length(p_jti)<16 OR length(p_jti)>128 OR p_subject IS NULL OR length(p_subject)=0
    OR p_expires_at<=p_issued_at OR p_expires_at<=clock_timestamp() THEN
  RAISE EXCEPTION 'Invalid access session registration' USING ERRCODE='22023';
 END IF;
 -- Serialize registration against account closure. Unknown and disabled subjects cannot register.
 PERFORM 1 FROM public.users WHERE auth_subject=p_subject AND status='active' FOR SHARE;
 IF NOT FOUND THEN RETURN; END IF;
 INSERT INTO private.auth_sessions(jti,subject,issued_at,expires_at,last_seen_at)
 VALUES(p_jti,p_subject,p_issued_at,p_expires_at,clock_timestamp())
 ON CONFLICT(jti) DO UPDATE SET last_seen_at=clock_timestamp()
 WHERE private.auth_sessions.subject=EXCLUDED.subject
   AND private.auth_sessions.issued_at=EXCLUDED.issued_at
   AND private.auth_sessions.expires_at=EXCLUDED.expires_at
   AND private.auth_sessions.revoked_at IS NULL;
END;
$function$;
ALTER FUNCTION private.register_auth_session(text,text,timestamptz,timestamptz) OWNER TO profitpilot_context_owner;

CREATE OR REPLACE FUNCTION private.is_auth_session_revoked(p_jti text,p_subject text)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,private
AS $function$
 SELECT NOT EXISTS(
  SELECT 1 FROM private.auth_sessions s
  WHERE s.jti=p_jti AND s.subject=p_subject
    AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
    AND EXISTS(SELECT 1 FROM public.users u WHERE u.auth_subject=p_subject AND u.status='active')
 )
$function$;
ALTER FUNCTION private.is_auth_session_revoked(text,text) OWNER TO profitpilot_context_owner;

COMMIT;

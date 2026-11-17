-- Narrow, policy-gated personal data deletion. Never delete financial, identity or audit history.
BEGIN;
ALTER TABLE public.privacy_requests ADD COLUMN details_redacted_at timestamptz;
ALTER TABLE public.privacy_requests ADD CONSTRAINT privacy_redacted_details_marker CHECK(
 details_redacted_at IS NULL OR details='[Removed under approved retention policy]'
);
CREATE TABLE private.privacy_retention_policies (
 tenant_id uuid PRIMARY KEY REFERENCES public.tenants(id),
 revision uuid NOT NULL,
 enabled boolean NOT NULL DEFAULT false,
 minimum_closed_age_days integer NOT NULL CHECK(minimum_closed_age_days BETWEEN 1 AND 36500),
 authority_reference text NOT NULL CHECK(length(btrim(authority_reference)) BETWEEN 3 AND 500)
);
CREATE TABLE private.privacy_retention_holds (
 tenant_id uuid NOT NULL,
 subject_user_id uuid NOT NULL,
 authority_reference text NOT NULL CHECK(length(btrim(authority_reference)) BETWEEN 3 AND 500),
 PRIMARY KEY(tenant_id,subject_user_id),
 FOREIGN KEY(tenant_id,subject_user_id) REFERENCES public.tenant_memberships(tenant_id,user_id)
);
CREATE TABLE private.privacy_redaction_approvals (
 request_id uuid PRIMARY KEY REFERENCES public.privacy_requests(id),
 target_id uuid NOT NULL REFERENCES public.privacy_requests(id),
 tenant_id uuid NOT NULL REFERENCES public.tenants(id),
 approved_by uuid NOT NULL,
 confirmation_at timestamptz NOT NULL,
 policy_revision uuid NOT NULL,
 minimum_age_days integer NOT NULL,
 approved_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 consumed_at timestamptz,
 FOREIGN KEY(tenant_id,approved_by) REFERENCES public.tenant_memberships(tenant_id,user_id),
 CHECK(request_id<>target_id),
 CHECK(expires_at>approved_at),
 CHECK(consumed_at IS NULL OR (consumed_at>=approved_at AND consumed_at<expires_at))
);
ALTER TABLE private.privacy_retention_policies OWNER TO profitpilot_context_owner;
ALTER TABLE private.privacy_retention_holds OWNER TO profitpilot_context_owner;
ALTER TABLE private.privacy_redaction_approvals OWNER TO profitpilot_context_owner;
REVOKE ALL ON private.privacy_retention_policies,private.privacy_retention_holds,private.privacy_redaction_approvals FROM PUBLIC,profitpilot_app;

CREATE FUNCTION private.lock_privacy_retention_subject(p_tenant uuid,p_subject uuid)
RETURNS void LANGUAGE sql SET search_path=pg_catalog AS $fn$
 SELECT pg_advisory_xact_lock(hashtextextended('privacy-retention-v1:'||p_tenant::text||':'||p_subject::text,0))
$fn$;
ALTER FUNCTION private.lock_privacy_retention_subject(uuid,uuid) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.lock_privacy_retention_subject(uuid,uuid) FROM PUBLIC,profitpilot_app;

CREATE FUNCTION private.serialize_privacy_hold() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,private AS $fn$
BEGIN
 IF TG_OP='DELETE' THEN
  PERFORM private.lock_privacy_retention_subject(OLD.tenant_id,OLD.subject_user_id);
  RETURN OLD;
 END IF;
 IF TG_OP='UPDATE' AND (NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.subject_user_id IS DISTINCT FROM OLD.subject_user_id) THEN
  RAISE EXCEPTION 'Retention hold identity cannot change';
 END IF;
 PERFORM private.lock_privacy_retention_subject(NEW.tenant_id,NEW.subject_user_id);
 RETURN NEW;
END
$fn$;
ALTER FUNCTION private.serialize_privacy_hold() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.serialize_privacy_hold() FROM PUBLIC,profitpilot_app;
CREATE TRIGGER privacy_request_hold_serialization BEFORE UPDATE OF status ON public.privacy_requests
 FOR EACH ROW WHEN (OLD.status IS DISTINCT FROM NEW.status AND (OLD.status='legal_hold' OR NEW.status='legal_hold'))
 EXECUTE FUNCTION private.serialize_privacy_hold();
CREATE TRIGGER privacy_retention_hold_serialization BEFORE INSERT OR UPDATE OR DELETE ON private.privacy_retention_holds
 FOR EACH ROW EXECUTE FUNCTION private.serialize_privacy_hold();

CREATE FUNCTION private.approve_request_redaction(
 p_tenant uuid,p_request uuid,p_target uuid,p_auth_time bigint,p_proof text
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
DECLARE actor uuid;
DECLARE item public.privacy_requests%ROWTYPE;
DECLARE target public.privacy_requests%ROWTYPE;
DECLARE policy private.privacy_retention_policies%ROWTYPE;
DECLARE existing private.privacy_redaction_approvals%ROWTYPE;
DECLARE now_at timestamptz;
BEGIN
 actor:=private.assert_privacy_step_up(p_tenant,p_request,'approve_request_redaction:'||p_target::text,p_auth_time,p_proof);
 IF NOT private.can_manage_privacy_requests() THEN RAISE EXCEPTION 'Privacy manager required' USING ERRCODE='42501'; END IF;
 SELECT * INTO item FROM public.privacy_requests WHERE tenant_id=p_tenant AND id=p_request FOR UPDATE;
 IF NOT FOUND THEN RETURN jsonb_build_object('status',404,'error','Privacy request not found'); END IF;
 IF item.subject_user_id=actor OR item.request_type<>'deletion' OR item.status<>'under_review' OR item.account_confirmed_at IS NULL
 OR item.account_confirmed_at<clock_timestamp()-interval '24 hours' OR p_target=p_request THEN
  RETURN jsonb_build_object('status',409,'error','Independent approval and reviewed deletion request required');
 END IF;
 SELECT * INTO target FROM public.privacy_requests WHERE tenant_id=p_tenant AND id=p_target AND subject_user_id=item.subject_user_id FOR UPDATE;
 IF NOT FOUND THEN RETURN jsonb_build_object('status',404,'error','Eligible target not found'); END IF;
 PERFORM private.lock_privacy_retention_subject(p_tenant,item.subject_user_id);
 SELECT * INTO policy FROM private.privacy_retention_policies WHERE tenant_id=p_tenant FOR SHARE;
 now_at:=clock_timestamp();
 IF NOT FOUND OR NOT policy.enabled
 OR target.request_type='deletion' OR target.status NOT IN ('withdrawn','rejected','fulfilled') OR target.details_redacted_at IS NOT NULL
 OR target.updated_at>now_at-make_interval(days=>policy.minimum_closed_age_days)
 OR EXISTS(SELECT 1 FROM public.privacy_requests WHERE tenant_id=p_tenant AND subject_user_id=item.subject_user_id AND status='legal_hold')
 OR EXISTS(SELECT 1 FROM private.privacy_retention_holds WHERE tenant_id=p_tenant AND subject_user_id=item.subject_user_id) THEN
  RETURN jsonb_build_object('status',409,'error','Retention policy, age, legal hold or target eligibility prevents redaction');
 END IF;
 SELECT * INTO existing FROM private.privacy_redaction_approvals WHERE request_id=p_request;
 IF FOUND AND (existing.consumed_at IS NOT NULL OR (existing.expires_at>now_at AND existing.confirmation_at=item.account_confirmed_at AND existing.policy_revision=policy.revision)) THEN
  RETURN jsonb_build_object('status',409,'error','An active or consumed approval already exists');
 END IF;
 INSERT INTO private.privacy_redaction_approvals(request_id,target_id,tenant_id,approved_by,confirmation_at,policy_revision,minimum_age_days,approved_at,expires_at)
 VALUES(p_request,p_target,p_tenant,actor,item.account_confirmed_at,policy.revision,policy.minimum_closed_age_days,now_at,now_at+interval '15 minutes')
 ON CONFLICT(request_id) DO UPDATE SET target_id=EXCLUDED.target_id,approved_by=EXCLUDED.approved_by,confirmation_at=EXCLUDED.confirmation_at,
 policy_revision=EXCLUDED.policy_revision,minimum_age_days=EXCLUDED.minimum_age_days,approved_at=EXCLUDED.approved_at,expires_at=EXCLUDED.expires_at;
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata)
 VALUES(p_tenant,actor,'privacy_redaction_approved','privacy_request',p_request,'Independent manager approved removal of closed request text',
 jsonb_build_object('targetRequestId',p_target,'policyRevision',policy.revision,'expiresAt',now_at+interval '15 minutes'));
 RETURN jsonb_build_object('status',200,'item',jsonb_build_object('requestId',p_request,'targetRequestId',p_target,'expiresAt',now_at+interval '15 minutes'));
END
$fn$;
ALTER FUNCTION private.approve_request_redaction(uuid,uuid,uuid,bigint,text) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.approve_request_redaction(uuid,uuid,uuid,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.approve_request_redaction(uuid,uuid,uuid,bigint,text) TO profitpilot_app;

CREATE FUNCTION private.execute_request_redaction(
 p_tenant uuid,p_request uuid,p_target uuid,p_auth_time bigint,p_proof text
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
DECLARE actor uuid;
DECLARE item public.privacy_requests%ROWTYPE;
DECLARE target public.privacy_requests%ROWTYPE;
DECLARE policy private.privacy_retention_policies%ROWTYPE;
DECLARE approval private.privacy_redaction_approvals%ROWTYPE;
DECLARE now_at timestamptz;
BEGIN
 actor:=private.assert_privacy_step_up(p_tenant,p_request,'execute_request_redaction:'||p_target::text,p_auth_time,p_proof);
 SELECT * INTO item FROM public.privacy_requests WHERE tenant_id=p_tenant AND id=p_request AND subject_user_id=actor FOR UPDATE;
 IF NOT FOUND THEN RETURN jsonb_build_object('status',404,'error','Privacy request not found'); END IF;
 SELECT * INTO approval FROM private.privacy_redaction_approvals WHERE request_id=p_request AND tenant_id=p_tenant AND target_id=p_target;
 IF NOT FOUND OR approval.consumed_at IS NOT NULL OR item.request_type<>'deletion' OR item.status<>'under_review'
 OR item.account_confirmed_at IS NULL OR approval.confirmation_at IS DISTINCT FROM item.account_confirmed_at
 OR p_auth_time<=floor(extract(epoch FROM approval.approved_at))::bigint THEN
  RETURN jsonb_build_object('status',409,'error','Unused approval and new requester MFA after approval required');
 END IF;
 SELECT * INTO target FROM public.privacy_requests WHERE tenant_id=p_tenant AND id=p_target AND subject_user_id=actor FOR UPDATE;
 IF NOT FOUND THEN RETURN jsonb_build_object('status',404,'error','Eligible target not found'); END IF;
 PERFORM private.lock_privacy_retention_subject(p_tenant,actor);
 SELECT * INTO policy FROM private.privacy_retention_policies WHERE tenant_id=p_tenant FOR SHARE;
 now_at:=clock_timestamp();
 IF NOT FOUND OR NOT policy.enabled OR policy.revision IS DISTINCT FROM approval.policy_revision
 OR policy.minimum_closed_age_days IS DISTINCT FROM approval.minimum_age_days
 OR approval.expires_at<=now_at OR item.account_confirmed_at<now_at-interval '24 hours'
 OR target.request_type='deletion' OR target.status NOT IN ('withdrawn','rejected','fulfilled') OR target.details_redacted_at IS NOT NULL
 OR target.updated_at>now_at-make_interval(days=>policy.minimum_closed_age_days)
 OR EXISTS(SELECT 1 FROM public.privacy_requests WHERE tenant_id=p_tenant AND subject_user_id=actor AND status='legal_hold')
 OR EXISTS(SELECT 1 FROM private.privacy_retention_holds WHERE tenant_id=p_tenant AND subject_user_id=actor)
 OR NOT EXISTS(SELECT 1 FROM public.tenant_memberships m JOIN public.users u ON u.id=m.user_id
 WHERE m.tenant_id=p_tenant AND m.user_id=approval.approved_by AND m.status='active' AND u.status='active'
 AND m.role IN ('owner','admin') AND m.user_id<>actor) THEN
  RETURN jsonb_build_object('status',409,'error','Retention policy, hold, expiry or approver prevents redaction');
 END IF;
 -- Remove only the designated narrative, not the legal record, financial history or audit events.
 UPDATE public.privacy_requests SET details='[Removed under approved retention policy]',details_redacted_at=now_at,updated_at=now_at
 WHERE id=p_target AND tenant_id=p_tenant AND subject_user_id=actor;
 UPDATE private.privacy_redaction_approvals SET consumed_at=now_at WHERE request_id=p_request;
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata)
 VALUES(p_tenant,actor,'privacy_redaction_executed','privacy_request',p_request,'Closed request narrative removed from active database',
 jsonb_build_object('targetRequestId',p_target,'policyRevision',policy.revision,'scope','closed-request-details-v1'));
 RETURN jsonb_build_object('status',200,'item',jsonb_build_object('requestId',p_request,'targetRequestId',p_target,
 'redactedAt',now_at,'scope','closed-request-details-v1','completePersonalDataDeletion',false));
END
$fn$;
ALTER FUNCTION private.execute_request_redaction(uuid,uuid,uuid,bigint,text) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.execute_request_redaction(uuid,uuid,uuid,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.execute_request_redaction(uuid,uuid,uuid,bigint,text) TO profitpilot_app;
COMMIT;

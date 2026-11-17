-- Prevent an approval from surviving a policy change or subject hold.
BEGIN;
ALTER TABLE private.privacy_redaction_approvals ADD COLUMN invalidated_at timestamptz;
CREATE FUNCTION private.refresh_privacy_policy_revision() RETURNS trigger LANGUAGE plpgsql
SET search_path=pg_catalog AS $fn$
BEGIN
 -- A change or re-creation cannot resurrect grants issued under an earlier policy.
 NEW.revision:=gen_random_uuid();
 RETURN NEW;
END
$fn$;
ALTER FUNCTION private.refresh_privacy_policy_revision() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.refresh_privacy_policy_revision() FROM PUBLIC,profitpilot_app;
CREATE TRIGGER privacy_policy_revision_refresh BEFORE INSERT OR UPDATE ON private.privacy_retention_policies
 FOR EACH ROW EXECUTE FUNCTION private.refresh_privacy_policy_revision();

CREATE OR REPLACE FUNCTION private.serialize_privacy_hold() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,private AS $fn$
DECLARE tenant_value uuid;
DECLARE subject_value uuid;
BEGIN
 IF TG_OP='DELETE' THEN
  tenant_value:=OLD.tenant_id;
  subject_value:=OLD.subject_user_id;
 ELSE
  IF TG_OP='UPDATE' AND (NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.subject_user_id IS DISTINCT FROM OLD.subject_user_id) THEN
   RAISE EXCEPTION 'Retention hold identity cannot change';
  END IF;
  tenant_value:=NEW.tenant_id;
  subject_value:=NEW.subject_user_id;
 END IF;
 PERFORM private.lock_privacy_retention_subject(tenant_value,subject_value);
 -- Changes to holds permanently invalidate outstanding grants; release is never permission to erase.
 UPDATE private.privacy_redaction_approvals a SET invalidated_at=clock_timestamp()
 WHERE a.tenant_id=tenant_value AND a.consumed_at IS NULL AND a.invalidated_at IS NULL
 AND EXISTS(SELECT 1 FROM public.privacy_requests r WHERE r.id=a.request_id AND r.tenant_id=tenant_value AND r.subject_user_id=subject_value);
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END
$fn$;
ALTER FUNCTION private.serialize_privacy_hold() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.serialize_privacy_hold() FROM PUBLIC,profitpilot_app;
-- Existing grants were issued before this invalidation rule; require reapproval.
UPDATE private.privacy_redaction_approvals SET invalidated_at=clock_timestamp() WHERE consumed_at IS NULL;
CREATE OR REPLACE FUNCTION private.approve_request_redaction(
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
 IF FOUND AND (existing.consumed_at IS NOT NULL OR (existing.invalidated_at IS NULL AND existing.expires_at>now_at AND existing.confirmation_at=item.account_confirmed_at AND existing.policy_revision=policy.revision)) THEN
  RETURN jsonb_build_object('status',409,'error','An active or consumed approval already exists');
 END IF;
 INSERT INTO private.privacy_redaction_approvals(request_id,target_id,tenant_id,approved_by,confirmation_at,policy_revision,minimum_age_days,approved_at,expires_at)
 VALUES(p_request,p_target,p_tenant,actor,item.account_confirmed_at,policy.revision,policy.minimum_closed_age_days,now_at,now_at+interval '15 minutes')
 ON CONFLICT(request_id) DO UPDATE SET target_id=EXCLUDED.target_id,approved_by=EXCLUDED.approved_by,confirmation_at=EXCLUDED.confirmation_at,
 policy_revision=EXCLUDED.policy_revision,minimum_age_days=EXCLUDED.minimum_age_days,approved_at=EXCLUDED.approved_at,expires_at=EXCLUDED.expires_at,invalidated_at=NULL;
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata)
 VALUES(p_tenant,actor,'privacy_redaction_approved','privacy_request',p_request,'Independent manager approved removal of closed request text',
 jsonb_build_object('targetRequestId',p_target,'policyRevision',policy.revision,'expiresAt',now_at+interval '15 minutes'));
 RETURN jsonb_build_object('status',200,'item',jsonb_build_object('requestId',p_request,'targetRequestId',p_target,'expiresAt',now_at+interval '15 minutes'));
END
$fn$;
ALTER FUNCTION private.approve_request_redaction(uuid,uuid,uuid,bigint,text) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.approve_request_redaction(uuid,uuid,uuid,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.approve_request_redaction(uuid,uuid,uuid,bigint,text) TO profitpilot_app;

CREATE OR REPLACE FUNCTION private.execute_request_redaction(
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
 IF NOT FOUND OR approval.consumed_at IS NOT NULL OR approval.invalidated_at IS NOT NULL OR item.request_type<>'deletion' OR item.status<>'under_review'
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
CREATE OR REPLACE FUNCTION private.release_account_export(
 p_tenant uuid,p_request uuid,p_auth_time bigint,p_proof text
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,public,private
AS $fn$
DECLARE actor uuid;
DECLARE item public.privacy_requests%ROWTYPE;
DECLARE approval private.privacy_export_approvals%ROWTYPE;
DECLARE profile jsonb;
DECLARE membership_data jsonb;
DECLARE request_data jsonb;
DECLARE request_count integer;
DECLARE activity_count integer;
DECLARE activity_data jsonb;
DECLARE payload jsonb;
DECLARE now_at timestamptz;
BEGIN
 actor:=private.assert_privacy_step_up(p_tenant,p_request,'release_account_export',p_auth_time,p_proof);
 SELECT * INTO item FROM public.privacy_requests WHERE tenant_id=p_tenant AND id=p_request AND subject_user_id=actor FOR UPDATE;
 IF NOT FOUND THEN RETURN jsonb_build_object('status',404,'error','Privacy request not found'); END IF;
 SELECT * INTO approval FROM private.privacy_export_approvals WHERE request_id=p_request AND tenant_id=p_tenant;
 now_at:=clock_timestamp();
 IF NOT FOUND OR item.request_type NOT IN ('access','export') OR item.status<>'under_review'
 OR item.account_confirmed_at IS NULL OR item.account_confirmed_at<now_at-interval '24 hours'
 OR approval.confirmation_at IS DISTINCT FROM item.account_confirmed_at
 OR approval.scope<>'account-v2' OR approval.consumed_at IS NOT NULL OR approval.expires_at<=now_at
 OR p_auth_time<=floor(extract(epoch FROM approval.approved_at))::bigint
 OR NOT EXISTS(SELECT 1 FROM public.tenant_memberships m JOIN public.users u ON u.id=m.user_id
   WHERE m.tenant_id=p_tenant AND m.user_id=approval.approved_by AND m.status='active' AND u.status='active'
   AND m.role IN ('owner','admin') AND m.user_id<>actor) THEN
  RETURN jsonb_build_object('status',409,'error','Valid unused approval and fresh requester MFA required');
 END IF;
 -- Every projection is explicitly allowlisted; never export raw JSON, free text, secrets or other members.
 SELECT jsonb_build_object('email',u.email,'status',u.status,'createdAt',u.created_at)
 INTO profile FROM public.users u WHERE u.id=actor AND u.status='active';
 SELECT jsonb_build_object('tenantId',m.tenant_id,'role',m.role,'status',m.status,'grantedAt',m.granted_at)
 INTO membership_data FROM public.tenant_memberships m WHERE m.tenant_id=p_tenant AND m.user_id=actor AND m.status='active';
 IF profile IS NULL OR membership_data IS NULL THEN RETURN jsonb_build_object('status',403,'error','Active account and membership required'); END IF;
 SELECT count(*),coalesce(jsonb_agg(r.record ORDER BY r.created_at,r.id),'[]'::jsonb)
 INTO request_count,request_data
 FROM (
  SELECT id,created_at,jsonb_build_object('id',id,'type',request_type,'status',status,
   'createdAt',created_at,'updatedAt',updated_at,'resolvedAt',resolved_at,'accountConfirmedAt',account_confirmed_at) AS record
  FROM public.privacy_requests WHERE tenant_id=p_tenant AND subject_user_id=actor
  ORDER BY created_at,id LIMIT 101
 ) r;
 IF request_count>100 THEN RETURN jsonb_build_object('status',409,'error','Export exceeds automatic record limit; manual review required'); END IF;
 -- Only fixed event labels and timestamps, from explicitly attributed tenant actor columns.
 SELECT count(*),coalesce(jsonb_agg(jsonb_build_object('kind',a.kind,'at',a.at) ORDER BY a.at,a.kind),'[]'::jsonb)
 INTO activity_count,activity_data
 FROM (
  SELECT kind,at FROM (
   SELECT 'import_created'::text AS kind,created_at AS at FROM public.import_batches WHERE tenant_id=p_tenant AND created_by=actor
   UNION ALL SELECT 'mapping_reviewed',reviewed_at FROM public.mapping_decisions WHERE tenant_id=p_tenant AND reviewer_id=actor AND reviewed_at IS NOT NULL
   UNION ALL SELECT 'match_reviewed',reviewed_at FROM public.match_reviews WHERE tenant_id=p_tenant AND reviewer_id=actor AND reviewed_at IS NOT NULL
   UNION ALL SELECT 'contract_approved',approved_at FROM public.contract_versions WHERE tenant_id=p_tenant AND approved_by=actor AND approved_at IS NOT NULL
   UNION ALL SELECT 'variation_approved',approved_at FROM public.variations WHERE tenant_id=p_tenant AND approved_by=actor AND approved_at IS NOT NULL
   UNION ALL SELECT 'calculation_created',created_at FROM public.calculation_runs WHERE tenant_id=p_tenant AND created_by=actor
  ) activity ORDER BY at,kind LIMIT 501
 ) a;
 IF activity_count>500 THEN RETURN jsonb_build_object('status',409,'error','Activity export exceeds automatic record limit; manual review required'); END IF;
 payload:=jsonb_build_object('schemaVersion',2,'scope','account-v2','completePersonalDataExport',false,
 'requestId',p_request,'generatedAt',now_at,'account',profile,'membership',membership_data,'privacyRequestMetadata',request_data,'attributedActivity',activity_data,
 'limitations',jsonb_build_array('Includes account profile, current tenant membership, own privacy request metadata and fixed-label activity timestamps explicitly attributed to the requester.',
 'Free text, third-party information, imported business and payroll data, underlying operational record contents, other tenants, audit details and identity-provider data require separate review.',
 'This does not complete the privacy request.'));
 IF octet_length(payload::text)>1048576 THEN RETURN jsonb_build_object('status',409,'error','Export exceeds automatic size limit; manual review required'); END IF;
 -- Recheck expiry at consumption; row lock serializes all competing request transitions/releases.
 now_at:=clock_timestamp();
 IF approval.expires_at<=now_at THEN RETURN jsonb_build_object('status',409,'error','Export approval expired'); END IF;
 UPDATE private.privacy_export_approvals SET consumed_at=now_at WHERE request_id=p_request;
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata)
 VALUES(p_tenant,actor,'privacy_account_export_released','privacy_request',p_request,
 'Restricted account export generated and authorized for response',
 jsonb_build_object('scope','account-v2','privacyRequestCount',request_count,'activityCount',activity_count));
 RETURN jsonb_build_object('status',200,'item',payload);
END
$fn$;
ALTER FUNCTION private.release_account_export(uuid,uuid,bigint,text) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.release_account_export(uuid,uuid,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.release_account_export(uuid,uuid,bigint,text) TO profitpilot_app;
COMMIT;

-- Expand safe attribution metadata; old grants cannot authorize a broader export.
BEGIN;
-- Original schema default grants otherwise permit direct runtime privilege escalation and deletion.
REVOKE INSERT,UPDATE,DELETE,TRUNCATE ON public.tenants,public.tenant_memberships,public.permission_catalog,public.role_permissions,public.tenant_membership_permission_overrides FROM profitpilot_app;
REVOKE DELETE,TRUNCATE ON public.privacy_requests FROM profitpilot_app;
ALTER TABLE private.privacy_export_approvals ADD COLUMN scope text NOT NULL DEFAULT 'account-v1' CHECK(scope IN ('account-v1','account-v2'));
GRANT SELECT(tenant_id,created_by,created_at) ON public.import_batches,public.calculation_runs TO profitpilot_context_owner;
GRANT SELECT(tenant_id,reviewer_id,reviewed_at) ON public.mapping_decisions,public.match_reviews TO profitpilot_context_owner;
GRANT SELECT(tenant_id,approved_by,approved_at) ON public.contract_versions,public.variations TO profitpilot_context_owner;
CREATE OR REPLACE FUNCTION private.approve_account_export(
 p_tenant uuid,p_request uuid,p_auth_time bigint,p_proof text
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,public,private
AS $fn$
DECLARE actor uuid;
DECLARE item public.privacy_requests%ROWTYPE;
DECLARE now_at timestamptz;
DECLARE approval private.privacy_export_approvals%ROWTYPE;
BEGIN
 actor:=private.assert_privacy_step_up(p_tenant,p_request,'approve_account_export',p_auth_time,p_proof);
 IF NOT private.can_manage_privacy_requests() THEN
  RAISE EXCEPTION 'Privacy manager required' USING ERRCODE='42501';
 END IF;
 SELECT * INTO item FROM public.privacy_requests WHERE tenant_id=p_tenant AND id=p_request FOR UPDATE;
 IF NOT FOUND THEN RETURN jsonb_build_object('status',404,'error','Privacy request not found'); END IF;
 now_at:=clock_timestamp();
 IF item.subject_user_id=actor OR item.request_type NOT IN ('access','export') OR item.status<>'under_review'
 OR item.account_confirmed_at IS NULL OR item.account_confirmed_at<now_at-interval '24 hours' THEN
  RETURN jsonb_build_object('status',409,'error','Independent approval and recent account confirmation required for an export request in review');
 END IF;
 -- An outstanding grant cannot be silently renewed or replaced.
 SELECT * INTO approval FROM private.privacy_export_approvals WHERE request_id=p_request;
 IF FOUND AND approval.consumed_at IS NULL AND approval.expires_at>now_at
 AND approval.confirmation_at=item.account_confirmed_at AND approval.scope='account-v2' THEN
  RETURN jsonb_build_object('status',409,'error','An unused export approval is already active');
 END IF;
 INSERT INTO private.privacy_export_approvals(request_id,tenant_id,approved_by,confirmation_at,approved_at,expires_at,consumed_at,scope)
 VALUES(p_request,p_tenant,actor,item.account_confirmed_at,now_at,now_at+interval '15 minutes',NULL,'account-v2')
 ON CONFLICT(request_id) DO UPDATE SET approved_by=EXCLUDED.approved_by,
 confirmation_at=EXCLUDED.confirmation_at,approved_at=EXCLUDED.approved_at,expires_at=EXCLUDED.expires_at,consumed_at=NULL,scope=EXCLUDED.scope;
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata)
 VALUES(p_tenant,actor,'privacy_account_export_approved','privacy_request',p_request,
 'Independent manager approved a restricted account export',
 jsonb_build_object('scope','account-v2','expiresAt',now_at+interval '15 minutes'));
 RETURN jsonb_build_object('status',200,'item',jsonb_build_object('requestId',p_request,'scope','account-v2','expiresAt',now_at+interval '15 minutes'));
END
$fn$;
ALTER FUNCTION private.approve_account_export(uuid,uuid,bigint,text) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.approve_account_export(uuid,uuid,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.approve_account_export(uuid,uuid,bigint,text) TO profitpilot_app;

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
 OR p_auth_time<floor(extract(epoch FROM approval.approved_at))::bigint
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

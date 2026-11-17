-- Restricted account-data export. No stored export files; one-use approved release.
BEGIN;
CREATE TABLE private.privacy_export_approvals (
 request_id uuid PRIMARY KEY REFERENCES public.privacy_requests(id) ON DELETE RESTRICT,
 tenant_id uuid NOT NULL,
 approved_by uuid NOT NULL,
 confirmation_at timestamptz NOT NULL,
 approved_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 consumed_at timestamptz,
 FOREIGN KEY(tenant_id,approved_by) REFERENCES public.tenant_memberships(tenant_id,user_id),
 CHECK(expires_at>approved_at),
 CHECK(consumed_at IS NULL OR (consumed_at>=approved_at AND consumed_at<expires_at))
);
ALTER TABLE private.privacy_export_approvals OWNER TO profitpilot_context_owner;
REVOKE ALL ON private.privacy_export_approvals FROM PUBLIC,profitpilot_app;

CREATE FUNCTION private.approve_account_export(
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
 AND approval.confirmation_at=item.account_confirmed_at THEN
  RETURN jsonb_build_object('status',409,'error','An unused export approval is already active');
 END IF;
 INSERT INTO private.privacy_export_approvals(request_id,tenant_id,approved_by,confirmation_at,approved_at,expires_at,consumed_at)
 VALUES(p_request,p_tenant,actor,item.account_confirmed_at,now_at,now_at+interval '15 minutes',NULL)
 ON CONFLICT(request_id) DO UPDATE SET approved_by=EXCLUDED.approved_by,
 confirmation_at=EXCLUDED.confirmation_at,approved_at=EXCLUDED.approved_at,expires_at=EXCLUDED.expires_at,consumed_at=NULL;
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata)
 VALUES(p_tenant,actor,'privacy_account_export_approved','privacy_request',p_request,
 'Independent manager approved a restricted account export',
 jsonb_build_object('scope','account-v1','expiresAt',now_at+interval '15 minutes'));
 RETURN jsonb_build_object('status',200,'item',jsonb_build_object('requestId',p_request,'scope','account-v1','expiresAt',now_at+interval '15 minutes'));
END
$fn$;
ALTER FUNCTION private.approve_account_export(uuid,uuid,bigint,text) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.approve_account_export(uuid,uuid,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.approve_account_export(uuid,uuid,bigint,text) TO profitpilot_app;

CREATE FUNCTION private.release_account_export(
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
 OR approval.consumed_at IS NOT NULL OR approval.expires_at<=now_at
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
 payload:=jsonb_build_object('schemaVersion',1,'scope','account-v1','completePersonalDataExport',false,
 'requestId',p_request,'generatedAt',now_at,'account',profile,'membership',membership_data,'privacyRequestMetadata',request_data,
 'limitations',jsonb_build_array('Only account profile, current tenant membership and own privacy request metadata are included.',
 'Free text, third-party information, imported business and payroll data, operational records, other tenants, audit details and identity-provider data require separate review.',
 'This does not complete the privacy request.'));
 IF octet_length(payload::text)>1048576 THEN RETURN jsonb_build_object('status',409,'error','Export exceeds automatic size limit; manual review required'); END IF;
 -- Recheck expiry at consumption; row lock serializes all competing request transitions/releases.
 now_at:=clock_timestamp();
 IF approval.expires_at<=now_at THEN RETURN jsonb_build_object('status',409,'error','Export approval expired'); END IF;
 UPDATE private.privacy_export_approvals SET consumed_at=now_at WHERE request_id=p_request;
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata)
 VALUES(p_tenant,actor,'privacy_account_export_released','privacy_request',p_request,
 'Restricted account export generated and authorized for response',
 jsonb_build_object('scope','account-v1','privacyRequestCount',request_count));
 RETURN jsonb_build_object('status',200,'item',payload);
END
$fn$;
ALTER FUNCTION private.release_account_export(uuid,uuid,bigint,text) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.release_account_export(uuid,uuid,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.release_account_export(uuid,uuid,bigint,text) TO profitpilot_app;
COMMIT;

-- Require request-bound step-up evidence and constrain privacy state writes.
BEGIN;
ALTER TABLE public.privacy_requests
 ADD COLUMN account_confirmed_at timestamptz,
 ADD COLUMN account_auth_time timestamptz,
 ADD CONSTRAINT privacy_account_confirmation_pair CHECK (
  (account_confirmed_at IS NULL AND account_auth_time IS NULL)
  OR (account_confirmed_at IS NOT NULL AND account_auth_time IS NOT NULL AND account_auth_time <= account_confirmed_at)
 );
-- Only the narrowly scoped security-definer functions may change a request.
REVOKE INSERT, UPDATE ON public.privacy_requests FROM profitpilot_app;
GRANT INSERT(tenant_id,subject_user_id,submitted_by,request_type,details) ON public.privacy_requests TO profitpilot_app;

CREATE FUNCTION private.assert_privacy_step_up(
 p_tenant uuid,p_request uuid,p_action text,p_auth_time bigint,p_proof text
) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,public,private
AS $fn$
DECLARE actor uuid;
DECLARE secret_value bytea;
DECLARE expected text;
DECLARE now_epoch bigint:=floor(extract(epoch FROM clock_timestamp()))::bigint;
BEGIN
 IF p_tenant IS NULL OR private.current_tenant_id() IS DISTINCT FROM p_tenant THEN
  RAISE EXCEPTION 'Tenant context mismatch' USING ERRCODE='42501';
 END IF;
 actor:=private.current_user_id();
 IF actor IS NULL OR p_request IS NULL OR p_action IS NULL OR p_auth_time IS NULL OR
    p_auth_time < now_epoch-900 OR p_auth_time > now_epoch OR
    p_proof IS NULL OR p_proof !~ '^[a-f0-9]{64}$' THEN
  RAISE EXCEPTION 'Invalid privacy step-up proof' USING ERRCODE='42501';
 END IF;
 SELECT secret INTO secret_value FROM private.tenant_context_keys
 WHERE key_id=current_setting('app.tenant_key_id',true) AND active;
 IF secret_value IS NULL THEN RAISE EXCEPTION 'Invalid privacy step-up proof' USING ERRCODE='42501'; END IF;
 expected:=encode(public.hmac(convert_to(
  'profitpilot-privacy-step-up-v1'||E'\n'||p_tenant::text||E'\n'||actor::text||E'\n'||
  p_request::text||E'\n'||p_action||E'\n'||p_auth_time::text||E'\n'||current_setting('app.tenant_nonce',true),
  'UTF8'),secret_value,'sha256'),'hex');
 IF expected IS DISTINCT FROM p_proof THEN
  RAISE EXCEPTION 'Invalid privacy step-up proof' USING ERRCODE='42501';
 END IF;
 RETURN actor;
END
$fn$;
ALTER FUNCTION private.assert_privacy_step_up(uuid,uuid,text,bigint,text) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.assert_privacy_step_up(uuid,uuid,text,bigint,text) FROM PUBLIC,profitpilot_app;

CREATE FUNCTION private.confirm_privacy_account(
 p_tenant uuid,p_request uuid,p_auth_time bigint,p_proof text
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,public,private
AS $fn$
DECLARE actor uuid;
DECLARE item public.privacy_requests%ROWTYPE;
BEGIN
 actor:=private.assert_privacy_step_up(p_tenant,p_request,'confirm_account',p_auth_time,p_proof);
 SELECT * INTO item FROM public.privacy_requests
 WHERE id=p_request AND tenant_id=p_tenant AND subject_user_id=actor FOR UPDATE;
 IF NOT FOUND THEN RETURN jsonb_build_object('status',404,'error','Privacy request not found'); END IF;
 IF item.status NOT IN ('identity_verification','under_review','legal_hold')
 OR p_auth_time < floor(extract(epoch FROM item.created_at))::bigint THEN
  RETURN jsonb_build_object('status',409,'error','Request is not awaiting account confirmation or authentication predates request');
 END IF;
 -- Duplicate confirmation from the same or an older authentication cannot renew evidence.
 IF item.account_auth_time IS NOT NULL AND to_timestamp(p_auth_time)<=item.account_auth_time THEN
  RETURN jsonb_build_object('status',409,'error','A new authentication event is required');
 END IF;
 UPDATE public.privacy_requests SET account_confirmed_at=clock_timestamp(),
 account_auth_time=to_timestamp(p_auth_time),updated_at=clock_timestamp()
 WHERE id=p_request AND tenant_id=p_tenant RETURNING * INTO item;
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata)
 VALUES(p_tenant,actor,'privacy_account_confirmed','privacy_request',p_request,
 'Requester confirmed account control using recent MFA',
 jsonb_build_object('method','provider_step_up','authenticatedAt',item.account_auth_time));
 RETURN jsonb_build_object('status',200,'item',jsonb_build_object('id',item.id,'account_confirmed_at',item.account_confirmed_at));
END
$fn$;
ALTER FUNCTION private.confirm_privacy_account(uuid,uuid,bigint,text) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.confirm_privacy_account(uuid,uuid,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.confirm_privacy_account(uuid,uuid,bigint,text) TO profitpilot_app;

CREATE FUNCTION private.decide_privacy_request(
 p_tenant uuid,p_request uuid,p_action text,p_reason text,p_summary text,p_auth_time bigint,p_proof text
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,public,private
AS $fn$
DECLARE actor uuid;
DECLARE item public.privacy_requests%ROWTYPE;
DECLARE next_status text;
DECLARE old_status text;
BEGIN
 actor:=private.assert_privacy_step_up(p_tenant,p_request,'decision:'||p_action,p_auth_time,p_proof);
 IF NOT private.can_manage_privacy_requests() THEN
  RAISE EXCEPTION 'Privacy manager required' USING ERRCODE='42501';
 END IF;
 IF p_action IS NULL OR p_action NOT IN ('verify_identity','begin_review','place_legal_hold','release_legal_hold','reject')
 OR p_reason IS NULL OR length(btrim(p_reason)) NOT BETWEEN 3 AND 1000
 OR (p_action='reject' AND (p_summary IS NULL OR length(btrim(p_summary)) NOT BETWEEN 3 AND 2000)) THEN
  RETURN jsonb_build_object('status',400,'error','Invalid privacy decision');
 END IF;
 SELECT * INTO item FROM public.privacy_requests WHERE id=p_request AND tenant_id=p_tenant FOR UPDATE;
 IF NOT FOUND THEN RETURN jsonb_build_object('status',404,'error','Privacy request not found'); END IF;
 old_status:=item.status;
 IF p_action='verify_identity' AND old_status='requested' THEN next_status:='identity_verification';
 ELSIF p_action='begin_review' AND old_status='identity_verification' THEN next_status:='under_review';
 ELSIF p_action='place_legal_hold' AND old_status IN ('requested','identity_verification','under_review') THEN next_status:='legal_hold';
 ELSIF p_action='release_legal_hold' AND old_status='legal_hold' THEN
  -- Release to verification, never directly into review.
  next_status:='identity_verification';
 ELSIF p_action='reject' AND old_status IN ('requested','identity_verification','under_review') THEN next_status:='rejected';
 ELSE RETURN jsonb_build_object('status',409,'error','Invalid privacy request transition');
 END IF;
 IF next_status='under_review' AND (
  actor=item.subject_user_id OR item.account_confirmed_at IS NULL OR
  item.account_confirmed_at < clock_timestamp()-interval '24 hours'
 ) THEN
  RETURN jsonb_build_object('status',409,'error','Recent requester MFA confirmation and independent manager required');
 END IF;
 UPDATE public.privacy_requests SET status=next_status,
 legal_hold_reason=CASE WHEN next_status='legal_hold' THEN btrim(p_reason) ELSE NULL END,
 resolution_summary=CASE WHEN next_status='rejected' THEN btrim(p_summary) ELSE resolution_summary END,
 assigned_to=actor,updated_at=clock_timestamp(),
 resolved_at=CASE WHEN next_status='rejected' THEN clock_timestamp() ELSE NULL END,
 account_confirmed_at=CASE WHEN p_action='release_legal_hold' THEN NULL ELSE account_confirmed_at END,
 account_auth_time=CASE WHEN p_action='release_legal_hold' THEN NULL ELSE account_auth_time END
 WHERE id=p_request AND tenant_id=p_tenant RETURNING * INTO item;
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata)
 VALUES(p_tenant,actor,'privacy_request_status_changed','privacy_request',p_request,btrim(p_reason),
 jsonb_build_object('action',p_action,'fromStatus',old_status,'toStatus',next_status));
 RETURN jsonb_build_object('status',200,'item',jsonb_build_object(
 'id',item.id,'request_type',item.request_type,'status',item.status,'updated_at',item.updated_at,
 'resolved_at',item.resolved_at,'resolution_summary',item.resolution_summary,'legal_hold_reason',item.legal_hold_reason,
 'account_confirmed_at',item.account_confirmed_at));
END
$fn$;
ALTER FUNCTION private.decide_privacy_request(uuid,uuid,text,text,text,bigint,text) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.decide_privacy_request(uuid,uuid,text,text,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.decide_privacy_request(uuid,uuid,text,text,text,bigint,text) TO profitpilot_app;
COMMIT;

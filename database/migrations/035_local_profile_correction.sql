-- Scoped local email correction from a reviewed request and signed provider evidence.
BEGIN;
CREATE TABLE private.local_email_corrections(
 request_id uuid PRIMARY KEY REFERENCES public.privacy_requests(id) ON DELETE RESTRICT,
 tenant_id uuid NOT NULL,
 user_id uuid NOT NULL,
 reviewed_by uuid NOT NULL,
 corrected_at timestamptz NOT NULL,
 FOREIGN KEY(tenant_id,user_id) REFERENCES public.tenant_memberships(tenant_id,user_id),
 FOREIGN KEY(tenant_id,reviewed_by) REFERENCES public.tenant_memberships(tenant_id,user_id),
 CHECK(user_id<>reviewed_by)
);
ALTER TABLE private.local_email_corrections OWNER TO profitpilot_context_owner;
REVOKE ALL ON private.local_email_corrections FROM PUBLIC,profitpilot_app;
CREATE FUNCTION private.correct_local_email(p_tenant uuid,p_request uuid,p_evidence text,p_auth_time bigint,p_proof text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
DECLARE actor uuid; item public.privacy_requests%ROWTYPE; account public.users%ROWTYPE;
DECLARE evidence jsonb; next_email text; issued_at bigint; at_time timestamptz;
BEGIN
 IF p_evidence IS NULL OR octet_length(p_evidence)>4096 THEN RAISE EXCEPTION 'Invalid correction evidence' USING ERRCODE='22023'; END IF;
 actor:=private.assert_privacy_step_up(p_tenant,p_request,'correct_local_email:'||encode(public.digest(convert_to(p_evidence,'UTF8'),'sha256'),'hex'),p_auth_time,p_proof);
 IF private.has_scoped_permission(p_tenant,'privacy.requests.submit') IS DISTINCT FROM true THEN RAISE EXCEPTION 'Correction permission required' USING ERRCODE='42501'; END IF;
 SELECT * INTO item FROM public.privacy_requests WHERE id=p_request AND tenant_id=p_tenant AND subject_user_id=actor FOR UPDATE;
 IF NOT FOUND THEN RETURN jsonb_build_object('status',404,'error','Privacy request not found'); END IF;
 SELECT * INTO account FROM public.users WHERE id=actor AND status='active' FOR UPDATE;
 IF NOT FOUND THEN RETURN jsonb_build_object('status',409,'error','Active account required'); END IF;
 PERFORM 1 FROM public.tenant_memberships WHERE user_id=actor ORDER BY tenant_id FOR UPDATE;
 PERFORM private.lock_privacy_retention_subject(p_tenant,actor);
 at_time:=clock_timestamp();
 evidence:=p_evidence::jsonb;next_email:=evidence->>'email';issued_at:=(evidence->>'issuedAt')::bigint;
 IF item.request_type<>'correction' OR item.status<>'under_review' OR item.account_confirmed_at IS NULL
 OR item.account_confirmed_at<at_time-interval '24 hours' OR p_auth_time<=floor(extract(epoch FROM item.updated_at))::bigint
 OR issued_at IS NULL OR issued_at<p_auth_time OR issued_at>floor(extract(epoch FROM at_time))::bigint+5
 OR item.assigned_to IS NULL OR item.assigned_to=actor
 OR NOT EXISTS(SELECT 1 FROM public.tenant_memberships m JOIN public.users u ON u.id=m.user_id
 WHERE m.tenant_id=p_tenant AND m.user_id=item.assigned_to AND m.status='active' AND m.role IN ('owner','admin') AND u.status='active')
 OR (SELECT count(*) FROM public.tenant_memberships WHERE user_id=actor)<>1
 OR EXISTS(SELECT 1 FROM private.privacy_retention_holds WHERE subject_user_id=actor)
 OR EXISTS(SELECT 1 FROM public.privacy_requests WHERE subject_user_id=actor AND status='legal_hold')
 OR EXISTS(SELECT 1 FROM private.local_email_corrections WHERE request_id=p_request)
 THEN RETURN jsonb_build_object('status',409,'error','Independent reviewed correction, new MFA, single membership and no hold required'); END IF;
 IF account.auth_issuer IS NULL OR account.auth_issuer IS DISTINCT FROM evidence->>'issuer'
 OR next_email IS NULL OR length(next_email) NOT BETWEEN 3 AND 254
 OR next_email !~ '^[^[:space:]@[:cntrl:]]+@[^[:space:]@[:cntrl:]]+\.[^[:space:]@[:cntrl:]]+$'
 OR next_email LIKE 'erased-%@invalid.example'
 OR next_email IS NOT DISTINCT FROM account.email
 THEN RETURN jsonb_build_object('status',409,'error','Verified email does not provide an eligible correction'); END IF;
 UPDATE public.users SET email=next_email WHERE id=actor;
 INSERT INTO private.local_email_corrections(request_id,tenant_id,user_id,reviewed_by,corrected_at)
 VALUES(p_request,p_tenant,actor,item.assigned_to,at_time);
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata)
 VALUES(p_tenant,actor,'privacy_local_email_corrected','privacy_request',p_request,'Local profile email corrected from verified provider claim',jsonb_build_object('scope','local-profile-email','completePersonalDataCorrection',false));
 -- Record a scoped receipt but do not close a potentially broader request.
 RETURN jsonb_build_object('status',200,'item',jsonb_build_object('requestId',p_request,'correctedAt',at_time,'scope','local-profile-email','completePersonalDataCorrection',false,'providerAccountChanged',false));
END
$fn$;
ALTER FUNCTION private.correct_local_email(uuid,uuid,text,bigint,text) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.correct_local_email(uuid,uuid,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.correct_local_email(uuid,uuid,text,bigint,text) TO profitpilot_app;

ALTER FUNCTION private.privacy_restore_state() RENAME TO privacy_restore_state_before_email_correction;
CREATE FUNCTION private.privacy_restore_state() RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
 SELECT jsonb_build_object(
 'markers',s.state->'markers'||COALESCE((SELECT jsonb_agg(jsonb_build_object('kind','local_email_correction','id',c.request_id,'tenantId',c.tenant_id,'userId',c.user_id,'at',extract(epoch FROM c.corrected_at)::text) ORDER BY c.request_id) FROM private.local_email_corrections c),'[]'::jsonb),
 'violations',s.state->'violations'||COALESCE((SELECT jsonb_agg(jsonb_build_object('kind','local_email_correction_mismatch','id',c.request_id)) FROM private.local_email_corrections c LEFT JOIN public.privacy_requests r ON r.id=c.request_id WHERE r.id IS NULL OR r.tenant_id<>c.tenant_id OR r.subject_user_id<>c.user_id OR r.request_type<>'correction'),'[]'::jsonb))
 FROM (SELECT private.privacy_restore_state_before_email_correction() AS state) s
$fn$;
ALTER FUNCTION private.privacy_restore_state() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.privacy_restore_state(),private.privacy_restore_state_before_email_correction() FROM PUBLIC,profitpilot_app;
COMMIT;

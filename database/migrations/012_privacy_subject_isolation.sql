-- ProfitPilot migration 012: enforce subject-level privacy request isolation in PostgreSQL.
-- Members may read and submit only their own requests. Tenant privacy managers
-- may review tenant requests. Member withdrawal is a narrowly scoped definer action.
BEGIN;

CREATE OR REPLACE FUNCTION private.current_user_id()
RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,private
AS $function$
DECLARE actor_id uuid;
BEGIN
 IF private.current_tenant_id() IS NULL THEN RETURN NULL; END IF;
 SELECT id INTO actor_id
 FROM public.users
 WHERE auth_subject=nullif(current_setting('app.tenant_subject',true),'')
   AND status='active';
 RETURN actor_id;
END
$function$;
ALTER FUNCTION private.current_user_id() OWNER TO profitpilot_context_owner;

CREATE OR REPLACE FUNCTION private.can_manage_privacy_requests()
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,private
AS $function$
 SELECT EXISTS (
  SELECT 1
  FROM public.tenant_memberships tm
  JOIN public.users u ON u.id=tm.user_id
  WHERE tm.tenant_id=private.current_tenant_id()
    AND u.auth_subject=nullif(current_setting('app.tenant_subject',true),'')
    AND u.status='active'
    AND tm.status='active'
    AND tm.role IN ('owner','admin')
 )
$function$;
ALTER FUNCTION private.can_manage_privacy_requests() OWNER TO profitpilot_context_owner;

REVOKE ALL ON FUNCTION private.current_user_id() FROM PUBLIC;
REVOKE ALL ON FUNCTION private.can_manage_privacy_requests() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.current_user_id() TO profitpilot_app;
GRANT EXECUTE ON FUNCTION private.can_manage_privacy_requests() TO profitpilot_app;

DROP POLICY tenant_isolation ON public.privacy_requests;
CREATE POLICY privacy_requests_subject_read
 ON public.privacy_requests FOR SELECT
 USING (
  tenant_id=private.current_tenant_id()
  AND (subject_user_id=private.current_user_id() OR private.can_manage_privacy_requests())
);
CREATE POLICY privacy_requests_subject_insert
 ON public.privacy_requests FOR INSERT
 WITH CHECK (
  tenant_id=private.current_tenant_id()
  AND subject_user_id=private.current_user_id()
  AND submitted_by=private.current_user_id()
);
CREATE POLICY privacy_requests_manager_update
 ON public.privacy_requests FOR UPDATE
 USING (
  tenant_id=private.current_tenant_id()
  AND private.can_manage_privacy_requests()
 )
 WITH CHECK (
  tenant_id=private.current_tenant_id()
  AND private.can_manage_privacy_requests()
 );

GRANT SELECT,UPDATE ON public.privacy_requests TO profitpilot_context_owner;

CREATE OR REPLACE FUNCTION private.withdraw_privacy_request(
 p_tenant_id uuid,p_request_id uuid,p_reason text
) RETURNS TABLE(request_id uuid,request_status text,request_updated_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,public,private
AS $function$
DECLARE actor_id uuid;
DECLARE changed_id uuid;
DECLARE changed_status text;
DECLARE changed_at timestamptz;
BEGIN
 IF private.current_tenant_id() IS DISTINCT FROM p_tenant_id THEN
  RAISE EXCEPTION 'Tenant context mismatch' USING ERRCODE='42501';
 END IF;
 IF p_reason IS NULL OR length(btrim(p_reason)) NOT BETWEEN 3 AND 1000 THEN
  RAISE EXCEPTION 'A valid withdrawal reason is required' USING ERRCODE='22023';
 END IF;
 actor_id:=private.current_user_id();
 IF actor_id IS NULL THEN
  RAISE EXCEPTION 'Authenticated tenant member required' USING ERRCODE='42501';
 END IF;
 UPDATE public.privacy_requests
 SET status='withdrawn',updated_at=clock_timestamp()
 WHERE id=p_request_id
   AND tenant_id=p_tenant_id
   AND subject_user_id=actor_id
   AND status IN ('requested','identity_verification','under_review')
 RETURNING id,status,updated_at INTO changed_id,changed_status,changed_at;
 IF NOT FOUND THEN RETURN; END IF;

 INSERT INTO public.audit_events(
  tenant_id,actor_user_id,action,object_type,object_id,reason,metadata
 ) VALUES (
  p_tenant_id,actor_id,'privacy_request_withdrawn','privacy_request',
  changed_id,btrim(p_reason),'{}'::jsonb
 );

 request_id:=changed_id;
 request_status:=changed_status;
 request_updated_at:=changed_at;
 RETURN NEXT;
END
$function$;
ALTER FUNCTION private.withdraw_privacy_request(uuid,uuid,text) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.withdraw_privacy_request(uuid,uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.withdraw_privacy_request(uuid,uuid,text) TO profitpilot_app;

COMMIT;

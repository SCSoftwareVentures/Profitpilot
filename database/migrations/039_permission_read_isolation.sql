-- Prevent direct runtime reads of other members' permission overrides and reasons.
BEGIN;
REVOKE SELECT ON public.tenant_membership_permission_overrides FROM PUBLIC,profitpilot_app;
-- This function evaluates only the authenticated actor and signed tenant context.
GRANT EXECUTE ON FUNCTION private.has_scoped_permission(uuid,text) TO profitpilot_app;

CREATE FUNCTION private.read_permission_overrides(p_tenant uuid,p_auth_time bigint,p_proof text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
DECLARE actor uuid; items jsonb;
BEGIN
 actor:=private.assert_privacy_step_up(p_tenant,p_tenant,'read_permission_overrides',p_auth_time,p_proof);
 IF private.has_scoped_permission(p_tenant,'security.permissions.read') IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'Permission administration read denied' USING ERRCODE='42501';
 END IF;
 SELECT COALESCE(jsonb_agg(to_jsonb(q) ORDER BY q.user_id,q.permission_key),'[]'::jsonb)
 INTO items FROM (
  SELECT user_id,permission_key,effect,reason,granted_by,created_at
  FROM public.tenant_membership_permission_overrides WHERE tenant_id=p_tenant
  ORDER BY user_id,permission_key LIMIT 501
 ) q;
 RETURN jsonb_build_object('overrides',CASE WHEN jsonb_array_length(items)>500 THEN items-500 ELSE items END,
  'overridesTruncated',jsonb_array_length(items)>500);
END
$fn$;
ALTER FUNCTION private.read_permission_overrides(uuid,bigint,text) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.read_permission_overrides(uuid,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.read_permission_overrides(uuid,bigint,text) TO profitpilot_app;
COMMIT;

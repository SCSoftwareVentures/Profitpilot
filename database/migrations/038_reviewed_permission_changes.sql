-- Require the same verified MFA evidence for permission mutations at the SQL boundary.
BEGIN;
CREATE FUNCTION private.apply_reviewed_permission_override(p_tenant uuid,p_target uuid,p_body text,p_auth_time bigint,p_proof text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
DECLARE actor uuid; data jsonb; mode text; perm text; purpose text; removed boolean;
BEGIN
 IF p_body IS NULL OR octet_length(p_body)>8192 THEN RAISE EXCEPTION 'Invalid permission evidence' USING ERRCODE='22023'; END IF;
 actor:=private.assert_privacy_step_up(p_tenant,p_target,'permission_override:'||encode(public.digest(convert_to(p_body,'UTF8'),'sha256'),'hex'),p_auth_time,p_proof);
 IF private.has_scoped_permission(p_tenant,'security.permissions.manage') IS DISTINCT FROM true THEN RAISE EXCEPTION 'Permission administration denied' USING ERRCODE='42501'; END IF;
 data:=p_body::jsonb;mode:=data->>'effect';perm:=data->>'permissionKey';purpose:=btrim(data->>'reason');
 IF mode IS NULL OR mode NOT IN ('grant','deny','remove') OR perm IS NULL OR length(perm) NOT BETWEEN 1 AND 128
 OR perm LIKE 'security.%' OR perm LIKE 'privacy.%' OR purpose IS NULL OR length(purpose) NOT BETWEEN 3 AND 1000
 THEN RETURN jsonb_build_object('status',400,'error','Invalid override details'); END IF;
 IF mode='remove' THEN
  removed:=private.remove_member_permission_override(p_tenant,actor,p_target,perm);
  IF NOT removed THEN RETURN jsonb_build_object('status',404,'error','Permission override not found'); END IF;
  INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata)
  VALUES(p_tenant,actor,'member_permission_override_removed','tenant_membership_permission_override',p_target,purpose,jsonb_build_object('permissionKey',perm));
  RETURN jsonb_build_object('status',200);
 END IF;
 IF NOT EXISTS(SELECT 1 FROM public.tenant_memberships m JOIN public.users u ON u.id=m.user_id WHERE m.tenant_id=p_tenant AND m.user_id=p_target AND m.status='active' AND u.status='active')
 THEN RETURN jsonb_build_object('status',404,'error','Active tenant member not found'); END IF;
 IF NOT EXISTS(SELECT 1 FROM public.permission_catalog pc WHERE pc.permission_key=perm) THEN RETURN jsonb_build_object('status',400,'error','Unknown permission'); END IF;
 PERFORM private.set_member_permission_override(p_tenant,actor,p_target,perm,mode,purpose);
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata)
 VALUES(p_tenant,actor,'member_permission_override_set','tenant_membership_permission_override',p_target,purpose,jsonb_build_object('permissionKey',perm,'effect',mode));
 RETURN jsonb_build_object('status',201,'override',jsonb_build_object('userId',p_target,'permissionKey',perm,'effect',mode,'reason',purpose));
END
$fn$;
ALTER FUNCTION private.apply_reviewed_permission_override(uuid,uuid,text,bigint,text) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.apply_reviewed_permission_override(uuid,uuid,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.apply_reviewed_permission_override(uuid,uuid,text,bigint,text) TO profitpilot_app;
REVOKE EXECUTE ON FUNCTION private.set_member_permission_override(uuid,uuid,uuid,text,text,text),private.remove_member_permission_override(uuid,uuid,uuid,text) FROM PUBLIC,profitpilot_app;
COMMIT;

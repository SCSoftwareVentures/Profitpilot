-- Shared authenticated-actor burst detection with bounded automatic containment.
-- The API must commit this check before serving the tenant request.
BEGIN;
CREATE TABLE private.actor_request_security(
 tenant_id uuid NOT NULL,
 actor_id uuid NOT NULL,
 window_start timestamptz NOT NULL,
 used integer NOT NULL CHECK(used BETWEEN 0 AND 120),
 blocked_until timestamptz,
 PRIMARY KEY(tenant_id,actor_id),
 FOREIGN KEY(tenant_id,actor_id) REFERENCES public.tenant_memberships(tenant_id,user_id) ON DELETE CASCADE
);
REVOKE ALL ON private.actor_request_security FROM PUBLIC,profitpilot_app;

CREATE FUNCTION private.admit_actor_request(p_tenant uuid)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE actor uuid; state private.actor_request_security%ROWTYPE; now_at timestamptz;
BEGIN
 IF p_tenant IS NULL OR private.current_tenant_id() IS DISTINCT FROM p_tenant THEN
  RAISE EXCEPTION 'Actor request authority denied' USING ERRCODE='42501';
 END IF;
 SELECT u.id INTO actor FROM public.users u
 JOIN public.tenant_memberships m ON m.user_id=u.id JOIN public.tenants t ON t.id=m.tenant_id
 WHERE u.auth_subject=nullif(current_setting('app.tenant_subject',true),'')
 AND m.tenant_id=p_tenant AND m.status='active' AND u.status='active' AND t.status='active'
 FOR SHARE OF u,m,t;
 IF NOT FOUND THEN RAISE EXCEPTION 'Actor request authority denied' USING ERRCODE='42501'; END IF;
 INSERT INTO private.actor_request_security(tenant_id,actor_id,window_start,used)
 VALUES(p_tenant,actor,clock_timestamp(),0) ON CONFLICT(tenant_id,actor_id) DO NOTHING;
 SELECT * INTO STRICT state FROM private.actor_request_security
 WHERE tenant_id=p_tenant AND actor_id=actor FOR UPDATE;
 now_at:=clock_timestamp();
 IF state.blocked_until>now_at THEN
  RETURN greatest(1,ceil(extract(epoch FROM state.blocked_until-now_at))::integer);
 END IF;
 IF state.blocked_until IS NOT NULL OR state.window_start<=now_at-interval '1 minute' THEN
  UPDATE private.actor_request_security SET window_start=now_at,used=1,blocked_until=NULL
  WHERE tenant_id=p_tenant AND actor_id=actor;
  RETURN 0;
 END IF;
 IF state.used>=120 THEN
  UPDATE private.actor_request_security SET blocked_until=now_at+interval '5 minutes'
  WHERE tenant_id=p_tenant AND actor_id=actor;
  INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,metadata)
  VALUES(p_tenant,actor,'actor_burst_containment','security_control',jsonb_build_object('rule','actor_request_burst_v1','windowSeconds',60,'threshold',120,'containmentSeconds',300));
  RETURN 300;
 END IF;
 UPDATE private.actor_request_security SET used=used+1 WHERE tenant_id=p_tenant AND actor_id=actor;
 RETURN 0;
END $fn$;
REVOKE ALL ON FUNCTION private.admit_actor_request(uuid) FROM PUBLIC,profitpilot_app;
GRANT EXECUTE ON FUNCTION private.admit_actor_request(uuid) TO profitpilot_app;
COMMIT;

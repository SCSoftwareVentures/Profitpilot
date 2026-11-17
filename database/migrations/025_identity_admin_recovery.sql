-- Human-approved identity administration; no runtime or self-service grants.
BEGIN;
DO $role$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='profitpilot_identity_operator') THEN
  CREATE ROLE profitpilot_identity_operator NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
 END IF;
END $role$;
GRANT USAGE ON SCHEMA private TO profitpilot_identity_operator;
CREATE TABLE private.identity_admin_events(
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 tenant_id uuid REFERENCES public.tenants(id),
 user_id uuid NOT NULL REFERENCES public.users(id),
 action text NOT NULL CHECK(action IN ('provision','membership_grant','membership_change','membership_revoke','recovery_replay')),
 role_value text CHECK(role_value IN ('owner','admin','analyst','reviewer','read_only')),
 authority_ref text NOT NULL CHECK(authority_ref ~ '^[A-Za-z][A-Za-z0-9_-]{2,63}$'),
 operator_name text NOT NULL DEFAULT session_user,
 occurred_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON private.identity_admin_events FROM PUBLIC,profitpilot_app,profitpilot_identity_operator;
CREATE TRIGGER identity_admin_event_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON private.identity_admin_events
 FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();
CREATE TRIGGER identity_security_event_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON private.identity_security_events
 FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();

CREATE FUNCTION private.provision_verified_identity(p_subject text,p_email text,p_ref text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE uid uuid;
BEGIN
 IF p_subject IS NULL OR char_length(p_subject) NOT BETWEEN 1 AND 255 OR p_subject ~ '[[:cntrl:]]'
 OR p_email IS NULL OR char_length(p_email) NOT BETWEEN 3 AND 254 OR p_email !~ '^[^[:space:]@]+@[^[:space:]@]+$'
 OR p_ref IS NULL OR p_ref !~ '^[A-Za-z][A-Za-z0-9_-]{2,63}$' THEN
  RAISE EXCEPTION 'Invalid verified identity or approval reference' USING ERRCODE='22023';
 END IF;
 INSERT INTO public.users(auth_subject,email,status) VALUES(p_subject,p_email,'active') RETURNING id INTO uid;
 INSERT INTO private.identity_admin_events(user_id,action,authority_ref) VALUES(uid,'provision',p_ref);
 RETURN uid;
END $fn$;

CREATE FUNCTION private.administer_membership(p_tenant uuid,p_user uuid,p_role text,p_action text,p_ref text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE existing public.tenant_memberships%ROWTYPE; event_action text;
BEGIN
 IF p_tenant IS NULL OR p_user IS NULL OR p_ref IS NULL OR p_ref !~ '^[A-Za-z][A-Za-z0-9_-]{2,63}$'
 OR p_action IS NULL OR p_action NOT IN ('grant','revoke')
 OR (p_action='grant' AND (p_role IS NULL OR p_role NOT IN ('owner','admin','analyst','reviewer','read_only')))
 OR (p_action='revoke' AND p_role IS NOT NULL) THEN RAISE EXCEPTION 'Invalid membership action' USING ERRCODE='22023'; END IF;
 -- Serialize grants, downgrades, and removals for this tenant.
 PERFORM 1 FROM public.tenants WHERE id=p_tenant AND status='active' FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Active tenant not found'; END IF;
 PERFORM 1 FROM public.users WHERE id=p_user AND (status='active' OR p_action='revoke') FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Eligible identity not found'; END IF;
 SELECT * INTO existing FROM public.tenant_memberships WHERE tenant_id=p_tenant AND user_id=p_user FOR UPDATE;
 IF p_action='revoke' AND (NOT FOUND OR existing.status<>'active') THEN RAISE EXCEPTION 'Active membership not found'; END IF;
 IF p_action='grant' AND existing.status='active' AND existing.role=p_role THEN RAISE EXCEPTION 'Membership already active'; END IF;
 IF existing.status='active' AND existing.role='owner' AND (p_action='revoke' OR p_role<>'owner')
 AND NOT EXISTS(SELECT 1 FROM public.tenant_memberships m JOIN public.users u ON u.id=m.user_id
  WHERE m.tenant_id=p_tenant AND m.user_id<>p_user AND m.role='owner' AND m.status='active' AND u.status='active')
 THEN RAISE EXCEPTION 'Cannot remove or downgrade the last active owner'; END IF;
 IF p_action='grant' THEN
  event_action:=CASE WHEN existing.user_id IS NULL THEN 'membership_grant' ELSE 'membership_change' END;
  INSERT INTO public.tenant_memberships(tenant_id,user_id,role,status) VALUES(p_tenant,p_user,p_role,'active')
  ON CONFLICT(tenant_id,user_id) DO UPDATE SET role=EXCLUDED.role,status='active',granted_at=clock_timestamp();
 ELSE
  event_action:='membership_revoke';
  UPDATE public.tenant_memberships SET status='revoked' WHERE tenant_id=p_tenant AND user_id=p_user;
 END IF;
 -- Any grant, downgrade or regrant requires fresh provider authentication.
 PERFORM private.revoke_identity_access(p_user,'revoke_all',p_ref,NULL);
 INSERT INTO private.identity_admin_events(tenant_id,user_id,action,role_value,authority_ref)
 VALUES(p_tenant,p_user,event_action,CASE WHEN p_action='grant' THEN p_role ELSE existing.role END,p_ref);
END $fn$;

-- Recovery receives authenticated, externally reconciled revocation evidence.
-- Never re-enables an account or decreases a cutoff.
CREATE FUNCTION private.replay_identity_revocation(p_user uuid,p_subject text,p_cutoff bigint,p_digest text,p_disable boolean,p_ref text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
BEGIN
 IF p_ref IS NULL OR p_ref !~ '^[A-Za-z][A-Za-z0-9_-]{2,63}$' OR p_disable IS NULL
 OR (p_cutoff IS NULL AND p_digest IS NULL AND NOT p_disable)
 OR (p_cutoff IS NOT NULL AND (p_cutoff<0 OR p_cutoff>floor(extract(epoch FROM clock_timestamp()))::bigint))
 OR (p_digest IS NOT NULL AND p_digest !~ '^[a-f0-9]{64}$') THEN RAISE EXCEPTION 'Invalid recovery revocation evidence'; END IF;
 PERFORM 1 FROM public.users WHERE id=p_user AND auth_subject=p_subject FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Recovered identity does not match authoritative record'; END IF;
 IF p_cutoff IS NOT NULL THEN
  INSERT INTO private.identity_session_cutoffs(user_id,revoked_through) VALUES(p_user,p_cutoff)
  ON CONFLICT(user_id) DO UPDATE SET revoked_through=greatest(private.identity_session_cutoffs.revoked_through,EXCLUDED.revoked_through);
 END IF;
 IF p_digest IS NOT NULL THEN INSERT INTO private.revoked_identity_sessions(user_id,session_digest) VALUES(p_user,p_digest) ON CONFLICT DO NOTHING; END IF;
 IF p_disable THEN UPDATE public.users SET status='disabled' WHERE id=p_user AND status<>'disabled'; END IF;
 INSERT INTO private.identity_admin_events(user_id,action,authority_ref) VALUES(p_user,'recovery_replay',p_ref);
END $fn$;

REVOKE ALL ON FUNCTION private.provision_verified_identity(text,text,text),private.administer_membership(uuid,uuid,text,text,text),private.replay_identity_revocation(uuid,text,bigint,text,boolean,text) FROM PUBLIC,profitpilot_app;
GRANT EXECUTE ON FUNCTION private.provision_verified_identity(text,text,text),private.administer_membership(uuid,uuid,text,text,text) TO profitpilot_identity_operator;
-- Recovery replay stays administrator-only. The identity operator cannot bypass
-- the normal action path or directly read/change identity tables.
COMMIT;

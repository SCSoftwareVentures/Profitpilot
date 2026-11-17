-- Dedicated independent operators provision and revoke access; no public self-enrolment.
BEGIN;
DO $fn$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='profitpilot_access_proposer') THEN
  CREATE ROLE profitpilot_access_proposer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='profitpilot_access_approver') THEN
  CREATE ROLE profitpilot_access_approver NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
 END IF;
END
$fn$;
GRANT USAGE ON SCHEMA private TO profitpilot_access_proposer,profitpilot_access_approver;
GRANT INSERT(id,legal_name),UPDATE(status) ON public.tenants TO profitpilot_context_owner;
GRANT INSERT(id,auth_subject,auth_issuer,email,status) ON public.users TO profitpilot_context_owner;
GRANT INSERT(tenant_id,user_id,role,status),UPDATE(role,status) ON public.tenant_memberships TO profitpilot_context_owner;
CREATE TABLE private.access_change_intents(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 action text NOT NULL CHECK(action IN ('create_tenant','grant','role','revoke')),
 body_digest text NOT NULL CHECK(body_digest ~ '^[a-f0-9]{64}$'),
 proposed_by name NOT NULL,
 proposal_evidence text NOT NULL CHECK(proposal_evidence ~ '^[a-f0-9]{64}$'),
 proposed_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 applied_at timestamptz,
 applied_by name,
 approval_evidence text CHECK(approval_evidence ~ '^[a-f0-9]{64}$'),
 tenant_id uuid REFERENCES public.tenants(id),
 user_id uuid REFERENCES public.users(id),
 membership_role text CHECK(membership_role IN ('owner','admin','analyst','reviewer','read_only')),
 membership_status text CHECK(membership_status IN ('active','revoked')),
 CHECK(expires_at>proposed_at),
 CHECK((applied_at IS NULL AND applied_by IS NULL AND approval_evidence IS NULL AND tenant_id IS NULL AND user_id IS NULL AND membership_role IS NULL AND membership_status IS NULL)
 OR (applied_at IS NOT NULL AND applied_by IS NOT NULL AND applied_by<>proposed_by AND approval_evidence IS NOT NULL AND approval_evidence<>proposal_evidence
 AND applied_at>=proposed_at AND applied_at<=expires_at AND tenant_id IS NOT NULL AND user_id IS NOT NULL AND membership_role IS NOT NULL AND membership_status IS NOT NULL))
);
ALTER TABLE private.access_change_intents OWNER TO profitpilot_context_owner;
REVOKE ALL ON private.access_change_intents FROM PUBLIC,profitpilot_app,profitpilot_access_proposer,profitpilot_access_approver;

CREATE FUNCTION private.guard_access_change_intent() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Access change receipt is retained' USING ERRCODE='55000'; END IF;
 IF OLD.applied_at IS NOT NULL OR NEW.applied_at IS NULL OR
 ROW(NEW.id,NEW.action,NEW.body_digest,NEW.proposed_by,NEW.proposal_evidence,NEW.proposed_at,NEW.expires_at) IS DISTINCT FROM
 ROW(OLD.id,OLD.action,OLD.body_digest,OLD.proposed_by,OLD.proposal_evidence,OLD.proposed_at,OLD.expires_at)
 THEN RAISE EXCEPTION 'Access change receipt is immutable except approved execution' USING ERRCODE='55000'; END IF;
 RETURN NEW;
END
$fn$;
ALTER FUNCTION private.guard_access_change_intent() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.guard_access_change_intent() FROM PUBLIC,profitpilot_app;
CREATE TRIGGER access_change_intent_guard BEFORE UPDATE OR DELETE ON private.access_change_intents FOR EACH ROW EXECUTE FUNCTION private.guard_access_change_intent();
CREATE TRIGGER access_change_intent_no_truncate BEFORE TRUNCATE ON private.access_change_intents FOR EACH STATEMENT EXECUTE FUNCTION private.guard_security_restore_anchor();

CREATE FUNCTION private.prepare_access_change(p_body text,p_evidence text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
DECLARE data jsonb; action_value text; event_id uuid; at_time timestamptz;
BEGIN
 IF NOT pg_has_role(session_user,'profitpilot_access_proposer','MEMBER') OR pg_has_role(session_user,'profitpilot_access_approver','MEMBER')
 OR pg_has_role(session_user,'profitpilot_incident_recovery','MEMBER') OR pg_has_role(session_user,'profitpilot_incident_containment','MEMBER')
 OR NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=session_user AND rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole)
 THEN RAISE EXCEPTION 'Dedicated proposer required' USING ERRCODE='42501'; END IF;
 IF p_body IS NULL OR octet_length(p_body)>8192 OR p_evidence IS NULL OR p_evidence !~ '^[a-f0-9]{64}$'
 THEN RAISE EXCEPTION 'Bounded access change and authority digest required' USING ERRCODE='22023'; END IF;
 data:=p_body::jsonb;action_value:=data->>'action';
 IF jsonb_typeof(data) IS DISTINCT FROM 'object' OR action_value IS NULL OR action_value NOT IN ('create_tenant','grant','role','revoke')
 THEN RAISE EXCEPTION 'Invalid access change action' USING ERRCODE='22023'; END IF;
 at_time:=clock_timestamp();
 INSERT INTO private.access_change_intents(action,body_digest,proposed_by,proposal_evidence,proposed_at,expires_at)
 VALUES(action_value,encode(public.digest(convert_to(p_body,'UTF8'),'sha256'),'hex'),session_user,p_evidence,at_time,at_time+interval '15 minutes')
 RETURNING id INTO event_id;
 RETURN event_id;
END
$fn$;
ALTER FUNCTION private.prepare_access_change(text,text) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.prepare_access_change(text,text) FROM PUBLIC,profitpilot_app,profitpilot_access_approver;
GRANT EXECUTE ON FUNCTION private.prepare_access_change(text,text) TO profitpilot_access_proposer;

CREATE FUNCTION private.execute_access_change(p_id uuid,p_body text,p_evidence text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
DECLARE intent private.access_change_intents%ROWTYPE; data jsonb; action_value text; target_tenant uuid; target_user uuid; role_value text; status_value text; subject_value text; issuer_value text; email_value text; name_value text; account public.users%ROWTYPE; member public.tenant_memberships%ROWTYPE; at_time timestamptz; allowed_keys text[]; account_exists boolean;
BEGIN
 IF NOT pg_has_role(session_user,'profitpilot_access_approver','MEMBER') OR pg_has_role(session_user,'profitpilot_access_proposer','MEMBER')
 OR pg_has_role(session_user,'profitpilot_incident_recovery','MEMBER') OR pg_has_role(session_user,'profitpilot_incident_containment','MEMBER')
 OR NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=session_user AND rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole)
 THEN RAISE EXCEPTION 'Independent access approver required' USING ERRCODE='42501'; END IF;
 IF p_body IS NULL OR octet_length(p_body)>8192 OR p_evidence IS NULL OR p_evidence !~ '^[a-f0-9]{64}$'
 THEN RAISE EXCEPTION 'Exact approved access evidence required' USING ERRCODE='22023'; END IF;
 SELECT * INTO intent FROM private.access_change_intents WHERE id=p_id FOR UPDATE;
 IF NOT FOUND OR intent.applied_at IS NOT NULL OR intent.expires_at<=clock_timestamp() OR intent.proposed_by=session_user
 OR intent.proposal_evidence=p_evidence OR intent.body_digest IS DISTINCT FROM encode(public.digest(convert_to(p_body,'UTF8'),'sha256'),'hex')
 THEN RAISE EXCEPTION 'Invalid, expired, consumed or changed access intent' USING ERRCODE='42501'; END IF;
 data:=p_body::jsonb;action_value:=data->>'action';target_tenant:=(data->>'tenantId')::uuid;target_user:=(data->>'userId')::uuid;
 role_value:=data->>'role';subject_value:=data->>'subject';issuer_value:=data->>'issuer';email_value:=data->>'email';name_value:=data->>'tenantName';
 IF target_tenant IS NULL OR target_user IS NULL OR action_value IS DISTINCT FROM intent.action THEN RAISE EXCEPTION 'Exact tenant, account and action required' USING ERRCODE='22023'; END IF;
 allowed_keys:=CASE action_value WHEN 'create_tenant' THEN ARRAY['action','tenantId','userId','tenantName','role','subject','issuer','email']
 WHEN 'grant' THEN ARRAY['action','tenantId','userId','role','subject','issuer','email']
 WHEN 'role' THEN ARRAY['action','tenantId','userId','role'] ELSE ARRAY['action','tenantId','userId'] END;
 IF EXISTS(SELECT 1 FROM jsonb_object_keys(data) k(key) WHERE NOT k.key=ANY(allowed_keys)) THEN RAISE EXCEPTION 'Unrecognised access change field' USING ERRCODE='22023'; END IF;
 IF action_value<>'revoke' AND (role_value IS NULL OR role_value NOT IN ('owner','admin','analyst','reviewer','read_only')) THEN RAISE EXCEPTION 'Valid role required' USING ERRCODE='22023'; END IF;
 IF action_value='create_tenant' THEN
  IF role_value<>'owner' OR name_value IS NULL OR length(btrim(name_value)) NOT BETWEEN 1 AND 200 OR name_value ~ '[[:cntrl:]]'
  THEN RAISE EXCEPTION 'New tenant needs an explicit initial owner' USING ERRCODE='22023'; END IF;
  INSERT INTO public.tenants(id,legal_name) VALUES(target_tenant,btrim(name_value));
 ELSE
  PERFORM 1 FROM public.tenants WHERE id=target_tenant AND status='active' FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Active tenant required' USING ERRCODE='55000'; END IF;
 END IF;
 SELECT * INTO account FROM public.users WHERE id=target_user FOR UPDATE;
 account_exists:=FOUND;
 IF action_value IN ('create_tenant','grant') THEN
  IF subject_value IS NULL OR length(subject_value) NOT BETWEEN 1 AND 512 OR btrim(subject_value)<>subject_value OR subject_value ~ '[[:cntrl:]]'
  OR issuer_value IS NULL OR issuer_value !~ '^https://[^[:space:]?#@]+$' OR length(issuer_value)>512
  OR email_value IS NULL OR length(email_value) NOT BETWEEN 3 AND 254 OR email_value !~ '^[^[:space:]@]+@[^[:space:]@]+$'
  THEN RAISE EXCEPTION 'Verified provider identity fields required' USING ERRCODE='22023'; END IF;
  IF NOT account_exists THEN
   INSERT INTO public.users(id,auth_subject,auth_issuer,email,status) VALUES(target_user,subject_value,issuer_value,email_value,'active');
  ELSIF account.status<>'active' OR account.auth_subject IS DISTINCT FROM subject_value OR account.auth_issuer IS DISTINCT FROM issuer_value OR account.email IS DISTINCT FROM email_value THEN
   RAISE EXCEPTION 'Existing account binding differs or is unavailable' USING ERRCODE='42501';
  END IF;
 ELSE
  IF NOT account_exists OR account.status<>'active' OR account.auth_issuer IS NULL THEN RAISE EXCEPTION 'Active bound account required' USING ERRCODE='55000'; END IF;
 END IF;
 IF EXISTS(SELECT 1 FROM private.account_closures c WHERE c.user_id=target_user) OR EXISTS(SELECT 1 FROM private.account_security_incidents i WHERE i.user_id=target_user AND i.recovered_at IS NULL)
 THEN RAISE EXCEPTION 'Closed or contained identity cannot be provisioned' USING ERRCODE='42501'; END IF;
 SELECT * INTO member FROM public.tenant_memberships WHERE tenant_id=target_tenant AND user_id=target_user FOR UPDATE;
 IF action_value IN ('create_tenant','grant') THEN
  IF FOUND AND member.status='active' THEN RAISE EXCEPTION 'Active membership already exists' USING ERRCODE='55000'; END IF;
  INSERT INTO public.tenant_memberships(tenant_id,user_id,role,status) VALUES(target_tenant,target_user,role_value,'active')
  ON CONFLICT(tenant_id,user_id) DO UPDATE SET role=EXCLUDED.role,status='active';
  status_value:='active';
 ELSE
  IF NOT FOUND OR member.status<>'active' THEN RAISE EXCEPTION 'Active membership required' USING ERRCODE='55000'; END IF;
  IF member.role='owner' AND (action_value='revoke' OR role_value<>'owner') AND NOT EXISTS(
   SELECT 1 FROM public.tenant_memberships m JOIN public.users u ON u.id=m.user_id
    WHERE m.tenant_id=target_tenant AND m.user_id<>target_user AND m.role='owner' AND m.status='active' AND u.status='active')
  THEN RAISE EXCEPTION 'Cannot remove last active owner' USING ERRCODE='55000'; END IF;
  IF action_value='revoke' THEN role_value:=member.role;status_value:='revoked'; ELSE status_value:='active'; END IF;
  UPDATE public.tenant_memberships SET role=role_value,status=status_value WHERE tenant_id=target_tenant AND user_id=target_user;
 END IF;
 -- Clear inherited personal overrides so a role change cannot silently retain old entitlements.
 DELETE FROM public.tenant_membership_permission_overrides WHERE tenant_id=target_tenant AND user_id=target_user;
 at_time:=clock_timestamp();
 IF at_time>intent.expires_at THEN RAISE EXCEPTION 'Access intent expired during execution' USING ERRCODE='42501'; END IF;
 UPDATE private.access_change_intents SET applied_at=at_time,applied_by=session_user,approval_evidence=p_evidence,
 tenant_id=target_tenant,user_id=target_user,membership_role=role_value,membership_status=status_value WHERE id=p_id;
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata)
 VALUES(target_tenant,NULL,'operator_access_changed','tenant_membership',target_user,'Independent access change approved',
 jsonb_build_object('intentId',p_id,'action',action_value,'role',role_value,'status',status_value,'bodyDigest',intent.body_digest,'approvalEvidence',p_evidence));
 RETURN jsonb_build_object('intentId',p_id,'tenantId',target_tenant,'userId',target_user,'role',role_value,'status',status_value);
END
$fn$;
ALTER FUNCTION private.execute_access_change(uuid,text,text) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.execute_access_change(uuid,text,text) FROM PUBLIC,profitpilot_app,profitpilot_access_proposer;
GRANT EXECUTE ON FUNCTION private.execute_access_change(uuid,text,text) TO profitpilot_access_approver;

ALTER FUNCTION private.privacy_restore_state() RENAME TO privacy_restore_state_before_access_changes;
CREATE FUNCTION private.privacy_restore_state() RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
 SELECT jsonb_build_object('markers',s.state->'markers'||COALESCE((
  SELECT jsonb_agg(jsonb_build_object('kind','access_change_applied','id',i.id,'tenantId',i.tenant_id,'userId',i.user_id,'at',extract(epoch FROM i.applied_at)::text,
   'evidence',encode(public.digest(convert_to(i.body_digest||':'||i.proposal_evidence||':'||i.approval_evidence,'UTF8'),'sha256'),'hex'),
   'role',i.membership_role,'status',i.membership_status) ORDER BY i.id)
  FROM private.access_change_intents i WHERE i.applied_at IS NOT NULL),'[]'::jsonb),
  'violations',s.state->'violations'||COALESCE((
   SELECT jsonb_agg(x.item ORDER BY x.item->>'id') FROM (
    SELECT jsonb_build_object('kind','access_change_audit_missing','id',i.id) AS item FROM private.access_change_intents i WHERE i.applied_at IS NOT NULL
    AND NOT EXISTS(SELECT 1 FROM public.audit_events a WHERE a.tenant_id=i.tenant_id AND a.object_id=i.user_id AND a.action='operator_access_changed' AND a.metadata->>'intentId'=i.id::text AND a.metadata->>'bodyDigest'=i.body_digest)
    UNION ALL
    SELECT jsonb_build_object('kind','access_membership_state_mismatch','id',r.id)
    FROM (SELECT DISTINCT ON (tenant_id,user_id) * FROM private.access_change_intents WHERE applied_at IS NOT NULL ORDER BY tenant_id,user_id,applied_at DESC,id DESC) r
    LEFT JOIN public.tenant_memberships m ON m.tenant_id=r.tenant_id AND m.user_id=r.user_id
    LEFT JOIN private.account_closures c ON c.user_id=r.user_id
    WHERE m.role IS DISTINCT FROM r.membership_role OR m.status IS DISTINCT FROM CASE WHEN c.user_id IS NOT NULL THEN 'revoked' ELSE r.membership_status END
   ) x),'[]'::jsonb))
 FROM (SELECT private.privacy_restore_state_before_access_changes() AS state) s
$fn$;
ALTER FUNCTION private.privacy_restore_state() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.privacy_restore_state(),private.privacy_restore_state_before_access_changes() FROM PUBLIC,profitpilot_app;
COMMIT;

-- Global compromise containment and independently authorised local recovery.
-- Dedicated operator groups have no members by default; provision separately.
BEGIN;
DO $fn$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='profitpilot_incident_containment') THEN
  CREATE ROLE profitpilot_incident_containment NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='profitpilot_incident_recovery') THEN
  CREATE ROLE profitpilot_incident_recovery NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
 END IF;
END
$fn$;
GRANT USAGE ON SCHEMA private TO profitpilot_incident_containment,profitpilot_incident_recovery;
CREATE TABLE private.account_security_incidents (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
 contained_at timestamptz NOT NULL,
 contained_by name NOT NULL,
 containment_evidence text NOT NULL CHECK(containment_evidence ~ '^[a-f0-9]{64}$'),
 recovered_at timestamptz,
 recovered_by name,
 identity_evidence text CHECK(identity_evidence ~ '^[a-f0-9]{64}$'),
 provider_revocation_evidence text CHECK(provider_revocation_evidence ~ '^[a-f0-9]{64}$'),
 CHECK((recovered_at IS NULL AND recovered_by IS NULL AND identity_evidence IS NULL AND provider_revocation_evidence IS NULL)
 OR (recovered_at IS NOT NULL AND recovered_by IS NOT NULL AND identity_evidence IS NOT NULL AND provider_revocation_evidence IS NOT NULL
 AND recovered_by<>contained_by AND recovered_at>=contained_at AND identity_evidence<>provider_revocation_evidence
 AND containment_evidence<>identity_evidence AND containment_evidence<>provider_revocation_evidence))
);
ALTER TABLE private.account_security_incidents OWNER TO profitpilot_context_owner;
REVOKE ALL ON private.account_security_incidents FROM PUBLIC,profitpilot_app,profitpilot_incident_containment,profitpilot_incident_recovery;
CREATE UNIQUE INDEX one_open_account_security_incident ON private.account_security_incidents(user_id) WHERE recovered_at IS NULL;
CREATE FUNCTION private.guard_account_security_incident() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Account security incident evidence must be retained' USING ERRCODE='55000'; END IF;
 IF OLD.recovered_at IS NOT NULL OR NEW.recovered_at IS NULL
 OR ROW(OLD.id,OLD.user_id,OLD.contained_at,OLD.contained_by,OLD.containment_evidence) IS DISTINCT FROM ROW(NEW.id,NEW.user_id,NEW.contained_at,NEW.contained_by,NEW.containment_evidence)
 THEN RAISE EXCEPTION 'Account security incident evidence is immutable except recovery' USING ERRCODE='55000'; END IF;
 RETURN NEW;
END
$fn$;
ALTER FUNCTION private.guard_account_security_incident() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.guard_account_security_incident() FROM PUBLIC,profitpilot_app;
CREATE TRIGGER account_security_incident_guard BEFORE UPDATE OR DELETE ON private.account_security_incidents FOR EACH ROW EXECUTE FUNCTION private.guard_account_security_incident();
CREATE TRIGGER account_security_incident_truncate_guard BEFORE TRUNCATE ON private.account_security_incidents FOR EACH STATEMENT EXECUTE FUNCTION private.guard_account_session_revocation_receipt();

CREATE FUNCTION private.guard_contained_account() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
BEGIN
 IF NEW.status='active' AND EXISTS(SELECT 1 FROM private.account_security_incidents WHERE user_id=NEW.id AND recovered_at IS NULL)
 THEN RAISE EXCEPTION 'Contained account requires independent recovery' USING ERRCODE='55000'; END IF;
 RETURN NEW;
END
$fn$;
ALTER FUNCTION private.guard_contained_account() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.guard_contained_account() FROM PUBLIC,profitpilot_app;
CREATE TRIGGER contained_account_guard BEFORE UPDATE OF status ON public.users FOR EACH ROW EXECUTE FUNCTION private.guard_contained_account();

CREATE FUNCTION private.contain_compromised_account(p_user uuid,p_evidence text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
DECLARE account public.users%ROWTYPE; incident_id uuid; cutoff bigint;
BEGIN
 IF NOT pg_has_role(session_user,'profitpilot_incident_containment','MEMBER')
 OR pg_has_role(session_user,'profitpilot_incident_recovery','MEMBER')
 OR NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=session_user AND rolcanlogin AND NOT rolsuper)
 THEN RAISE EXCEPTION 'Dedicated containment operator required' USING ERRCODE='42501'; END IF;
 IF p_evidence IS NULL OR p_evidence !~ '^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'Containment evidence digest required' USING ERRCODE='22023'; END IF;
 SELECT * INTO account FROM public.users WHERE id=p_user AND status='active' AND auth_issuer IS NOT NULL FOR UPDATE;
 IF NOT FOUND OR EXISTS(SELECT 1 FROM private.account_closures WHERE user_id=p_user) THEN RAISE EXCEPTION 'Active bound account required' USING ERRCODE='55000'; END IF;
 INSERT INTO private.account_security_incidents(user_id,contained_at,contained_by,containment_evidence)
 VALUES(p_user,clock_timestamp(),session_user,p_evidence) RETURNING id INTO incident_id;
 UPDATE public.users SET status='disabled' WHERE id=p_user;
 cutoff:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 INSERT INTO private.account_session_revocations(user_id,revoked_through_epoch) VALUES(p_user,cutoff)
 ON CONFLICT(user_id) DO UPDATE SET revoked_through_epoch=GREATEST(private.account_session_revocations.revoked_through_epoch,EXCLUDED.revoked_through_epoch);
 UPDATE private.auth_sessions SET revoked_at=clock_timestamp(),revocation_reason='account_compromise_containment'
 WHERE subject=account.auth_subject AND revoked_at IS NULL;
 RETURN incident_id;
END
$fn$;
ALTER FUNCTION private.contain_compromised_account(uuid,text) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.contain_compromised_account(uuid,text) FROM PUBLIC,profitpilot_app,profitpilot_incident_recovery;
GRANT EXECUTE ON FUNCTION private.contain_compromised_account(uuid,text) TO profitpilot_incident_containment;

CREATE FUNCTION private.recover_contained_account(p_incident uuid,p_identity_evidence text,p_provider_evidence text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
DECLARE incident private.account_security_incidents%ROWTYPE; account public.users%ROWTYPE; target uuid; cutoff bigint; recovered_time timestamptz;
BEGIN
 IF NOT pg_has_role(session_user,'profitpilot_incident_recovery','MEMBER')
 OR pg_has_role(session_user,'profitpilot_incident_containment','MEMBER')
 OR NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=session_user AND rolcanlogin AND NOT rolsuper)
 THEN RAISE EXCEPTION 'Dedicated independent recovery operator required' USING ERRCODE='42501'; END IF;
 IF p_identity_evidence IS NULL OR p_provider_evidence IS NULL OR p_identity_evidence !~ '^[a-f0-9]{64}$' OR p_provider_evidence !~ '^[a-f0-9]{64}$' OR p_identity_evidence=p_provider_evidence
 THEN RAISE EXCEPTION 'Separate identity and provider revocation evidence digests required' USING ERRCODE='22023'; END IF;
 SELECT user_id INTO target FROM private.account_security_incidents WHERE id=p_incident;
 SELECT * INTO account FROM public.users WHERE id=target AND status='disabled' FOR UPDATE;
 IF NOT FOUND OR EXISTS(SELECT 1 FROM private.account_closures WHERE user_id=target) THEN RAISE EXCEPTION 'Recoverable contained account required' USING ERRCODE='55000'; END IF;
 SELECT * INTO incident FROM private.account_security_incidents WHERE id=p_incident AND recovered_at IS NULL FOR UPDATE;
 IF NOT FOUND OR incident.contained_by=session_user OR incident.containment_evidence IN(p_identity_evidence,p_provider_evidence)
 THEN RAISE EXCEPTION 'Independent recovery with new evidence required' USING ERRCODE='42501'; END IF;
 -- No identity rebinding, password reset, membership change or external provider call.
 -- Advance the cutoff again so authentication events during containment cannot be used.
 recovered_time:=clock_timestamp();
 cutoff:=floor(extract(epoch FROM recovered_time))::bigint;
 INSERT INTO private.account_session_revocations(user_id,revoked_through_epoch) VALUES(target,cutoff)
 ON CONFLICT(user_id) DO UPDATE SET revoked_through_epoch=GREATEST(private.account_session_revocations.revoked_through_epoch,EXCLUDED.revoked_through_epoch);
 UPDATE private.auth_sessions SET revoked_at=clock_timestamp(),revocation_reason='account_compromise_recovery'
 WHERE subject=account.auth_subject AND revoked_at IS NULL;
 UPDATE private.account_security_incidents SET recovered_at=recovered_time,recovered_by=session_user,
 identity_evidence=p_identity_evidence,provider_revocation_evidence=p_provider_evidence WHERE id=p_incident;
 UPDATE public.users SET status='active' WHERE id=target;
 RETURN true;
END
$fn$;
ALTER FUNCTION private.recover_contained_account(uuid,text,text) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.recover_contained_account(uuid,text,text) FROM PUBLIC,profitpilot_app,profitpilot_incident_containment;
GRANT EXECUTE ON FUNCTION private.recover_contained_account(uuid,text,text) TO profitpilot_incident_recovery;

ALTER FUNCTION private.privacy_restore_state() RENAME TO privacy_restore_state_before_account_incidents;
CREATE FUNCTION private.privacy_restore_state() RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
 SELECT jsonb_build_object('markers',s.state->'markers'||COALESCE((
 SELECT jsonb_agg(marker ORDER BY marker->>'kind',marker->>'id') FROM (
 SELECT jsonb_build_object('kind','account_contained','id',i.id,'userId',i.user_id,'at',extract(epoch FROM i.contained_at)::text,
 'evidence',i.containment_evidence) AS marker FROM private.account_security_incidents i
 UNION ALL SELECT jsonb_build_object('kind','account_recovered','id',i.id,'userId',i.user_id,'at',extract(epoch FROM i.recovered_at)::text,
 'evidence',encode(public.digest(convert_to(i.identity_evidence||':'||i.provider_revocation_evidence,'UTF8'),'sha256'),'hex'))
 FROM private.account_security_incidents i WHERE i.recovered_at IS NOT NULL
 ) m),'[]'::jsonb),'violations',s.state->'violations'||COALESCE((
 SELECT jsonb_agg(jsonb_build_object('kind','account_containment_state_mismatch','id',i.id) ORDER BY i.id)
 FROM private.account_security_incidents i JOIN public.users u ON u.id=i.user_id
 LEFT JOIN private.account_session_revocations w ON w.user_id=i.user_id
 WHERE (i.recovered_at IS NULL AND (u.status<>'disabled' OR EXISTS(SELECT 1 FROM private.auth_sessions a WHERE a.subject=u.auth_subject AND a.revoked_at IS NULL)))
 OR w.revoked_through_epoch IS NULL OR w.revoked_through_epoch<floor(extract(epoch FROM COALESCE(i.recovered_at,i.contained_at)))::bigint
 ),'[]'::jsonb))
 FROM (SELECT private.privacy_restore_state_before_account_incidents() AS state) s
$fn$;
ALTER FUNCTION private.privacy_restore_state() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.privacy_restore_state(),private.privacy_restore_state_before_account_incidents() FROM PUBLIC,profitpilot_app;
COMMIT;

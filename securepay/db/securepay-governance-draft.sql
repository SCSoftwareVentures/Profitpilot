-- Sandbox case governance: identity fingerprints provisioned outside runtime.
BEGIN;
CREATE ROLE securepay_dispute_admin_runtime NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS;
CREATE ROLE securepay_settlement_dashboard_runtime NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS;
GRANT USAGE ON SCHEMA securepay_private TO securepay_dispute_admin_runtime,securepay_settlement_dashboard_runtime;
ALTER TABLE securepay_private.dispute_actors DROP CONSTRAINT dispute_actors_role_check,
 ADD CONSTRAINT dispute_actors_role_check CHECK(role IN ('owner','customer','reviewer','settlement','reconciler','administrator'));
CREATE TABLE securepay_private.actor_person_registry(
 tenant_id uuid NOT NULL,actor_id uuid NOT NULL,person_digest text NOT NULL CHECK(person_digest ~ '^[a-f0-9]{64}$'),
 PRIMARY KEY(tenant_id,actor_id)
);
CREATE TABLE securepay_private.governed_cases(
 case_id uuid PRIMARY KEY REFERENCES securepay_private.dispute_cases(case_id),tenant_id uuid NOT NULL,administrator_id uuid NOT NULL,
 reason text NOT NULL CHECK(length(btrim(reason)) BETWEEN 10 AND 1000),created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE securepay_private.case_governance_assignments(
 case_id uuid NOT NULL REFERENCES securepay_private.governed_cases(case_id),tenant_id uuid NOT NULL,actor_id uuid NOT NULL,
 role text NOT NULL CHECK(role IN ('reviewer','settlement')),assigned_by uuid NOT NULL,reason text NOT NULL CHECK(length(btrim(reason)) BETWEEN 10 AND 1000),
 assigned_at timestamptz NOT NULL DEFAULT clock_timestamp(),revoked_at timestamptz,declaration_at timestamptz,declaration_digest text,
 PRIMARY KEY(case_id,actor_id),CHECK((declaration_at IS NULL)=(declaration_digest IS NULL))
);
CREATE TABLE securepay_private.case_conflicts(
 case_id uuid NOT NULL REFERENCES securepay_private.governed_cases(case_id),tenant_id uuid NOT NULL,actor_id uuid NOT NULL,reported_by uuid NOT NULL,
 reason text NOT NULL CHECK(length(btrim(reason)) BETWEEN 10 AND 1000),reported_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(case_id,actor_id)
);
ALTER TABLE securepay_private.actor_person_registry OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.actor_person_registry FROM PUBLIC,securepay_dispute_admin_runtime,securepay_settlement_dashboard_runtime,securepay_reviewer_runtime,securepay_dispute_runtime,securepay_settlement_runtime;
CREATE TRIGGER sp_chain_actor_person_registry AFTER INSERT OR UPDATE OR DELETE ON securepay_private.actor_person_registry FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
ALTER TABLE securepay_private.governed_cases OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.governed_cases FROM PUBLIC,securepay_dispute_admin_runtime,securepay_settlement_dashboard_runtime,securepay_reviewer_runtime,securepay_dispute_runtime,securepay_settlement_runtime;
CREATE TRIGGER sp_chain_governed_cases AFTER INSERT OR UPDATE OR DELETE ON securepay_private.governed_cases FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
ALTER TABLE securepay_private.case_governance_assignments OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.case_governance_assignments FROM PUBLIC,securepay_dispute_admin_runtime,securepay_settlement_dashboard_runtime,securepay_reviewer_runtime,securepay_dispute_runtime,securepay_settlement_runtime;
CREATE TRIGGER sp_chain_case_governance_assignments AFTER INSERT OR UPDATE OR DELETE ON securepay_private.case_governance_assignments FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
ALTER TABLE securepay_private.case_conflicts OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.case_conflicts FROM PUBLIC,securepay_dispute_admin_runtime,securepay_settlement_dashboard_runtime,securepay_reviewer_runtime,securepay_dispute_runtime,securepay_settlement_runtime;
CREATE TRIGGER sp_chain_case_conflicts AFTER INSERT OR UPDATE OR DELETE ON securepay_private.case_conflicts FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
CREATE FUNCTION securepay_private.person_distinct(t uuid,a uuid,b uuid) RETURNS boolean
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT coalesce((SELECT x.person_digest<>y.person_digest FROM securepay_private.actor_person_registry x JOIN securepay_private.actor_person_registry y ON y.tenant_id=x.tenant_id WHERE x.tenant_id=t AND x.actor_id=a AND y.actor_id=b),false)
$$;
CREATE FUNCTION securepay_private.governance_eligible(t uuid,d uuid,a uuid,wanted text) RETURNS boolean
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM securepay_private.governed_cases g JOIN securepay_private.dispute_cases c ON c.case_id=g.case_id AND c.tenant_id=g.tenant_id
 JOIN securepay_private.dispute_actors x ON x.tenant_id=t AND x.actor_id=a AND x.role=wanted AND x.active
 JOIN securepay_private.case_governance_assignments s ON s.case_id=d AND s.tenant_id=t AND s.actor_id=a AND s.role=wanted AND s.revoked_at IS NULL
 WHERE g.tenant_id=t AND g.case_id=d AND securepay_private.person_distinct(t,a,c.customer_id) AND securepay_private.person_distinct(t,a,c.owner_id)
 AND securepay_private.person_distinct(t,a,g.administrator_id) AND (c.first_reviewer IS NULL OR a=c.first_reviewer OR securepay_private.person_distinct(t,a,c.first_reviewer))
 AND (c.final_reviewer IS NULL OR a=c.final_reviewer OR securepay_private.person_distinct(t,a,c.final_reviewer))
 AND NOT EXISTS(SELECT 1 FROM securepay_private.case_conflicts k JOIN securepay_private.actor_person_registry b ON b.tenant_id=t AND b.actor_id=k.actor_id
 JOIN securepay_private.actor_person_registry me ON me.tenant_id=t AND me.actor_id=a AND me.person_digest=b.person_digest WHERE k.case_id=d))
$$;
CREATE FUNCTION securepay_private.governance_cleared(t uuid,d uuid,a uuid,wanted text) RETURNS boolean
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT securepay_private.governance_eligible(t,d,a,wanted) AND EXISTS(SELECT 1 FROM securepay_private.case_governance_assignments s WHERE s.case_id=d AND s.tenant_id=t AND s.actor_id=a AND s.declaration_at IS NOT NULL)
$$;
CREATE OR REPLACE FUNCTION securepay_private.reviewer_assigned(t uuid,d uuid,a uuid) RETURNS boolean
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM securepay_private.dispute_photo_reviewers r JOIN securepay_private.dispute_actors x ON x.tenant_id=r.tenant_id AND x.actor_id=r.reviewer_id
 JOIN securepay_private.dispute_cases c ON c.case_id=r.case_id AND c.tenant_id=r.tenant_id
 WHERE r.tenant_id=t AND r.case_id=d AND r.reviewer_id=a AND x.active AND x.role='reviewer' AND a NOT IN(c.customer_id,c.owner_id))
 AND (NOT EXISTS(SELECT 1 FROM securepay_private.governed_cases WHERE case_id=d) OR securepay_private.governance_cleared(t,d,a,'reviewer'))
$$;
CREATE FUNCTION securepay_private.admin_case_action(t uuid,d uuid,a uuid,target uuid,op text,reason text,expires bigint,sig text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c securepay_private.dispute_cases%ROWTYPE;mid uuid;target_role text;g securepay_private.governed_cases%ROWTYPE;
BEGIN
 IF t IS NULL OR d IS NULL OR a IS NULL OR op IS NULL OR op NOT IN ('enroll','assign','revoke','conflict') OR reason IS NULL OR length(btrim(reason)) NOT BETWEEN 10 AND 1000
 OR (op='enroll')<>(target IS NULL)
 OR securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-admin-case-v1',t,d,a,coalesce(target::text,'-'),op,encode(convert_to(reason,'UTF8'),'hex'),expires),expires,sig) IS DISTINCT FROM 'administrator' THEN RETURN false; END IF;
 SELECT milestone_id INTO mid FROM securepay_private.dispute_cases WHERE tenant_id=t AND case_id=d;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM 1 FROM public.securepay_milestones WHERE tenant_id=t AND id=mid FOR UPDATE;
 SELECT * INTO c FROM securepay_private.dispute_cases WHERE case_id=d AND tenant_id=t FOR UPDATE;
 IF NOT FOUND OR c.status='settled' OR NOT securepay_private.person_distinct(t,a,c.customer_id) OR NOT securepay_private.person_distinct(t,a,c.owner_id) THEN RETURN false; END IF;
 IF op='enroll' THEN
  IF c.status<>'open' OR c.first_reviewer IS NOT NULL THEN RETURN false; END IF;
  INSERT INTO securepay_private.governed_cases(case_id,tenant_id,administrator_id,reason) VALUES(d,t,a,reason);
  RETURN true;
 END IF;
 SELECT * INTO g FROM securepay_private.governed_cases WHERE case_id=d AND tenant_id=t AND administrator_id=a;
 IF NOT FOUND THEN RETURN false; END IF;
 IF op='assign' THEN
  IF c.status NOT IN ('open','decided','appealed','final') THEN RETURN false; END IF;
  SELECT role INTO target_role FROM securepay_private.dispute_actors WHERE tenant_id=t AND actor_id=target AND active AND role IN ('reviewer','settlement');
  IF NOT FOUND OR NOT securepay_private.person_distinct(t,target,a) OR NOT securepay_private.person_distinct(t,target,c.customer_id) OR NOT securepay_private.person_distinct(t,target,c.owner_id)
  OR EXISTS(SELECT 1 FROM securepay_private.case_governance_assignments x WHERE x.case_id=d AND NOT securepay_private.person_distinct(t,target,x.actor_id))
  OR EXISTS(SELECT 1 FROM securepay_private.case_conflicts x WHERE x.case_id=d AND NOT securepay_private.person_distinct(t,target,x.actor_id)) THEN RETURN false; END IF;
  IF (SELECT count(*) FROM securepay_private.case_governance_assignments WHERE case_id=d)>=20 THEN RETURN false; END IF;
  INSERT INTO securepay_private.case_governance_assignments(case_id,tenant_id,actor_id,role,assigned_by,reason) VALUES(d,t,target,target_role,a,reason);
  IF target_role='reviewer' THEN INSERT INTO securepay_private.dispute_photo_reviewers(case_id,tenant_id,reviewer_id) VALUES(d,t,target) ON CONFLICT DO NOTHING; END IF;
 ELSIF op='revoke' THEN
  UPDATE securepay_private.case_governance_assignments SET revoked_at=clock_timestamp() WHERE case_id=d AND actor_id=target AND revoked_at IS NULL;
  IF NOT FOUND THEN RETURN false; END IF;
 ELSE
  IF NOT EXISTS(SELECT 1 FROM securepay_private.case_governance_assignments WHERE case_id=d AND actor_id=target) THEN RETURN false; END IF;
  INSERT INTO securepay_private.case_conflicts(case_id,tenant_id,actor_id,reported_by,reason) VALUES(d,t,target,a,reason);
  UPDATE securepay_private.case_governance_assignments SET revoked_at=coalesce(revoked_at,clock_timestamp()) WHERE case_id=d AND actor_id=target;
 END IF;
 INSERT INTO securepay_private.dispute_events(event_id,case_id,actor_id,action,details) VALUES(gen_random_uuid(),d,a,'governance_'||op,reason);
 RETURN true;
EXCEPTION WHEN unique_violation THEN RETURN false;
END $$;
CREATE FUNCTION securepay_private.declare_independence(t uuid,d uuid,a uuid,attestation text,expires bigint,sig text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE wanted text;mid uuid;
BEGIN
 IF attestation IS DISTINCT FROM 'No known personal, financial or professional conflict; I will disclose any change' THEN RETURN false; END IF;
 wanted:=securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-independence-v1',t,d,a,encode(convert_to(attestation,'UTF8'),'hex'),expires),expires,sig);
 IF wanted IS NULL OR wanted NOT IN ('reviewer','settlement') THEN RETURN false; END IF;
 SELECT milestone_id INTO mid FROM securepay_private.dispute_cases WHERE case_id=d AND tenant_id=t;
 PERFORM 1 FROM public.securepay_milestones WHERE tenant_id=t AND id=mid FOR UPDATE;
 PERFORM 1 FROM securepay_private.dispute_cases WHERE case_id=d AND tenant_id=t AND status<>'settled' FOR UPDATE;
 IF NOT FOUND OR NOT securepay_private.governance_eligible(t,d,a,wanted) THEN RETURN false; END IF;
 UPDATE securepay_private.case_governance_assignments SET declaration_at=clock_timestamp(),declaration_digest=encode(public.digest(convert_to(attestation,'UTF8'),'sha256'),'hex')
 WHERE case_id=d AND actor_id=a AND declaration_at IS NULL AND revoked_at IS NULL;
 RETURN FOUND;
END $$;
CREATE FUNCTION securepay_private.admin_queue(t uuid,a uuid,expires bigint,sig text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r jsonb;
BEGIN
 IF securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-admin-queue-v1',t,a,expires),expires,sig) IS DISTINCT FROM 'administrator' THEN RETURN NULL; END IF;
 SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY q."caseId"),'[]'::jsonb) INTO r FROM (
 SELECT c.case_id AS "caseId",c.status,c.severity,c.milestone_id AS "milestoneId",g.case_id IS NOT NULL AS governed,g.administrator_id=a AS "managedByMe",
 (SELECT coalesce(jsonb_agg(jsonb_build_object('actorId',x.actor_id,'role',x.role,'declared',x.declaration_at IS NOT NULL,'revoked',x.revoked_at IS NOT NULL,'conflict',EXISTS(SELECT 1 FROM securepay_private.case_conflicts k WHERE k.case_id=c.case_id AND k.actor_id=x.actor_id)) ORDER BY x.actor_id),'[]'::jsonb) FROM securepay_private.case_governance_assignments x WHERE x.case_id=c.case_id) AS assignments
 FROM securepay_private.dispute_cases c LEFT JOIN securepay_private.governed_cases g ON g.case_id=c.case_id WHERE c.tenant_id=t AND c.status<>'settled' AND securepay_private.person_distinct(t,a,c.customer_id) AND securepay_private.person_distinct(t,a,c.owner_id) ORDER BY c.case_id LIMIT 101) q;
 IF jsonb_array_length(r)>100 THEN RAISE EXCEPTION 'Administration queue exceeds capacity'; END IF;
 RETURN r;
END $$;
CREATE FUNCTION securepay_private.governance_settlement_ok(t uuid,d uuid,a uuid) RETURNS boolean
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT NOT EXISTS(SELECT 1 FROM securepay_private.governed_cases WHERE case_id=d)
 OR EXISTS(SELECT 1 FROM securepay_private.dispute_cases c WHERE c.case_id=d AND c.tenant_id=t
 AND securepay_private.governance_cleared(t,d,a,'settlement') AND securepay_private.governance_cleared(t,d,c.first_reviewer,'reviewer')
 AND securepay_private.governance_cleared(t,d,c.final_reviewer,'reviewer') AND securepay_private.person_distinct(t,c.first_reviewer,c.final_reviewer)
 AND securepay_private.person_distinct(t,a,c.first_reviewer) AND securepay_private.person_distinct(t,a,c.final_reviewer))
$$;
ALTER FUNCTION securepay_private.person_distinct(uuid,uuid,uuid) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.person_distinct(uuid,uuid,uuid) FROM PUBLIC;
ALTER FUNCTION securepay_private.governance_eligible(uuid,uuid,uuid,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.governance_eligible(uuid,uuid,uuid,text) FROM PUBLIC;
ALTER FUNCTION securepay_private.governance_cleared(uuid,uuid,uuid,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.governance_cleared(uuid,uuid,uuid,text) FROM PUBLIC;
ALTER FUNCTION securepay_private.admin_case_action(uuid,uuid,uuid,uuid,text,text,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.admin_case_action(uuid,uuid,uuid,uuid,text,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.admin_case_action(uuid,uuid,uuid,uuid,text,text,bigint,text) TO securepay_dispute_admin_runtime;
ALTER FUNCTION securepay_private.declare_independence(uuid,uuid,uuid,text,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.declare_independence(uuid,uuid,uuid,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.declare_independence(uuid,uuid,uuid,text,bigint,text) TO securepay_reviewer_runtime,securepay_settlement_dashboard_runtime;
ALTER FUNCTION securepay_private.admin_queue(uuid,uuid,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.admin_queue(uuid,uuid,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.admin_queue(uuid,uuid,bigint,text) TO securepay_dispute_admin_runtime;
ALTER FUNCTION securepay_private.governance_settlement_ok(uuid,uuid,uuid) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.governance_settlement_ok(uuid,uuid,uuid) FROM PUBLIC;
COMMIT;

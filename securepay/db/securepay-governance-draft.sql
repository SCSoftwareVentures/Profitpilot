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
CREATE OR REPLACE FUNCTION securepay_private.read_dispute_photo(p uuid,t uuid,m uuid,d uuid,a uuid,expires bigint,sig text)
 RETURNS TABLE(media_type text,digest text,content bytea)
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c securepay_private.dispute_cases%ROWTYPE; role_name text; record_photo securepay_private.dispute_photos%ROWTYPE; secret_key bytea; plain bytea;
BEGIN
 IF p IS NULL OR t IS NULL OR m IS NULL OR d IS NULL OR a IS NULL THEN RETURN; END IF;
 role_name:=securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-photo-read-v1',p,t,m,d,a,expires),expires,sig);
 IF role_name IS NULL OR role_name NOT IN ('owner','customer','reviewer') THEN RETURN; END IF;
 SELECT * INTO c FROM securepay_private.dispute_cases WHERE case_id=d AND tenant_id=t AND milestone_id=m;
 IF NOT FOUND OR (role_name='owner' AND a<>c.owner_id) OR (role_name='customer' AND a<>c.customer_id)
 OR (role_name='reviewer' AND NOT securepay_private.reviewer_assigned(t,d,a)) THEN RETURN; END IF;
 SELECT q.* INTO record_photo FROM securepay_private.dispute_photos q WHERE q.photo_id=p AND q.case_id=d;
 IF NOT FOUND OR record_photo.purged_at IS NOT NULL THEN RETURN; END IF;
 SELECT secret INTO secret_key FROM securepay_private.evidence_keys WHERE key_id=record_photo.key_id AND read_enabled;
 IF secret_key IS NULL THEN RAISE EXCEPTION 'Evidence unavailable' USING ERRCODE='22000'; END IF;
 plain:=public.pgp_sym_decrypt_bytea(record_photo.content,encode(secret_key,'hex'));
 IF octet_length(plain)<>record_photo.plaintext_size OR encode(public.digest(plain,'sha256'),'hex')<>record_photo.digest THEN
  RAISE EXCEPTION 'Evidence integrity failure' USING ERRCODE='22000';
 END IF;
 PERFORM securepay_private.append_audit_chain(t,'dispute_photos','READ',encode(public.digest(convert_to(concat_ws(':',p,d,a,record_photo.digest),'UTF8'),'sha256'),'hex'));
 RETURN QUERY SELECT record_photo.media_type,record_photo.digest,plain;
END $$;
CREATE OR REPLACE FUNCTION securepay_private.dispute_work_evidence(t uuid,m uuid,d uuid,a uuid,p uuid,expires bigint,sig text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c securepay_private.dispute_cases%ROWTYPE;role_name text;photo securepay_private.work_photos%ROWTYPE;k bytea;plain bytea;items jsonb;
BEGIN
 role_name:=securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-linked-work-v1',t,m,d,a,coalesce(p::text,'-'),expires),expires,sig);
 IF role_name IS NULL OR t IS NULL OR m IS NULL OR d IS NULL OR a IS NULL THEN RETURN NULL; END IF;
 PERFORM 1 FROM public.securepay_milestones WHERE tenant_id=t AND id=m FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL; END IF;
 SELECT * INTO c FROM securepay_private.dispute_cases WHERE tenant_id=t AND milestone_id=m AND case_id=d FOR UPDATE;
 IF NOT FOUND OR NOT ((role_name='customer' AND a=c.customer_id) OR (role_name='owner' AND a=c.owner_id) OR (role_name='reviewer' AND securepay_private.reviewer_assigned(t,d,a))) THEN RETURN NULL; END IF;
 IF p IS NULL THEN
  SELECT coalesce(jsonb_agg(jsonb_build_object('completionId',w.completion_id,'manifestDigest',l.manifest_digest,'comments',w.comments,'status',w.status,'rejectionReason',w.rejection_reason,
   'photos',(SELECT coalesce(jsonb_agg(jsonb_build_object('photoId',q.photo_id,'digest',q.digest,'purged',q.purged_at IS NOT NULL) ORDER BY q.photo_id),'[]'::jsonb) FROM securepay_private.work_photos q WHERE q.completion_id=w.completion_id)) ORDER BY w.completion_id),'[]'::jsonb) INTO items
  FROM securepay_private.work_dispute_links l JOIN securepay_private.work_completion w ON w.completion_id=l.completion_id WHERE l.case_id=d AND l.tenant_id=t;
  RETURN jsonb_build_object('completions',items);
 END IF;
 SELECT q.* INTO photo FROM securepay_private.work_photos q JOIN securepay_private.work_dispute_links l ON l.completion_id=q.completion_id WHERE l.case_id=d AND l.tenant_id=t AND q.photo_id=p AND q.tenant_id=t;
 IF NOT FOUND OR photo.purged_at IS NOT NULL THEN RETURN NULL; END IF;
 SELECT secret INTO k FROM securepay_private.evidence_keys WHERE key_id=photo.key_id AND read_enabled;
 IF k IS NULL THEN RAISE EXCEPTION 'Evidence unavailable'; END IF;
 plain:=public.pgp_sym_decrypt_bytea(photo.content,encode(k,'hex'));
 IF octet_length(plain)<>photo.plaintext_size OR encode(public.digest(plain,'sha256'),'hex')<>photo.digest THEN RAISE EXCEPTION 'Evidence integrity failure'; END IF;
 PERFORM securepay_private.append_audit_chain(t,'work_photos','READ',encode(public.digest(convert_to(concat_ws(':',p,d,a,photo.digest),'UTF8'),'sha256'),'hex'));
 RETURN jsonb_build_object('photoId',p,'digest',photo.digest,'content',replace(encode(plain,'base64'),chr(10),''));
END $$;
CREATE OR REPLACE FUNCTION securepay_private.authorize_settlement(s uuid,t uuid,m uuid,d uuid,a uuid,payout bigint,refund bigint,expires bigint,sig text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c securepay_private.dispute_cases%ROWTYPE; milestone public.securepay_milestones%ROWTYPE;
BEGIN
 IF s IS NULL OR t IS NULL OR m IS NULL OR d IS NULL OR a IS NULL OR payout IS NULL OR refund IS NULL OR payout<0 OR refund<0 OR
 securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-settlement-v1',s,t,m,d,a,payout,refund,expires),expires,sig) IS DISTINCT FROM 'settlement' THEN RETURN false; END IF;
 SELECT * INTO milestone FROM public.securepay_milestones WHERE tenant_id=t AND id=m FOR UPDATE;
 IF NOT FOUND OR milestone.status<>'disputed' OR payout::numeric+refund::numeric<>milestone.amount_cents THEN RETURN false; END IF;
 PERFORM 1 FROM securepay_private.provider_funding WHERE tenant_id=t AND milestone_id=m AND status='funded' AND amount_cents=milestone.amount_cents FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO c FROM securepay_private.dispute_cases WHERE case_id=d AND tenant_id=t AND milestone_id=m FOR UPDATE;
 IF NOT FOUND OR c.status<>'final' OR a IN (c.customer_id,c.owner_id,c.first_reviewer,c.final_reviewer) OR
 payout<>c.payout_cents OR refund<>c.refund_cents OR NOT securepay_private.governance_settlement_ok(t,d,a) THEN RETURN false; END IF;
 INSERT INTO securepay_private.dispute_settlements(settlement_id,case_id,authorizer,payout_cents,refund_cents,status) VALUES(s,d,a,payout,refund,'authorized');
 UPDATE securepay_private.dispute_cases SET status='authorized' WHERE case_id=d;
 RETURN true;
EXCEPTION WHEN unique_violation THEN RETURN false;
END $$;
CREATE OR REPLACE FUNCTION securepay_private.dispatch_settlement_leg(s uuid,t uuid,m uuid,d uuid,k text)
 RETURNS TABLE(leg_id uuid,attempt integer,amount_cents bigint)
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE amount bigint;
BEGIN
 IF k IS NULL OR k NOT IN ('payout','refund') THEN RETURN; END IF;
 SELECT x.amount_cents INTO amount FROM public.securepay_milestones x WHERE x.tenant_id=t AND x.id=m AND x.status='disputed' FOR UPDATE;
 IF NOT FOUND THEN RETURN; END IF;
 PERFORM 1 FROM securepay_private.provider_funding f WHERE f.tenant_id=t AND f.milestone_id=m AND f.status='funded' AND f.amount_cents=amount FOR UPDATE;
 IF NOT FOUND THEN RETURN; END IF;
 PERFORM 1 FROM securepay_private.dispute_cases c WHERE c.case_id=d AND c.tenant_id=t AND c.milestone_id=m AND c.status='authorized' FOR UPDATE;
 IF NOT FOUND THEN RETURN; END IF;
 PERFORM 1 FROM securepay_private.dispute_settlements x WHERE x.settlement_id=s AND x.case_id=d AND x.status IN ('authorized','submitted') FOR UPDATE;
 IF NOT FOUND THEN RETURN; END IF;
 IF NOT EXISTS(SELECT 1 FROM securepay_private.dispute_settlements st WHERE st.settlement_id=s AND securepay_private.governance_settlement_ok(t,d,st.authorizer)) THEN RETURN; END IF;
 IF EXISTS(SELECT 1 FROM securepay_private.settlement_legs x WHERE x.settlement_id=s AND x.status IN ('unknown','not_executed'))
 OR EXISTS(SELECT 1 FROM securepay_private.settlement_leg_conflicts x WHERE x.case_id=d AND x.resolved_at IS NULL) THEN RETURN; END IF;
 RETURN QUERY UPDATE securepay_private.settlement_legs x SET status='submitted',attempts=x.attempts+1
 WHERE x.settlement_id=s AND x.kind=k AND x.status='pending' AND x.attempts<4
 RETURNING x.leg_id,x.attempts,x.amount_cents;
 IF FOUND THEN UPDATE securepay_private.dispute_settlements SET status='submitted' WHERE settlement_id=s AND status='authorized'; END IF;
END $$;
CREATE FUNCTION securepay_private.governance_my_cases(t uuid,a uuid,expires bigint,sig text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE wanted text;r jsonb;
BEGIN
 wanted:=securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-governance-my-v1',t,a,expires),expires,sig);
 IF wanted IS NULL OR wanted NOT IN ('reviewer','settlement') THEN RETURN NULL; END IF;
 SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY q."caseId"),'[]'::jsonb) INTO r FROM (
 SELECT c.case_id AS "caseId",c.status,c.severity,x.declaration_at IS NOT NULL AS declared,securepay_private.governance_eligible(t,c.case_id,a,wanted) AS eligible
 FROM securepay_private.case_governance_assignments x JOIN securepay_private.dispute_cases c ON c.case_id=x.case_id AND c.tenant_id=x.tenant_id
 WHERE x.tenant_id=t AND x.actor_id=a AND x.role=wanted AND c.status<>'settled' ORDER BY c.case_id LIMIT 101) q;
 IF jsonb_array_length(r)>100 THEN RAISE EXCEPTION 'Assignment capacity exceeded'; END IF;
 RETURN r;
END $$;
CREATE FUNCTION securepay_private.settlement_dashboard_snapshot(t uuid,d uuid,a uuid) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r jsonb;
BEGIN
 IF NOT securepay_private.governance_cleared(t,d,a,'settlement') THEN RETURN NULL; END IF;
 SELECT jsonb_build_object('caseId',c.case_id,'milestoneId',c.milestone_id,'caseStatus',c.status,'fundingStatus',f.status,'amountCents',m.amount_cents::text,'payoutCents',c.payout_cents::text,'refundCents',c.refund_cents::text,
 'journalVerified',securepay_private.verify_financial_journal(t,m.id),'fundedCents',b.funded_cents::text,'remainingCents',b.remaining_cents::text,
 'confirmedPayoutCents',b.payout_cents::text,'confirmedRefundCents',b.refund_cents::text,
 'unresolved',EXISTS(SELECT 1 FROM securepay_private.provider_reconciliation x WHERE x.tenant_id=t AND x.milestone_id=m.id AND x.resolved_at IS NULL) OR EXISTS(SELECT 1 FROM securepay_private.settlement_leg_conflicts x WHERE x.case_id=d AND x.resolved_at IS NULL),
 'independent',securepay_private.governance_settlement_ok(t,d,a),
 'decision',(SELECT jsonb_build_object('eventId',e.event_id,'reason',e.details,'digest',e.evidence_digest) FROM securepay_private.dispute_events e WHERE e.case_id=d AND e.action='finalize' ORDER BY e.occurred_at DESC,e.event_id DESC LIMIT 1),
 'settlementId',st.settlement_id,'settlementStatus',st.status,
 'legs',(SELECT coalesce(jsonb_agg(jsonb_build_object('kind',l.kind,'amountCents',l.amount_cents::text,'status',l.status) ORDER BY l.kind),'[]'::jsonb) FROM securepay_private.settlement_legs l WHERE l.case_id=d))
 INTO r FROM securepay_private.dispute_cases c JOIN public.securepay_milestones m ON m.tenant_id=c.tenant_id AND m.id=c.milestone_id JOIN securepay_private.provider_funding f ON f.tenant_id=c.tenant_id AND f.milestone_id=c.milestone_id CROSS JOIN LATERAL securepay_private.financial_balance(t,m.id) b LEFT JOIN securepay_private.dispute_settlements st ON st.case_id=c.case_id WHERE c.tenant_id=t AND c.case_id=d;
 RETURN r;
END $$;
CREATE FUNCTION securepay_private.settlement_dashboard_read(t uuid,d uuid,a uuid,expires bigint,sig text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r jsonb;mid uuid;
BEGIN
 IF securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-settlement-dashboard-v1',t,d,a,expires),expires,sig) IS DISTINCT FROM 'settlement' OR NOT securepay_private.governance_cleared(t,d,a,'settlement') THEN RETURN NULL; END IF;
 SELECT milestone_id INTO mid FROM securepay_private.dispute_cases WHERE tenant_id=t AND case_id=d;
 PERFORM 1 FROM public.securepay_milestones WHERE tenant_id=t AND id=mid FOR UPDATE;
 PERFORM 1 FROM securepay_private.provider_funding WHERE tenant_id=t AND milestone_id=mid FOR UPDATE;
 PERFORM 1 FROM securepay_private.dispute_cases WHERE tenant_id=t AND case_id=d FOR UPDATE;
 r:=securepay_private.settlement_dashboard_snapshot(t,d,a);
 IF r IS NULL THEN RETURN NULL; END IF;
 PERFORM securepay_private.append_audit_chain(t,'settlement_dashboard','READ',encode(public.digest(convert_to(concat_ws(':',d,a),'UTF8'),'sha256'),'hex'));
 RETURN jsonb_build_object('case',r,'stateDigest',encode(public.digest(convert_to(r::text,'UTF8'),'sha256'),'hex'));
END $$;
CREATE FUNCTION securepay_private.settlement_dashboard_authorize(s uuid,t uuid,d uuid,a uuid,payout bigint,refund bigint,state_hash text,expires bigint,sig text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE mid uuid;r jsonb;k bytea;inner_sig text;
BEGIN
 IF s IS NULL OR t IS NULL OR d IS NULL OR a IS NULL OR payout IS NULL OR refund IS NULL OR payout<0 OR refund<0 OR state_hash IS NULL OR state_hash !~ '^[a-f0-9]{64}$'
 OR securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-settlement-dashboard-authorize-v1',s,t,d,a,payout,refund,state_hash,expires),expires,sig) IS DISTINCT FROM 'settlement' OR NOT securepay_private.governance_cleared(t,d,a,'settlement') THEN RETURN false; END IF;
 SELECT milestone_id INTO mid FROM securepay_private.dispute_cases WHERE tenant_id=t AND case_id=d;
 PERFORM 1 FROM public.securepay_milestones WHERE tenant_id=t AND id=mid FOR UPDATE;
 PERFORM 1 FROM securepay_private.provider_funding WHERE tenant_id=t AND milestone_id=mid FOR UPDATE;
 PERFORM 1 FROM securepay_private.dispute_cases WHERE tenant_id=t AND case_id=d FOR UPDATE;
 r:=securepay_private.settlement_dashboard_snapshot(t,d,a);
 IF r IS NULL OR encode(public.digest(convert_to(r::text,'UTF8'),'sha256'),'hex')<>state_hash
 OR r->>'caseStatus'<>'final' OR r->>'fundingStatus'<>'funded' OR NOT (r->>'journalVerified')::boolean OR (r->>'unresolved')::boolean OR NOT (r->>'independent')::boolean
 OR r->>'payoutCents' IS DISTINCT FROM payout::text OR r->>'refundCents' IS DISTINCT FROM refund::text OR (r->>'remainingCents')::numeric<>payout::numeric+refund::numeric OR r->'decision'='null'::jsonb THEN RETURN false; END IF;
 SELECT secret INTO k FROM securepay_private.dispute_actors WHERE tenant_id=t AND actor_id=a AND active AND role='settlement';
 IF k IS NULL THEN RETURN false; END IF;
 inner_sig:=encode(public.hmac(convert_to(concat_ws(':','sp-settlement-v1',s,t,mid,d,a,payout,refund,expires),'UTF8'),k,'sha256'),'hex');
 RETURN securepay_private.authorize_settlement_internal(s,t,mid,d,a,payout,refund,expires,inner_sig);
END $$;
ALTER FUNCTION securepay_private.governance_my_cases(uuid,uuid,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.governance_my_cases(uuid,uuid,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.governance_my_cases(uuid,uuid,bigint,text) TO securepay_reviewer_runtime,securepay_settlement_dashboard_runtime;
ALTER FUNCTION securepay_private.settlement_dashboard_snapshot(uuid,uuid,uuid) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.settlement_dashboard_snapshot(uuid,uuid,uuid) FROM PUBLIC;
ALTER FUNCTION securepay_private.settlement_dashboard_read(uuid,uuid,uuid,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.settlement_dashboard_read(uuid,uuid,uuid,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.settlement_dashboard_read(uuid,uuid,uuid,bigint,text) TO securepay_settlement_dashboard_runtime;
ALTER FUNCTION securepay_private.settlement_dashboard_authorize(uuid,uuid,uuid,uuid,bigint,bigint,text,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.settlement_dashboard_authorize(uuid,uuid,uuid,uuid,bigint,bigint,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.settlement_dashboard_authorize(uuid,uuid,uuid,uuid,bigint,bigint,text,bigint,text) TO securepay_settlement_dashboard_runtime;
-- Keep legacy internal adapters only for ungoverned synthetic cases.
ALTER FUNCTION securepay_private.dispute_action(uuid,uuid,uuid,uuid,uuid,text,text,text,bigint,bigint,bigint,text) RENAME TO dispute_action_internal;
REVOKE EXECUTE ON FUNCTION securepay_private.dispute_action_internal(uuid,uuid,uuid,uuid,uuid,text,text,text,bigint,bigint,bigint,text) FROM securepay_dispute_runtime;
CREATE FUNCTION securepay_private.dispute_action(e uuid,t uuid,m uuid,d uuid,a uuid,op text,details text,digest text,payout bigint,refund bigint,expires bigint,sig text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF op IN ('decide','finalize') THEN
  PERFORM 1 FROM public.securepay_milestones WHERE tenant_id=t AND id=m FOR UPDATE;
  IF EXISTS(SELECT 1 FROM securepay_private.governed_cases WHERE case_id=d) THEN RETURN false; END IF;
 END IF;
 RETURN securepay_private.dispute_action_internal(e,t,m,d,a,op,details,digest,payout,refund,expires,sig);
END $$;
ALTER FUNCTION securepay_private.dispute_action(uuid,uuid,uuid,uuid,uuid,text,text,text,bigint,bigint,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.dispute_action(uuid,uuid,uuid,uuid,uuid,text,text,text,bigint,bigint,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.dispute_action(uuid,uuid,uuid,uuid,uuid,text,text,text,bigint,bigint,bigint,text) TO securepay_dispute_runtime;
CREATE OR REPLACE FUNCTION securepay_private.reviewer_decision(e uuid,t uuid,d uuid,a uuid,op text,reason text,payout bigint,refund bigint,state_hash text,expires bigint,sig text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE mid uuid;k bytea;s jsonb;h text;inner_sig text;
BEGIN
 IF e IS NULL OR op IS NULL OR op NOT IN ('decide','finalize') OR reason IS NULL OR length(btrim(reason)) NOT BETWEEN 10 AND 4000 OR payout IS NULL OR refund IS NULL OR payout<0 OR refund<0 OR state_hash IS NULL OR state_hash !~ '^[a-f0-9]{64}$'
 OR securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-review-decision-v1',e,t,d,a,op,encode(convert_to(reason,'UTF8'),'hex'),payout,refund,state_hash,expires),expires,sig) IS DISTINCT FROM 'reviewer' OR NOT securepay_private.reviewer_assigned(t,d,a) THEN RETURN false; END IF;
 SELECT milestone_id INTO mid FROM securepay_private.dispute_cases WHERE tenant_id=t AND case_id=d;
 PERFORM 1 FROM public.securepay_milestones WHERE tenant_id=t AND id=mid FOR UPDATE;
 PERFORM 1 FROM securepay_private.provider_funding WHERE tenant_id=t AND milestone_id=mid FOR UPDATE;
 PERFORM 1 FROM securepay_private.dispute_cases WHERE tenant_id=t AND case_id=d FOR UPDATE;
 s:=securepay_private.reviewer_snapshot(t,d,a);
 IF s IS NULL THEN RETURN false; END IF;
 h:=encode(public.digest(convert_to(s::text,'UTF8'),'sha256'),'hex');
 IF h<>state_hash OR EXISTS(SELECT 1 FROM jsonb_array_elements((s->'photos')||(s->'linkedPhotos')) AS item(photo) WHERE NOT (item.photo->>'purged')::boolean AND NOT EXISTS(SELECT 1 FROM securepay_private.reviewer_photo_reads r WHERE r.tenant_id=t AND r.case_id=d AND r.reviewer_id=a AND r.source=(item.photo->>'source') AND r.photo_id=(item.photo->>'photoId')::uuid AND r.digest=(item.photo->>'digest'))) THEN RETURN false; END IF;
 SELECT secret INTO k FROM securepay_private.dispute_actors WHERE tenant_id=t AND actor_id=a AND active AND role='reviewer';
 IF k IS NULL THEN RETURN false; END IF;
 inner_sig:=encode(public.hmac(convert_to(concat_ws(':','sp-dispute-v1',e,t,mid,d,a,op,encode(convert_to(reason,'UTF8'),'hex'),h,payout,refund,expires),'UTF8'),k,'sha256'),'hex');
 RETURN securepay_private.dispute_action_internal(e,t,mid,d,a,op,reason,h,payout,refund,expires,inner_sig);
END $$;
ALTER FUNCTION securepay_private.authorize_settlement(uuid,uuid,uuid,uuid,uuid,bigint,bigint,bigint,text) RENAME TO authorize_settlement_internal;
REVOKE EXECUTE ON FUNCTION securepay_private.authorize_settlement_internal(uuid,uuid,uuid,uuid,uuid,bigint,bigint,bigint,text) FROM securepay_settlement_runtime;
CREATE FUNCTION securepay_private.authorize_settlement(s uuid,t uuid,m uuid,d uuid,a uuid,payout bigint,refund bigint,expires bigint,sig text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM 1 FROM public.securepay_milestones WHERE tenant_id=t AND id=m FOR UPDATE;
 IF EXISTS(SELECT 1 FROM securepay_private.governed_cases WHERE case_id=d) THEN RETURN false; END IF;
 RETURN securepay_private.authorize_settlement_internal(s,t,m,d,a,payout,refund,expires,sig);
END $$;
ALTER FUNCTION securepay_private.authorize_settlement(uuid,uuid,uuid,uuid,uuid,bigint,bigint,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.authorize_settlement(uuid,uuid,uuid,uuid,uuid,bigint,bigint,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.authorize_settlement(uuid,uuid,uuid,uuid,uuid,bigint,bigint,bigint,text) TO securepay_settlement_runtime;
COMMIT;

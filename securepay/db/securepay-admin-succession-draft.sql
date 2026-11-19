-- Emergency succession requires a disabled current administrator and three
-- independently registered replacement participants. No financial authority.
BEGIN;
CREATE TABLE securepay_private.case_admin_successions(
 request_id uuid PRIMARY KEY, tenant_id uuid NOT NULL,case_id uuid NOT NULL REFERENCES securepay_private.governed_cases(case_id),
 previous_admin uuid NOT NULL,nominee uuid NOT NULL,requested_by uuid NOT NULL,approved_by uuid,
 reason text NOT NULL CHECK(length(btrim(reason)) BETWEEN 10 AND 1000),
 approval_reason text CHECK(length(btrim(approval_reason)) BETWEEN 10 AND 1000),
 state_digest text NOT NULL CHECK(state_digest ~ '^[a-f0-9]{64}$'),
 status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','withdrawn')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),resolved_at timestamptz,
 CHECK((status='approved')=(approved_by IS NOT NULL AND approval_reason IS NOT NULL)),
 CHECK((status='pending')=(resolved_at IS NULL))
);
ALTER TABLE securepay_private.case_admin_successions OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.case_admin_successions FROM PUBLIC,securepay_dispute_admin_runtime,securepay_reviewer_runtime,securepay_settlement_dashboard_runtime;
CREATE UNIQUE INDEX sp_admin_succession_pending ON securepay_private.case_admin_successions(case_id) WHERE status='pending';
CREATE TRIGGER sp_chain_admin_succession AFTER INSERT OR UPDATE OR DELETE ON securepay_private.case_admin_successions FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
CREATE FUNCTION securepay_private.distinct_from_succession(t uuid,d uuid,a uuid) RETURNS boolean
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT NOT EXISTS(SELECT 1 FROM securepay_private.case_admin_successions s WHERE s.tenant_id=t AND s.case_id=d AND s.status='approved'
 AND (NOT securepay_private.person_distinct(t,a,s.previous_admin) OR NOT securepay_private.person_distinct(t,a,s.nominee)
 OR NOT securepay_private.person_distinct(t,a,s.requested_by) OR NOT securepay_private.person_distinct(t,a,s.approved_by)))
$$;
CREATE FUNCTION securepay_private.succession_snapshot(t uuid,d uuid,n uuid,a uuid) RETURNS text
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT encode(public.digest(convert_to(jsonb_build_array(g.administrator_id,c.status,c.first_reviewer,c.final_reviewer,
 (SELECT jsonb_agg(jsonb_build_array(x.actor_id,x.active,x.role,p.person_digest) ORDER BY x.actor_id) FROM securepay_private.dispute_actors x LEFT JOIN securepay_private.actor_person_registry p USING(tenant_id,actor_id) WHERE x.tenant_id=t AND x.actor_id IN(g.administrator_id,n,a)),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY x.actor_id) FROM securepay_private.case_governance_assignments x WHERE x.case_id=d),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY x.actor_id) FROM securepay_private.case_conflicts x WHERE x.case_id=d),
 (SELECT jsonb_agg(jsonb_build_array(x.request_id,x.status) ORDER BY x.request_id) FROM securepay_private.case_reassessments x WHERE x.case_id=d),
 (SELECT jsonb_agg(jsonb_build_array(x.review_id,x.status) ORDER BY x.review_id) FROM securepay_private.post_auth_reviews x WHERE x.case_id=d),
 (SELECT count(*) FROM securepay_private.dispute_events x WHERE x.case_id=d)
 )::text,'UTF8'),'sha256'),'hex') FROM securepay_private.governed_cases g JOIN securepay_private.dispute_cases c ON c.case_id=g.case_id AND c.tenant_id=g.tenant_id
 JOIN securepay_private.dispute_actors old ON old.tenant_id=t AND old.actor_id=g.administrator_id AND old.role='administrator' AND NOT old.active
 WHERE g.tenant_id=t AND g.case_id=d AND c.status<>'settled'
$$;
CREATE FUNCTION securepay_private.succession_actor_valid(t uuid,d uuid,a uuid,old uuid) RETURNS boolean
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT securepay_private.reassessment_admin_valid(t,d,a) AND securepay_private.person_distinct(t,a,old)
 AND NOT EXISTS(SELECT 1 FROM securepay_private.case_reassessments r WHERE r.case_id=d AND r.status='approved' AND NOT securepay_private.person_distinct(t,a,r.approved_by))
 AND NOT EXISTS(SELECT 1 FROM securepay_private.case_conflicts x WHERE x.case_id=d AND NOT securepay_private.person_distinct(t,a,x.actor_id))
$$;
CREATE FUNCTION securepay_private.succession_action(r uuid,t uuid,d uuid,a uuid,n uuid,op text,reason text,h text,expires bigint,sig text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE mid uuid;g securepay_private.governed_cases%ROWTYPE;q securepay_private.case_admin_successions%ROWTYPE;digest text;
BEGIN
 IF r IS NULL OR t IS NULL OR d IS NULL OR a IS NULL OR n IS NULL OR op IS NULL OR op NOT IN ('request','approve','withdraw') OR reason IS NULL OR length(btrim(reason)) NOT BETWEEN 10 AND 1000
 OR (op='request')<>(h IS NULL) OR (h IS NOT NULL AND h !~ '^[a-f0-9]{64}$')
 OR securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-admin-succession-v1',r,t,d,a,n,op,encode(convert_to(reason,'UTF8'),'hex'),coalesce(h,'-'),expires),expires,sig) IS DISTINCT FROM 'administrator' THEN RETURN NULL; END IF;
 SELECT milestone_id INTO mid FROM securepay_private.dispute_cases WHERE tenant_id=t AND case_id=d;
 IF NOT FOUND THEN RETURN NULL; END IF;
 PERFORM 1 FROM public.securepay_milestones WHERE tenant_id=t AND id=mid FOR UPDATE;
 PERFORM 1 FROM securepay_private.provider_funding WHERE tenant_id=t AND milestone_id=mid FOR UPDATE;
 PERFORM 1 FROM securepay_private.dispute_cases WHERE tenant_id=t AND case_id=d AND status<>'settled' FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL; END IF;
 SELECT * INTO g FROM securepay_private.governed_cases WHERE tenant_id=t AND case_id=d FOR UPDATE;
 IF NOT FOUND OR NOT securepay_private.succession_actor_valid(t,d,a,g.administrator_id) THEN RETURN NULL; END IF;
 -- Lock actor status and fingerprint rows so concurrent deactivation or reprovisioning cannot change approval validity.
 PERFORM 1 FROM securepay_private.dispute_actors WHERE tenant_id=t AND actor_id IN(a,n,g.administrator_id) ORDER BY actor_id FOR UPDATE;
 PERFORM 1 FROM securepay_private.actor_person_registry WHERE tenant_id=t AND actor_id IN(a,n,g.administrator_id) ORDER BY actor_id FOR UPDATE;
 IF NOT securepay_private.succession_actor_valid(t,d,a,g.administrator_id) THEN RETURN NULL; END IF;
 IF op='request' THEN
  IF NOT securepay_private.succession_actor_valid(t,d,n,g.administrator_id) OR NOT securepay_private.person_distinct(t,a,n)
  OR (SELECT count(*) FROM securepay_private.case_admin_successions WHERE case_id=d)>=10 THEN RETURN NULL; END IF;
  digest:=securepay_private.succession_snapshot(t,d,n,a);
  IF digest IS NULL THEN RETURN NULL; END IF;
  INSERT INTO securepay_private.case_admin_successions(request_id,tenant_id,case_id,previous_admin,nominee,requested_by,reason,state_digest) VALUES(r,t,d,g.administrator_id,n,a,reason,digest);
  RETURN jsonb_build_object('requestId',r,'stateDigest',digest,'status','pending');
 END IF;
 SELECT * INTO q FROM securepay_private.case_admin_successions WHERE request_id=r AND tenant_id=t AND case_id=d AND nominee=n AND status='pending' FOR UPDATE;
 IF NOT FOUND OR q.state_digest<>h OR q.previous_admin<>g.administrator_id THEN RETURN NULL; END IF;
 IF op='withdraw' THEN
  IF q.requested_by<>a THEN RETURN NULL; END IF;
  UPDATE securepay_private.case_admin_successions SET status='withdrawn',resolved_at=clock_timestamp() WHERE request_id=r;
  RETURN jsonb_build_object('requestId',r,'status','withdrawn');
 END IF;
 PERFORM 1 FROM securepay_private.dispute_actors WHERE tenant_id=t AND actor_id=q.requested_by FOR UPDATE;
 PERFORM 1 FROM securepay_private.actor_person_registry WHERE tenant_id=t AND actor_id=q.requested_by FOR UPDATE;
 IF NOT securepay_private.succession_actor_valid(t,d,a,g.administrator_id) OR NOT securepay_private.succession_actor_valid(t,d,n,g.administrator_id)
 OR NOT securepay_private.succession_actor_valid(t,d,q.requested_by,g.administrator_id)
 OR NOT securepay_private.person_distinct(t,a,n) OR NOT securepay_private.person_distinct(t,a,q.requested_by) OR NOT securepay_private.person_distinct(t,n,q.requested_by)
 OR securepay_private.succession_snapshot(t,d,n,q.requested_by) IS DISTINCT FROM h THEN RETURN NULL; END IF;
 UPDATE securepay_private.case_admin_successions SET status='approved',approved_by=a,approval_reason=$7,resolved_at=clock_timestamp() WHERE request_id=r;
 UPDATE securepay_private.governed_cases SET administrator_id=n WHERE case_id=d AND tenant_id=t;
 -- Pending prior-admin reassessments must be reissued by the successor.
 UPDATE securepay_private.case_reassessments SET status='withdrawn',resolved_at=clock_timestamp() WHERE case_id=d AND status='pending';
 INSERT INTO securepay_private.dispute_events(event_id,case_id,actor_id,action,details,evidence_digest) VALUES(gen_random_uuid(),d,a,'governance_succession',reason,h);
 RETURN jsonb_build_object('requestId',r,'status','approved');
EXCEPTION WHEN unique_violation THEN RETURN NULL;
END $$;
CREATE FUNCTION securepay_private.succession_queue(t uuid,a uuid,expires bigint,sig text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE result jsonb;
BEGIN
 IF securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-admin-succession-queue-v1',t,a,expires),expires,sig) IS DISTINCT FROM 'administrator' THEN RETURN NULL; END IF;
 SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY q."caseId"),'[]'::jsonb) INTO result FROM (
 SELECT g.case_id AS "caseId",c.status AS "caseStatus",g.administrator_id AS "previousAdmin",
 s.request_id AS "requestId",s.nominee,s.reason,s.state_digest AS "stateDigest",coalesce(s.requested_by=a,false) AS "requestedByMe",
 coalesce(s.state_digest=securepay_private.succession_snapshot(t,g.case_id,s.nominee,s.requested_by),false) AS current
 FROM securepay_private.governed_cases g JOIN securepay_private.dispute_cases c ON c.case_id=g.case_id AND c.tenant_id=t
 JOIN securepay_private.dispute_actors x ON x.tenant_id=t AND x.actor_id=g.administrator_id AND NOT x.active
 LEFT JOIN securepay_private.case_admin_successions s ON s.case_id=g.case_id AND s.status='pending'
 WHERE g.tenant_id=t AND c.status<>'settled' AND securepay_private.succession_actor_valid(t,g.case_id,a,g.administrator_id) ORDER BY g.case_id LIMIT 101) q;
 IF jsonb_array_length(result)>100 THEN RAISE EXCEPTION 'Succession queue capacity exceeded'; END IF;
 RETURN result;
END $$;
ALTER FUNCTION securepay_private.distinct_from_succession(uuid,uuid,uuid) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.distinct_from_succession(uuid,uuid,uuid) FROM PUBLIC;
ALTER FUNCTION securepay_private.succession_snapshot(uuid,uuid,uuid,uuid) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.succession_snapshot(uuid,uuid,uuid,uuid) FROM PUBLIC;
ALTER FUNCTION securepay_private.succession_actor_valid(uuid,uuid,uuid,uuid) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.succession_actor_valid(uuid,uuid,uuid,uuid) FROM PUBLIC;
ALTER FUNCTION securepay_private.succession_action(uuid,uuid,uuid,uuid,uuid,text,text,text,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.succession_action(uuid,uuid,uuid,uuid,uuid,text,text,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.succession_action(uuid,uuid,uuid,uuid,uuid,text,text,text,bigint,text) TO securepay_dispute_admin_runtime;
ALTER FUNCTION securepay_private.succession_queue(uuid,uuid,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.succession_queue(uuid,uuid,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.succession_queue(uuid,uuid,bigint,text) TO securepay_dispute_admin_runtime;
CREATE OR REPLACE FUNCTION securepay_private.governance_eligible(t uuid,d uuid,a uuid,wanted text) RETURNS boolean
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM securepay_private.governed_cases g JOIN securepay_private.dispute_cases c ON c.case_id=g.case_id AND c.tenant_id=g.tenant_id
 JOIN securepay_private.dispute_actors x ON x.tenant_id=t AND x.actor_id=a AND x.role=wanted AND x.active
 JOIN securepay_private.case_governance_assignments s ON s.case_id=d AND s.tenant_id=t AND s.actor_id=a AND s.role=wanted AND s.revoked_at IS NULL
 WHERE g.tenant_id=t AND g.case_id=d AND securepay_private.person_distinct(t,a,c.customer_id) AND securepay_private.person_distinct(t,a,c.owner_id)
 AND securepay_private.person_distinct(t,a,g.administrator_id) AND (c.first_reviewer IS NULL OR a=c.first_reviewer OR securepay_private.person_distinct(t,a,c.first_reviewer))
 AND (c.final_reviewer IS NULL OR a=c.final_reviewer OR securepay_private.person_distinct(t,a,c.final_reviewer))
 AND securepay_private.distinct_from_succession(t,d,a)
 AND NOT EXISTS(SELECT 1 FROM securepay_private.case_reassessments rr WHERE rr.case_id=d AND rr.status='approved' AND NOT securepay_private.person_distinct(t,a,rr.approved_by))
 AND NOT EXISTS(SELECT 1 FROM securepay_private.case_conflicts k JOIN securepay_private.actor_person_registry b ON b.tenant_id=t AND b.actor_id=k.actor_id
 JOIN securepay_private.actor_person_registry me ON me.tenant_id=t AND me.actor_id=a AND me.person_digest=b.person_digest WHERE k.case_id=d))
$$;
CREATE OR REPLACE FUNCTION securepay_private.admin_case_action(t uuid,d uuid,a uuid,target uuid,op text,reason text,expires bigint,sig text) RETURNS boolean
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
  IF NOT FOUND OR NOT securepay_private.distinct_from_succession(t,d,target) OR NOT securepay_private.person_distinct(t,target,a) OR NOT securepay_private.person_distinct(t,target,c.customer_id) OR NOT securepay_private.person_distinct(t,target,c.owner_id)
  OR EXISTS(SELECT 1 FROM securepay_private.case_governance_assignments x WHERE x.case_id=d AND NOT securepay_private.person_distinct(t,target,x.actor_id))
  OR EXISTS(SELECT 1 FROM securepay_private.case_conflicts x WHERE x.case_id=d AND NOT securepay_private.person_distinct(t,target,x.actor_id))
  OR EXISTS(SELECT 1 FROM securepay_private.case_reassessments x WHERE x.case_id=d AND x.status='approved' AND NOT securepay_private.person_distinct(t,target,x.approved_by)) THEN RETURN false; END IF;
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
CREATE OR REPLACE FUNCTION securepay_private.recovery_people_independent(t uuid,d uuid,a uuid,b uuid) RETURNS boolean
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT securepay_private.person_distinct(t,a,b) AND securepay_private.distinct_from_succession(t,d,a) AND securepay_private.distinct_from_succession(t,d,b) AND EXISTS(SELECT 1 FROM securepay_private.dispute_cases c JOIN securepay_private.governed_cases g ON g.case_id=c.case_id WHERE c.case_id=d AND c.tenant_id=t
 AND securepay_private.person_distinct(t,a,c.customer_id) AND securepay_private.person_distinct(t,b,c.customer_id)
 AND securepay_private.person_distinct(t,a,c.owner_id) AND securepay_private.person_distinct(t,b,c.owner_id)
 AND securepay_private.person_distinct(t,a,g.administrator_id) AND securepay_private.person_distinct(t,b,g.administrator_id)
 AND NOT EXISTS(SELECT 1 FROM securepay_private.case_governance_assignments x WHERE x.case_id=d AND (NOT securepay_private.person_distinct(t,a,x.actor_id) OR NOT securepay_private.person_distinct(t,b,x.actor_id)))
 AND NOT EXISTS(SELECT 1 FROM securepay_private.case_reassessments x WHERE x.case_id=d AND x.status='approved' AND (NOT securepay_private.person_distinct(t,a,x.approved_by) OR NOT securepay_private.person_distinct(t,b,x.approved_by))))
$$;
CREATE OR REPLACE FUNCTION securepay_private.post_auth_start(r uuid,t uuid,d uuid,a uuid,u uuid,v uuid,w uuid,reason text,expires bigint,sig text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE mid uuid;st securepay_private.dispute_settlements%ROWTYPE;x uuid;wanted text;
BEGIN
 IF r IS NULL OR u IS NULL OR v IS NULL OR w IS NULL OR reason IS NULL OR length(btrim(reason)) NOT BETWEEN 10 AND 1000
 OR securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-post-auth-start-v1',r,t,d,a,u,v,w,encode(convert_to(reason,'UTF8'),'hex'),expires),expires,sig) IS DISTINCT FROM 'administrator' THEN RETURN false; END IF;
 SELECT milestone_id INTO mid FROM securepay_private.dispute_cases WHERE case_id=d AND tenant_id=t;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM 1 FROM public.securepay_milestones WHERE tenant_id=t AND id=mid AND status='disputed' FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM 1 FROM securepay_private.provider_funding WHERE tenant_id=t AND milestone_id=mid FOR UPDATE;
 PERFORM 1 FROM securepay_private.dispute_cases WHERE case_id=d AND tenant_id=t AND status='authorized' FOR UPDATE;
 IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM securepay_private.governed_cases WHERE case_id=d AND tenant_id=t AND administrator_id=a)
 OR NOT securepay_private.reassessment_admin_valid(t,d,a) THEN RETURN false; END IF;
 SELECT * INTO st FROM securepay_private.dispute_settlements WHERE case_id=d AND status IN ('authorized','submitted') FOR UPDATE;
 IF NOT FOUND OR securepay_private.governance_settlement_ok(t,d,st.authorizer) OR NOT securepay_private.verify_financial_journal(t,mid)
 OR NOT securepay_private.person_distinct(t,u,v) OR NOT securepay_private.person_distinct(t,u,w) OR NOT securepay_private.person_distinct(t,v,w)
 OR (SELECT count(*) FROM securepay_private.case_governance_assignments WHERE case_id=d)>17 THEN RETURN false; END IF;
 FOREACH x IN ARRAY ARRAY[u,v,w] LOOP
  wanted:=CASE WHEN x=w THEN 'settlement' ELSE 'reviewer' END;
  IF NOT EXISTS(SELECT 1 FROM securepay_private.dispute_actors WHERE tenant_id=t AND actor_id=x AND role=wanted AND active)
  OR NOT securepay_private.distinct_from_succession(t,d,x) OR NOT securepay_private.person_distinct(t,x,a)
  OR EXISTS(SELECT 1 FROM securepay_private.dispute_cases c WHERE c.case_id=d AND (NOT securepay_private.person_distinct(t,x,c.owner_id) OR NOT securepay_private.person_distinct(t,x,c.customer_id)))
  OR EXISTS(SELECT 1 FROM securepay_private.case_governance_assignments q WHERE q.case_id=d AND NOT securepay_private.person_distinct(t,x,q.actor_id))
  OR EXISTS(SELECT 1 FROM securepay_private.case_conflicts q WHERE q.case_id=d AND NOT securepay_private.person_distinct(t,x,q.actor_id))
  OR EXISTS(SELECT 1 FROM securepay_private.case_reassessments q WHERE q.case_id=d AND q.status='approved' AND NOT securepay_private.person_distinct(t,x,q.approved_by)) THEN RETURN false; END IF;
 END LOOP;
 INSERT INTO securepay_private.post_auth_reviews(review_id,tenant_id,case_id,settlement_id,administrator_id,reviewer_one,reviewer_two,authorizer_id,reason) VALUES(r,t,d,st.settlement_id,a,u,v,w,reason);
 UPDATE securepay_private.case_governance_assignments SET revoked_at=clock_timestamp() WHERE case_id=d AND revoked_at IS NULL;
 FOREACH x IN ARRAY ARRAY[u,v,w] LOOP
  wanted:=CASE WHEN x=w THEN 'settlement' ELSE 'reviewer' END;
  INSERT INTO securepay_private.case_governance_assignments(case_id,tenant_id,actor_id,role,assigned_by,reason) VALUES(d,t,x,wanted,a,reason);
  IF wanted='reviewer' THEN INSERT INTO securepay_private.dispute_photo_reviewers(case_id,tenant_id,reviewer_id) VALUES(d,t,x) ON CONFLICT DO NOTHING; END IF;
 END LOOP;
 INSERT INTO securepay_private.dispute_events(event_id,case_id,actor_id,action,details) VALUES(gen_random_uuid(),d,a,'post_auth_review',reason);
 RETURN true;
EXCEPTION WHEN unique_violation THEN RETURN false;
END $$;
COMMIT;

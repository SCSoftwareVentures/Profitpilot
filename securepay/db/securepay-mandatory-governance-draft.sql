-- Mandatory case governance and pre-authorization reassessment. Sandbox only.
BEGIN;
CREATE TABLE securepay_private.case_reassessments(
 request_id uuid PRIMARY KEY,case_id uuid NOT NULL REFERENCES securepay_private.governed_cases(case_id),tenant_id uuid NOT NULL,
 requested_by uuid NOT NULL,approved_by uuid,reason text NOT NULL CHECK(length(btrim(reason)) BETWEEN 10 AND 1000),
 state_digest text NOT NULL CHECK(state_digest ~ '^[a-f0-9]{64}$'),prior_case jsonb NOT NULL,
 status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','withdrawn')),
 requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),resolved_at timestamptz,
 CHECK((status='approved')=(approved_by IS NOT NULL)),CHECK((status='pending')=(resolved_at IS NULL)),CHECK(requested_by<>approved_by)
);
ALTER TABLE securepay_private.case_reassessments OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.case_reassessments FROM PUBLIC,securepay_dispute_admin_runtime,securepay_reviewer_runtime,securepay_settlement_dashboard_runtime,securepay_dispute_runtime;
CREATE UNIQUE INDEX sp_reassessment_pending ON securepay_private.case_reassessments(case_id) WHERE status='pending';
CREATE TRIGGER sp_chain_reassessment AFTER INSERT OR UPDATE OR DELETE ON securepay_private.case_reassessments FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
CREATE OR REPLACE FUNCTION securepay_private.reviewer_assigned(t uuid,d uuid,a uuid) RETURNS boolean
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM securepay_private.dispute_photo_reviewers r JOIN securepay_private.dispute_actors x ON x.tenant_id=r.tenant_id AND x.actor_id=r.reviewer_id
 JOIN securepay_private.dispute_cases c ON c.case_id=r.case_id AND c.tenant_id=r.tenant_id
 WHERE r.tenant_id=t AND r.case_id=d AND r.reviewer_id=a AND x.active AND x.role='reviewer' AND a NOT IN(c.customer_id,c.owner_id))
 AND securepay_private.governance_cleared(t,d,a,'reviewer')
$$;
CREATE OR REPLACE FUNCTION securepay_private.governance_settlement_ok(t uuid,d uuid,a uuid) RETURNS boolean
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM securepay_private.dispute_cases c WHERE c.case_id=d AND c.tenant_id=t
 AND securepay_private.governance_cleared(t,d,a,'settlement') AND securepay_private.governance_cleared(t,d,c.first_reviewer,'reviewer')
 AND securepay_private.governance_cleared(t,d,c.final_reviewer,'reviewer') AND securepay_private.person_distinct(t,c.first_reviewer,c.final_reviewer)
 AND securepay_private.person_distinct(t,a,c.first_reviewer) AND securepay_private.person_distinct(t,a,c.final_reviewer))
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
  IF NOT FOUND OR NOT securepay_private.person_distinct(t,target,a) OR NOT securepay_private.person_distinct(t,target,c.customer_id) OR NOT securepay_private.person_distinct(t,target,c.owner_id)
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
CREATE OR REPLACE FUNCTION securepay_private.governance_eligible(t uuid,d uuid,a uuid,wanted text) RETURNS boolean
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM securepay_private.governed_cases g JOIN securepay_private.dispute_cases c ON c.case_id=g.case_id AND c.tenant_id=g.tenant_id
 JOIN securepay_private.dispute_actors x ON x.tenant_id=t AND x.actor_id=a AND x.role=wanted AND x.active
 JOIN securepay_private.case_governance_assignments s ON s.case_id=d AND s.tenant_id=t AND s.actor_id=a AND s.role=wanted AND s.revoked_at IS NULL
 WHERE g.tenant_id=t AND g.case_id=d AND securepay_private.person_distinct(t,a,c.customer_id) AND securepay_private.person_distinct(t,a,c.owner_id)
 AND securepay_private.person_distinct(t,a,g.administrator_id) AND (c.first_reviewer IS NULL OR a=c.first_reviewer OR securepay_private.person_distinct(t,a,c.first_reviewer))
 AND (c.final_reviewer IS NULL OR a=c.final_reviewer OR securepay_private.person_distinct(t,a,c.final_reviewer))
 AND NOT EXISTS(SELECT 1 FROM securepay_private.case_reassessments rr WHERE rr.case_id=d AND rr.status='approved' AND NOT securepay_private.person_distinct(t,a,rr.approved_by))
 AND NOT EXISTS(SELECT 1 FROM securepay_private.case_conflicts k JOIN securepay_private.actor_person_registry b ON b.tenant_id=t AND b.actor_id=k.actor_id
 JOIN securepay_private.actor_person_registry me ON me.tenant_id=t AND me.actor_id=a AND me.person_digest=b.person_digest WHERE k.case_id=d))
$$;
CREATE OR REPLACE FUNCTION securepay_private.dispute_action(e uuid,t uuid,m uuid,d uuid,a uuid,op text,details text,digest text,payout bigint,refund bigint,expires bigint,sig text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF op IN ('decide','finalize') THEN RETURN false; END IF;
 IF op='ack' AND EXISTS(SELECT 1 FROM securepay_private.case_reassessments WHERE case_id=d AND status='approved') THEN
  IF securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-dispute-v1',e,t,m,d,a,op,encode(convert_to(details,'UTF8'),'hex'),coalesce(digest,'-'),coalesce(payout::text,'-'),coalesce(refund::text,'-'),expires),expires,sig) NOT IN ('customer','owner') THEN RETURN false; END IF;
  PERFORM 1 FROM public.securepay_milestones WHERE tenant_id=t AND id=m FOR UPDATE;
  IF digest IS NULL OR digest IS DISTINCT FROM (SELECT evidence_digest FROM securepay_private.dispute_events WHERE case_id=d AND action='decide' ORDER BY occurred_at DESC,event_id DESC LIMIT 1) THEN RETURN false; END IF;
 END IF;
 RETURN securepay_private.dispute_action_internal(e,t,m,d,a,op,details,digest,payout,refund,expires,sig);
END $$;
CREATE OR REPLACE FUNCTION securepay_private.authorize_settlement(s uuid,t uuid,m uuid,d uuid,a uuid,payout bigint,refund bigint,expires bigint,sig text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 RETURN false;
END $;
CREATE OR REPLACE FUNCTION securepay_private.payer_ack_negotiated(t uuid,z uuid,v uuid,e uuid,decision uuid,payout bigint,refund bigint) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c uuid;o securepay_private.funded_cancellation_offers%ROWTYPE;d securepay_private.dispute_cases%ROWTYPE;
BEGIN
 c:=securepay_private.current_payer(t);
 IF c IS NULL OR e IS NULL OR decision IS NULL OR payout IS NULL OR refund IS NULL THEN RETURN false; END IF;
 SELECT * INTO o FROM securepay_private.funded_cancellation_offers WHERE tenant_id=t AND plan_id=z AND offer_id=v AND customer_id=c AND status='accepted';
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM 1 FROM public.securepay_milestones WHERE tenant_id=t AND id=o.milestone_id AND status='disputed' FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO d FROM securepay_private.dispute_cases WHERE case_id=o.case_id AND tenant_id=t AND customer_id=c AND status='decided' FOR UPDATE;
 IF NOT FOUND OR decision IS DISTINCT FROM (SELECT event_id FROM securepay_private.dispute_events WHERE case_id=d.case_id AND action='decide' ORDER BY occurred_at DESC,event_id DESC LIMIT 1) OR d.customer_ack OR d.payout_cents<>payout OR d.refund_cents<>refund OR NOT EXISTS(SELECT 1 FROM securepay_private.dispute_events WHERE case_id=d.case_id AND event_id=decision AND action='decide' AND payout_cents=payout AND refund_cents=refund) THEN RETURN false; END IF;
 UPDATE securepay_private.dispute_cases SET customer_ack=true WHERE case_id=d.case_id;
 INSERT INTO securepay_private.dispute_events(event_id,case_id,actor_id,action,details,payout_cents,refund_cents)
 VALUES(e,d.case_id,c,'ack','Customer acknowledged exact reasoned provisional decision',payout,refund);
 RETURN true;
EXCEPTION WHEN unique_violation THEN RETURN false;
END $$;
CREATE OR REPLACE FUNCTION securepay_private.owner_ack_negotiated(t uuid,z uuid,v uuid,e uuid,decision uuid,a uuid,payout bigint,refund bigint,expires bigint,sig text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE o securepay_private.funded_cancellation_offers%ROWTYPE;d securepay_private.dispute_cases%ROWTYPE;
BEGIN
 IF t IS NULL OR z IS NULL OR v IS NULL OR e IS NULL OR decision IS NULL OR a IS NULL OR payout IS NULL OR refund IS NULL OR securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-negotiated-ack-v1',t,z,v,e,decision,a,payout,refund,expires),expires,sig) IS DISTINCT FROM 'owner' THEN RETURN false; END IF;
 SELECT * INTO o FROM securepay_private.funded_cancellation_offers WHERE tenant_id=t AND plan_id=z AND offer_id=v AND owner_id=a AND status='accepted';
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM 1 FROM public.securepay_milestones WHERE tenant_id=t AND id=o.milestone_id AND status='disputed' FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO d FROM securepay_private.dispute_cases WHERE case_id=o.case_id AND tenant_id=t AND owner_id=a AND status='decided' FOR UPDATE;
 IF NOT FOUND OR decision IS DISTINCT FROM (SELECT event_id FROM securepay_private.dispute_events WHERE case_id=d.case_id AND action='decide' ORDER BY occurred_at DESC,event_id DESC LIMIT 1) OR d.owner_ack OR d.payout_cents<>payout OR d.refund_cents<>refund OR NOT EXISTS(SELECT 1 FROM securepay_private.dispute_events WHERE case_id=d.case_id AND event_id=decision AND action='decide' AND payout_cents=payout AND refund_cents=refund) THEN RETURN false; END IF;
 UPDATE securepay_private.dispute_cases SET owner_ack=true WHERE case_id=d.case_id;
 INSERT INTO securepay_private.dispute_events(event_id,case_id,actor_id,action,details,payout_cents,refund_cents)
 VALUES(e,d.case_id,a,'ack','Owner acknowledged exact reasoned provisional decision',payout,refund);
 RETURN true;
EXCEPTION WHEN unique_violation THEN RETURN false;
END $$;
CREATE OR REPLACE FUNCTION securepay_private.payer_appeal_negotiated(t uuid,z uuid,v uuid,e uuid,decision uuid,reason text,digest text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c uuid;o securepay_private.funded_cancellation_offers%ROWTYPE;d securepay_private.dispute_cases%ROWTYPE;
BEGIN
 c:=securepay_private.current_payer(t);
 IF c IS NULL OR e IS NULL OR decision IS NULL OR reason IS NULL OR length(btrim(reason)) NOT BETWEEN 10 AND 2000 OR digest IS NULL OR digest !~ '^[a-f0-9]{64}$' THEN RETURN false; END IF;
 SELECT * INTO o FROM securepay_private.funded_cancellation_offers WHERE tenant_id=t AND plan_id=z AND offer_id=v AND customer_id=c AND status='accepted';
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM 1 FROM public.securepay_milestones WHERE tenant_id=t AND id=o.milestone_id AND status='disputed' FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO d FROM securepay_private.dispute_cases WHERE case_id=o.case_id AND tenant_id=t AND customer_id=c AND status='decided' FOR UPDATE;
 IF NOT FOUND OR decision IS DISTINCT FROM (SELECT event_id FROM securepay_private.dispute_events WHERE case_id=d.case_id AND action='decide' ORDER BY occurred_at DESC,event_id DESC LIMIT 1) OR NOT EXISTS(SELECT 1 FROM securepay_private.dispute_events WHERE case_id=d.case_id AND event_id=decision AND action='decide') THEN RETURN false; END IF;
 UPDATE securepay_private.dispute_cases SET status='appealed',customer_appeal_evidence=true,owner_appeal_evidence=false WHERE case_id=d.case_id;
 INSERT INTO securepay_private.dispute_events(event_id,case_id,actor_id,action,details,evidence_digest) VALUES(e,d.case_id,c,'appeal',reason,digest);
 RETURN true;
EXCEPTION WHEN unique_violation THEN RETURN false;
END $$;
CREATE FUNCTION securepay_private.reassessment_snapshot(t uuid,d uuid) RETURNS jsonb
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('case',to_jsonb(c),'funding',to_jsonb(f),'assignments',
 (SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY x.actor_id),'[]'::jsonb) FROM securepay_private.case_governance_assignments x WHERE x.case_id=d),
 'conflicts',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY x.actor_id),'[]'::jsonb) FROM securepay_private.case_conflicts x WHERE x.case_id=d),
 'events',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY x.occurred_at,x.event_id),'[]'::jsonb) FROM securepay_private.dispute_events x WHERE x.case_id=d))
 FROM securepay_private.dispute_cases c JOIN securepay_private.provider_funding f ON f.tenant_id=c.tenant_id AND f.milestone_id=c.milestone_id
 WHERE c.tenant_id=t AND c.case_id=d AND c.status IN ('decided','appealed','final')
 AND NOT EXISTS(SELECT 1 FROM securepay_private.dispute_settlements WHERE case_id=d)
 AND (NOT securepay_private.governance_cleared(t,d,c.first_reviewer,'reviewer') OR (c.final_reviewer IS NOT NULL AND NOT securepay_private.governance_cleared(t,d,c.final_reviewer,'reviewer')))
 AND f.status IN ('funded','held') AND securepay_private.verify_financial_journal(t,c.milestone_id)
 AND (SELECT remaining_cents=f.amount_cents FROM securepay_private.financial_balance(t,c.milestone_id))
$$;
CREATE FUNCTION securepay_private.reassessment_admin_valid(t uuid,d uuid,a uuid) RETURNS boolean
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM securepay_private.dispute_cases c JOIN securepay_private.dispute_actors x ON x.tenant_id=t AND x.actor_id=a AND x.role='administrator' AND x.active WHERE c.tenant_id=t AND c.case_id=d
 AND securepay_private.person_distinct(t,a,c.owner_id) AND securepay_private.person_distinct(t,a,c.customer_id)
 AND NOT EXISTS(SELECT 1 FROM securepay_private.case_governance_assignments s WHERE s.case_id=d AND NOT securepay_private.person_distinct(t,a,s.actor_id)))
$$;
CREATE FUNCTION securepay_private.reassessment_action(rid uuid,t uuid,d uuid,a uuid,op text,reason text,expected text,expires bigint,sig text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE mid uuid;g securepay_private.governed_cases%ROWTYPE;r securepay_private.case_reassessments%ROWTYPE;s jsonb;h text;
BEGIN
 IF rid IS NULL OR t IS NULL OR d IS NULL OR a IS NULL OR op IS NULL OR op NOT IN ('request','approve','withdraw') OR reason IS NULL OR length(btrim(reason)) NOT BETWEEN 10 AND 1000
 OR (op='request')<>(expected IS NULL) OR (expected IS NOT NULL AND expected !~ '^[a-f0-9]{64}$')
 OR securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-reassess-v1',rid,t,d,a,op,encode(convert_to(reason,'UTF8'),'hex'),coalesce(expected,'-'),expires),expires,sig) IS DISTINCT FROM 'administrator' THEN RETURN NULL; END IF;
 SELECT milestone_id INTO mid FROM securepay_private.dispute_cases WHERE case_id=d AND tenant_id=t;
 IF NOT FOUND THEN RETURN NULL; END IF;
 PERFORM 1 FROM public.securepay_milestones WHERE tenant_id=t AND id=mid AND status='disputed' FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL; END IF;
 PERFORM 1 FROM securepay_private.provider_funding WHERE tenant_id=t AND milestone_id=mid FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL; END IF;
 PERFORM 1 FROM securepay_private.dispute_cases WHERE tenant_id=t AND case_id=d FOR UPDATE;
 SELECT * INTO g FROM securepay_private.governed_cases WHERE tenant_id=t AND case_id=d;
 IF NOT FOUND OR NOT securepay_private.reassessment_admin_valid(t,d,a) THEN RETURN NULL; END IF;
 IF op='request' THEN
  IF a<>g.administrator_id OR (SELECT count(*) FROM securepay_private.case_reassessments WHERE case_id=d)>=5 THEN RETURN NULL; END IF;
  s:=securepay_private.reassessment_snapshot(t,d);
  IF s IS NULL OR jsonb_array_length(s->'events')>200 THEN RETURN NULL; END IF;
  h:=encode(public.digest(convert_to(s::text,'UTF8'),'sha256'),'hex');
  INSERT INTO securepay_private.case_reassessments(request_id,tenant_id,case_id,requested_by,reason,state_digest,prior_case) VALUES(rid,t,d,a,reason,h,s);
  RETURN jsonb_build_object('requestId',rid,'stateDigest',h,'status','pending');
 END IF;
 SELECT * INTO r FROM securepay_private.case_reassessments WHERE request_id=rid AND tenant_id=t AND case_id=d AND status='pending' FOR UPDATE;
 IF NOT FOUND OR expected<>r.state_digest THEN RETURN NULL; END IF;
 IF op='withdraw' THEN
  IF a<>r.requested_by THEN RETURN NULL; END IF;
  UPDATE securepay_private.case_reassessments SET status='withdrawn',resolved_at=clock_timestamp() WHERE request_id=rid;
  RETURN jsonb_build_object('requestId',rid,'status','withdrawn');
 END IF;
 IF NOT securepay_private.person_distinct(t,a,r.requested_by) OR NOT securepay_private.reassessment_admin_valid(t,d,r.requested_by) THEN RETURN NULL; END IF;
 s:=securepay_private.reassessment_snapshot(t,d);
 IF s IS NULL OR encode(public.digest(convert_to(s::text,'UTF8'),'sha256'),'hex')<>r.state_digest THEN RETURN NULL; END IF;
 UPDATE securepay_private.case_reassessments SET status='approved',approved_by=a,resolved_at=clock_timestamp() WHERE request_id=rid;
 UPDATE securepay_private.case_governance_assignments SET revoked_at=clock_timestamp() WHERE case_id=d AND revoked_at IS NULL;
 UPDATE securepay_private.dispute_cases SET status='open',first_reviewer=NULL,final_reviewer=NULL,payout_cents=NULL,refund_cents=NULL,customer_ack=false,owner_ack=false,customer_appeal_evidence=false,owner_appeal_evidence=false WHERE case_id=d;
 INSERT INTO securepay_private.dispute_events(event_id,case_id,actor_id,action,details,evidence_digest) VALUES(gen_random_uuid(),d,a,'governance_reassessment',reason,r.state_digest);
 RETURN jsonb_build_object('requestId',rid,'status','approved');
EXCEPTION WHEN unique_violation THEN RETURN NULL;
END $$;
CREATE FUNCTION securepay_private.reassessment_queue(t uuid,a uuid,expires bigint,sig text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE result jsonb;
BEGIN
 IF securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-reassess-queue-v1',t,a,expires),expires,sig) IS DISTINCT FROM 'administrator' THEN RETURN NULL; END IF;
 SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY q."requestId"),'[]'::jsonb) INTO result FROM (
 SELECT r.request_id AS "requestId",r.case_id AS "caseId",r.reason,r.state_digest AS "stateDigest",r.status,
 r.requested_by=a AS "requestedByMe",(r.prior_case->'case'->>'status') AS "priorStatus",
 (r.prior_case->'case'->>'payout_cents') AS "priorPayoutCents",(r.prior_case->'case'->>'refund_cents') AS "priorRefundCents",
 coalesce(r.state_digest=encode(public.digest(convert_to(securepay_private.reassessment_snapshot(t,r.case_id)::text,'UTF8'),'sha256'),'hex'),false) AS current
 FROM securepay_private.case_reassessments r WHERE r.tenant_id=t AND r.status='pending' AND securepay_private.reassessment_admin_valid(t,r.case_id,a) ORDER BY r.request_id LIMIT 101) q;
 IF jsonb_array_length(result)>100 THEN RAISE EXCEPTION 'Reassessment queue capacity exceeded'; END IF;
 RETURN result;
END $$;
CREATE FUNCTION securepay_private.self_report_conflict(t uuid,d uuid,a uuid,reason text,expires bigint,sig text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE wanted text;mid uuid;
BEGIN
 IF reason IS NULL OR length(btrim(reason)) NOT BETWEEN 10 AND 1000 THEN RETURN false; END IF;
 wanted:=securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-self-conflict-v1',t,d,a,encode(convert_to(reason,'UTF8'),'hex'),expires),expires,sig);
 IF wanted IS NULL OR wanted NOT IN ('reviewer','settlement') THEN RETURN false; END IF;
 SELECT milestone_id INTO mid FROM securepay_private.dispute_cases WHERE tenant_id=t AND case_id=d;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM 1 FROM public.securepay_milestones WHERE tenant_id=t AND id=mid FOR UPDATE;
 PERFORM 1 FROM securepay_private.dispute_cases WHERE tenant_id=t AND case_id=d FOR UPDATE;
 IF NOT EXISTS(SELECT 1 FROM securepay_private.case_governance_assignments WHERE tenant_id=t AND case_id=d AND actor_id=a AND role=wanted) THEN RETURN false; END IF;
 INSERT INTO securepay_private.case_conflicts(case_id,tenant_id,actor_id,reported_by,reason) VALUES(d,t,a,a,reason);
 UPDATE securepay_private.case_governance_assignments SET revoked_at=coalesce(revoked_at,clock_timestamp()) WHERE case_id=d AND actor_id=a;
 INSERT INTO securepay_private.dispute_events(event_id,case_id,actor_id,action,details) VALUES(gen_random_uuid(),d,a,'governance_self_conflict',reason);
 RETURN true;
EXCEPTION WHEN unique_violation THEN RETURN false;
END $$;
ALTER FUNCTION securepay_private.reassessment_snapshot(uuid,uuid) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.reassessment_snapshot(uuid,uuid) FROM PUBLIC;
ALTER FUNCTION securepay_private.reassessment_admin_valid(uuid,uuid,uuid) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.reassessment_admin_valid(uuid,uuid,uuid) FROM PUBLIC;
ALTER FUNCTION securepay_private.reassessment_action(uuid,uuid,uuid,uuid,text,text,text,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.reassessment_action(uuid,uuid,uuid,uuid,text,text,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.reassessment_action(uuid,uuid,uuid,uuid,text,text,text,bigint,text) TO securepay_dispute_admin_runtime;
ALTER FUNCTION securepay_private.reassessment_queue(uuid,uuid,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.reassessment_queue(uuid,uuid,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.reassessment_queue(uuid,uuid,bigint,text) TO securepay_dispute_admin_runtime;
ALTER FUNCTION securepay_private.self_report_conflict(uuid,uuid,uuid,text,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.self_report_conflict(uuid,uuid,uuid,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.self_report_conflict(uuid,uuid,uuid,text,bigint,text) TO securepay_reviewer_runtime,securepay_settlement_dashboard_runtime;
COMMIT;

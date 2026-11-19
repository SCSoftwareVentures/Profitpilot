-- Post-authorization review can reaffirm an exact historical allocation only.
BEGIN;
CREATE TABLE securepay_private.post_auth_reviews(
 review_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,case_id uuid NOT NULL UNIQUE REFERENCES securepay_private.governed_cases(case_id),
 settlement_id uuid NOT NULL UNIQUE REFERENCES securepay_private.dispute_settlements(settlement_id),
 administrator_id uuid NOT NULL,reviewer_one uuid NOT NULL,reviewer_two uuid NOT NULL,authorizer_id uuid NOT NULL,
 reason text NOT NULL CHECK(length(btrim(reason)) BETWEEN 10 AND 1000),status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','reaffirmed','stopped')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),resolved_at timestamptz,
 CHECK((status='pending')=(resolved_at IS NULL))
);
CREATE TABLE securepay_private.post_auth_votes(
 review_id uuid NOT NULL REFERENCES securepay_private.post_auth_reviews(review_id),tenant_id uuid NOT NULL,case_id uuid NOT NULL,
 actor_id uuid NOT NULL,stage text NOT NULL CHECK(stage IN ('reviewer','authorizer')),outcome text NOT NULL CHECK(outcome IN ('reaffirm','stop')),
 state_digest text NOT NULL CHECK(state_digest ~ '^[a-f0-9]{64}$'),reason text NOT NULL CHECK(length(btrim(reason)) BETWEEN 10 AND 4000),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(review_id,actor_id,state_digest,outcome)
);
ALTER TABLE securepay_private.post_auth_reviews OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.post_auth_reviews FROM PUBLIC,securepay_dispute_admin_runtime,securepay_reviewer_runtime,securepay_settlement_dashboard_runtime,securepay_dispute_runtime,securepay_settlement_runtime,securepay_provider_runtime;
CREATE TRIGGER sp_chain_post_auth_reviews AFTER INSERT OR UPDATE OR DELETE ON securepay_private.post_auth_reviews FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
ALTER TABLE securepay_private.post_auth_votes OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.post_auth_votes FROM PUBLIC,securepay_dispute_admin_runtime,securepay_reviewer_runtime,securepay_settlement_dashboard_runtime,securepay_dispute_runtime,securepay_settlement_runtime,securepay_provider_runtime;
CREATE TRIGGER sp_chain_post_auth_votes AFTER INSERT OR UPDATE OR DELETE ON securepay_private.post_auth_votes FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
CREATE FUNCTION securepay_private.post_auth_panel_valid(t uuid,d uuid,r uuid) RETURNS boolean
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM securepay_private.post_auth_reviews p WHERE p.tenant_id=t AND p.case_id=d AND p.review_id=r
 AND securepay_private.governance_cleared(t,d,p.reviewer_one,'reviewer') AND securepay_private.governance_cleared(t,d,p.reviewer_two,'reviewer') AND securepay_private.governance_cleared(t,d,p.authorizer_id,'settlement')
 AND securepay_private.person_distinct(t,p.reviewer_one,p.reviewer_two) AND securepay_private.person_distinct(t,p.reviewer_one,p.authorizer_id) AND securepay_private.person_distinct(t,p.reviewer_two,p.authorizer_id))
$$;
CREATE FUNCTION securepay_private.settlement_dispatch_cleared(t uuid,d uuid,s uuid,a uuid) RETURNS boolean
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT CASE WHEN EXISTS(SELECT 1 FROM securepay_private.post_auth_reviews WHERE case_id=d)
 THEN EXISTS(SELECT 1 FROM securepay_private.post_auth_reviews p WHERE p.tenant_id=t AND p.case_id=d AND p.settlement_id=s AND p.status='reaffirmed' AND securepay_private.post_auth_panel_valid(t,d,p.review_id))
 ELSE securepay_private.governance_settlement_ok(t,d,a) END
$$;
CREATE FUNCTION securepay_private.current_settlement_authorizer(t uuid,d uuid,s uuid,a uuid) RETURNS boolean
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT CASE WHEN EXISTS(SELECT 1 FROM securepay_private.post_auth_reviews WHERE case_id=d)
 THEN EXISTS(SELECT 1 FROM securepay_private.post_auth_reviews p WHERE p.tenant_id=t AND p.case_id=d AND p.settlement_id=s AND p.authorizer_id=a AND p.status='reaffirmed' AND securepay_private.post_auth_panel_valid(t,d,p.review_id))
 ELSE EXISTS(SELECT 1 FROM securepay_private.dispute_settlements st WHERE st.case_id=d AND st.settlement_id=s AND st.authorizer=a AND securepay_private.governance_settlement_ok(t,d,a)) END
$$;
CREATE FUNCTION securepay_private.recovery_people_independent(t uuid,d uuid,a uuid,b uuid) RETURNS boolean
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT securepay_private.person_distinct(t,a,b) AND EXISTS(SELECT 1 FROM securepay_private.dispute_cases c JOIN securepay_private.governed_cases g ON g.case_id=c.case_id WHERE c.case_id=d AND c.tenant_id=t
 AND securepay_private.person_distinct(t,a,c.customer_id) AND securepay_private.person_distinct(t,b,c.customer_id)
 AND securepay_private.person_distinct(t,a,c.owner_id) AND securepay_private.person_distinct(t,b,c.owner_id)
 AND securepay_private.person_distinct(t,a,g.administrator_id) AND securepay_private.person_distinct(t,b,g.administrator_id)
 AND NOT EXISTS(SELECT 1 FROM securepay_private.case_governance_assignments x WHERE x.case_id=d AND (NOT securepay_private.person_distinct(t,a,x.actor_id) OR NOT securepay_private.person_distinct(t,b,x.actor_id)))
 AND NOT EXISTS(SELECT 1 FROM securepay_private.case_reassessments x WHERE x.case_id=d AND x.status='approved' AND (NOT securepay_private.person_distinct(t,a,x.approved_by) OR NOT securepay_private.person_distinct(t,b,x.approved_by))))
$$;
CREATE FUNCTION securepay_private.post_auth_start(r uuid,t uuid,d uuid,a uuid,u uuid,v uuid,w uuid,reason text,expires bigint,sig text) RETURNS boolean
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
  OR NOT securepay_private.person_distinct(t,x,a)
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
CREATE FUNCTION securepay_private.post_auth_snapshot(t uuid,d uuid) RETURNS jsonb
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('reviewId',p.review_id,'caseId',d,'settlementId',p.settlement_id,'status',p.status,'reason',p.reason,
 'payoutCents',st.payout_cents::text,'refundCents',st.refund_cents::text,'confirmedPayoutCents',b.payout_cents::text,'confirmedRefundCents',b.refund_cents::text,'remainingCents',b.remaining_cents::text,
 'fundingStatus',f.status,'caseStatus',c.status,'providerState',securepay_private.recovery_state(p.settlement_id,t,c.milestone_id,d),
 'journalVerified',securepay_private.verify_financial_journal(t,c.milestone_id),'panelCleared',securepay_private.post_auth_panel_valid(t,d,p.review_id),
 'safeToReaffirm',f.status='funded' AND c.status='authorized' AND securepay_private.verify_financial_journal(t,c.milestone_id) AND NOT EXISTS(SELECT 1 FROM securepay_private.settlement_legs x WHERE x.settlement_id=p.settlement_id AND x.status IN ('submitted','unknown'))
 AND NOT EXISTS(SELECT 1 FROM securepay_private.provider_reconciliation x WHERE x.tenant_id=t AND x.milestone_id=c.milestone_id AND x.resolved_at IS NULL)
 AND NOT EXISTS(SELECT 1 FROM securepay_private.settlement_leg_conflicts x WHERE x.case_id=d AND x.resolved_at IS NULL),
 'legs',(SELECT coalesce(jsonb_agg(jsonb_build_object('kind',l.kind,'amountCents',l.amount_cents::text,'status',l.status,'attempts',l.attempts) ORDER BY l.kind),'[]'::jsonb) FROM securepay_private.settlement_legs l WHERE l.settlement_id=p.settlement_id),
 'events',(SELECT coalesce(jsonb_agg(jsonb_build_object('eventId',e.event_id,'action',e.action,'details',e.details,'digest',e.evidence_digest) ORDER BY e.occurred_at,e.event_id),'[]'::jsonb) FROM securepay_private.dispute_events e WHERE e.case_id=d),
 'photos',(SELECT coalesce(jsonb_agg(jsonb_build_object('photoId',x.photo_id,'digest',x.digest,'purged',x.purged_at IS NOT NULL,'source','dispute') ORDER BY x.photo_id),'[]'::jsonb) FROM securepay_private.dispute_photos x WHERE x.case_id=d),
 'linkedPhotos',(SELECT coalesce(jsonb_agg(jsonb_build_object('photoId',x.photo_id,'digest',x.digest,'purged',x.purged_at IS NOT NULL,'source','completion') ORDER BY x.photo_id),'[]'::jsonb) FROM securepay_private.work_dispute_links l JOIN securepay_private.work_photos x ON x.completion_id=l.completion_id WHERE l.case_id=d AND l.tenant_id=t))
 FROM securepay_private.post_auth_reviews p JOIN securepay_private.dispute_cases c ON c.case_id=p.case_id JOIN securepay_private.dispute_settlements st ON st.settlement_id=p.settlement_id
 JOIN securepay_private.provider_funding f ON f.tenant_id=t AND f.milestone_id=c.milestone_id CROSS JOIN LATERAL securepay_private.financial_balance(t,c.milestone_id) b WHERE p.tenant_id=t AND p.case_id=d
$$;
CREATE FUNCTION securepay_private.post_auth_read(t uuid,d uuid,a uuid,expires bigint,sig text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE role_name text;s jsonb;h text;mid uuid;
BEGIN
 role_name:=securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-post-auth-read-v1',t,d,a,expires),expires,sig);
 IF role_name IS NULL OR role_name NOT IN ('reviewer','settlement') OR NOT securepay_private.governance_cleared(t,d,a,role_name) THEN RETURN NULL; END IF;
 IF NOT EXISTS(SELECT 1 FROM securepay_private.post_auth_reviews p WHERE p.tenant_id=t AND p.case_id=d AND a IN(p.reviewer_one,p.reviewer_two,p.authorizer_id)) THEN RETURN NULL; END IF;
 SELECT milestone_id INTO mid FROM securepay_private.dispute_cases WHERE tenant_id=t AND case_id=d;
 PERFORM 1 FROM public.securepay_milestones WHERE tenant_id=t AND id=mid FOR UPDATE;
 PERFORM 1 FROM securepay_private.provider_funding WHERE tenant_id=t AND milestone_id=mid FOR UPDATE;
 PERFORM 1 FROM securepay_private.dispute_cases WHERE tenant_id=t AND case_id=d FOR UPDATE;
 IF NOT securepay_private.governance_cleared(t,d,a,role_name) THEN RETURN NULL; END IF;
 s:=securepay_private.post_auth_snapshot(t,d);
 IF s IS NULL OR jsonb_array_length(s->'events')>200 THEN RETURN NULL; END IF;
 h:=encode(public.digest(convert_to(s::text,'UTF8'),'sha256'),'hex');
 PERFORM securepay_private.append_audit_chain(t,'post_auth_review','READ',encode(public.digest(convert_to(concat_ws(':',d,a,h),'UTF8'),'sha256'),'hex'));
 RETURN jsonb_build_object('review',s,'stateDigest',h,'votes',(SELECT coalesce(jsonb_agg(jsonb_build_object('stage',v.stage,'outcome',v.outcome,'reason',v.reason,'mine',v.actor_id=a) ORDER BY v.recorded_at,v.actor_id),'[]'::jsonb) FROM securepay_private.post_auth_votes v WHERE v.review_id=(s->>'reviewId')::uuid AND v.state_digest=h));
END $$;
CREATE FUNCTION securepay_private.post_auth_vote(t uuid,d uuid,a uuid,r uuid,outcome text,reason text,h text,expires bigint,sig text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE role_name text;mid uuid;s jsonb;p securepay_private.post_auth_reviews%ROWTYPE;
BEGIN
 IF r IS NULL OR outcome IS NULL OR outcome NOT IN ('reaffirm','stop') OR reason IS NULL OR length(btrim(reason)) NOT BETWEEN 10 AND 4000 OR h IS NULL OR h !~ '^[a-f0-9]{64}$' THEN RETURN false; END IF;
 role_name:=securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-post-auth-vote-v1',t,d,a,r,outcome,encode(convert_to(reason,'UTF8'),'hex'),h,expires),expires,sig);
 IF role_name IS NULL OR role_name NOT IN ('reviewer','settlement') THEN RETURN false; END IF;
 SELECT milestone_id INTO mid FROM securepay_private.dispute_cases WHERE tenant_id=t AND case_id=d;
 PERFORM 1 FROM public.securepay_milestones WHERE tenant_id=t AND id=mid AND status='disputed' FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM 1 FROM securepay_private.provider_funding WHERE tenant_id=t AND milestone_id=mid FOR UPDATE;
 PERFORM 1 FROM securepay_private.dispute_cases WHERE tenant_id=t AND case_id=d AND status='authorized' FOR UPDATE;
 IF NOT FOUND OR NOT securepay_private.governance_cleared(t,d,a,role_name) THEN RETURN false; END IF;
 SELECT * INTO p FROM securepay_private.post_auth_reviews WHERE tenant_id=t AND case_id=d AND review_id=r AND status='pending' FOR UPDATE;
 IF NOT FOUND OR (role_name='reviewer' AND a NOT IN(p.reviewer_one,p.reviewer_two)) OR (role_name='settlement' AND a<>p.authorizer_id) THEN RETURN false; END IF;
 s:=securepay_private.post_auth_snapshot(t,d);
 IF s IS NULL OR jsonb_array_length(s->'events')>200 OR h<>encode(public.digest(convert_to(s::text,'UTF8'),'sha256'),'hex') THEN RETURN false; END IF;
 IF (SELECT count(*) FROM securepay_private.post_auth_votes WHERE review_id=r)>=60 THEN RETURN false; END IF;
 IF outcome='reaffirm' THEN
  IF NOT (s->>'safeToReaffirm')::boolean OR NOT (s->>'panelCleared')::boolean THEN RETURN false; END IF;
  IF role_name='reviewer' AND EXISTS(SELECT 1 FROM jsonb_array_elements((s->'photos')||(s->'linkedPhotos')) AS item(photo) WHERE NOT (item.photo->>'purged')::boolean AND NOT EXISTS(SELECT 1 FROM securepay_private.reviewer_photo_reads q WHERE q.case_id=d AND q.tenant_id=t AND q.reviewer_id=a AND q.source=item.photo->>'source' AND q.photo_id=(item.photo->>'photoId')::uuid AND q.digest=item.photo->>'digest')) THEN RETURN false; END IF;
  IF role_name='settlement' AND (SELECT count(*) FROM securepay_private.post_auth_votes q WHERE q.review_id=r AND q.state_digest=h AND q.stage='reviewer' AND q.outcome='reaffirm')<>2 THEN RETURN false; END IF;
 END IF;
 INSERT INTO securepay_private.post_auth_votes(review_id,tenant_id,case_id,actor_id,stage,outcome,state_digest,reason) VALUES(r,t,d,a,CASE WHEN role_name='settlement' THEN 'authorizer' ELSE 'reviewer' END,outcome,h,reason);
 IF outcome='stop' OR role_name='settlement' THEN
  UPDATE securepay_private.post_auth_reviews SET status=CASE WHEN outcome='stop' THEN 'stopped' ELSE 'reaffirmed' END,resolved_at=clock_timestamp() WHERE review_id=r;
 END IF;
 RETURN true;
EXCEPTION WHEN unique_violation THEN RETURN false;
END $$;
ALTER FUNCTION securepay_private.post_auth_panel_valid(uuid,uuid,uuid) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.post_auth_panel_valid(uuid,uuid,uuid) FROM PUBLIC;
ALTER FUNCTION securepay_private.settlement_dispatch_cleared(uuid,uuid,uuid,uuid) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.settlement_dispatch_cleared(uuid,uuid,uuid,uuid) FROM PUBLIC;
ALTER FUNCTION securepay_private.current_settlement_authorizer(uuid,uuid,uuid,uuid) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.current_settlement_authorizer(uuid,uuid,uuid,uuid) FROM PUBLIC;
ALTER FUNCTION securepay_private.recovery_people_independent(uuid,uuid,uuid,uuid) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.recovery_people_independent(uuid,uuid,uuid,uuid) FROM PUBLIC;
ALTER FUNCTION securepay_private.post_auth_start(uuid,uuid,uuid,uuid,uuid,uuid,uuid,text,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.post_auth_start(uuid,uuid,uuid,uuid,uuid,uuid,uuid,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.post_auth_start(uuid,uuid,uuid,uuid,uuid,uuid,uuid,text,bigint,text) TO securepay_dispute_admin_runtime;
ALTER FUNCTION securepay_private.post_auth_snapshot(uuid,uuid) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.post_auth_snapshot(uuid,uuid) FROM PUBLIC;
ALTER FUNCTION securepay_private.post_auth_read(uuid,uuid,uuid,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.post_auth_read(uuid,uuid,uuid,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.post_auth_read(uuid,uuid,uuid,bigint,text) TO securepay_reviewer_runtime,securepay_settlement_dashboard_runtime;
ALTER FUNCTION securepay_private.post_auth_vote(uuid,uuid,uuid,uuid,text,text,text,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.post_auth_vote(uuid,uuid,uuid,uuid,text,text,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.post_auth_vote(uuid,uuid,uuid,uuid,text,text,text,bigint,text) TO securepay_reviewer_runtime,securepay_settlement_dashboard_runtime;
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
 IF NOT EXISTS(SELECT 1 FROM securepay_private.dispute_settlements st WHERE st.settlement_id=s AND securepay_private.settlement_dispatch_cleared(t,d,s,st.authorizer)) THEN RETURN; END IF;
 IF EXISTS(SELECT 1 FROM securepay_private.settlement_legs x WHERE x.settlement_id=s AND x.status IN ('unknown','not_executed'))
 OR EXISTS(SELECT 1 FROM securepay_private.provider_reconciliation x WHERE x.tenant_id=t AND x.milestone_id=m AND x.resolved_at IS NULL)
 OR EXISTS(SELECT 1 FROM securepay_private.settlement_leg_conflicts x WHERE x.case_id=d AND x.resolved_at IS NULL) THEN RETURN; END IF;
 RETURN QUERY UPDATE securepay_private.settlement_legs x SET status='submitted',attempts=x.attempts+1
 WHERE x.settlement_id=s AND x.kind=k AND x.status='pending' AND x.attempts<4
 RETURNING x.leg_id,x.attempts,x.amount_cents;
 IF FOUND THEN UPDATE securepay_private.dispute_settlements SET status='submitted' WHERE settlement_id=s AND status='authorized'; END IF;
END $$;
CREATE OR REPLACE FUNCTION securepay_private.retry_settlement_leg(e uuid,s uuid,t uuid,m uuid,d uuid,l uuid,a uuid,n integer,expires bigint,sig text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c securepay_private.dispute_cases%ROWTYPE;
BEGIN
 IF e IS NULL OR s IS NULL OR t IS NULL OR m IS NULL OR d IS NULL OR l IS NULL OR a IS NULL OR n IS NULL OR n NOT BETWEEN 1 AND 2
 OR securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-leg-retry-v1',e,s,t,m,d,l,a,n,expires),expires,sig) IS DISTINCT FROM 'settlement' THEN RETURN false; END IF;
 PERFORM 1 FROM public.securepay_milestones WHERE tenant_id=t AND id=m AND status='disputed' FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM 1 FROM securepay_private.provider_funding WHERE tenant_id=t AND milestone_id=m AND status='funded' FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO c FROM securepay_private.dispute_cases WHERE case_id=d AND tenant_id=t AND milestone_id=m AND status='authorized' FOR UPDATE;
 IF NOT FOUND OR a IN(c.customer_id,c.owner_id,c.first_reviewer,c.final_reviewer) THEN RETURN false; END IF;
 PERFORM 1 FROM securepay_private.dispute_settlements WHERE settlement_id=s AND case_id=d AND status='submitted' FOR UPDATE;
 IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM securepay_private.dispute_settlements st WHERE st.settlement_id=s AND securepay_private.settlement_dispatch_cleared(t,d,s,st.authorizer) AND securepay_private.current_settlement_authorizer(t,d,s,a)) OR EXISTS(SELECT 1 FROM securepay_private.settlement_leg_conflicts WHERE case_id=d AND resolved_at IS NULL) THEN RETURN false; END IF;
 UPDATE securepay_private.settlement_legs SET status='pending' WHERE leg_id=l AND settlement_id=s AND status='not_executed' AND attempts=n;
 IF NOT FOUND THEN RETURN false; END IF;
 INSERT INTO securepay_private.settlement_leg_events(event_id,case_id,leg_id,outcome,attempt,actor_id) VALUES(e,d,l,'retry_authorized',n,a);
 RETURN true;
EXCEPTION WHEN unique_violation THEN RETURN false;
END $$;
CREATE OR REPLACE FUNCTION securepay_private.recover_settlement(rid uuid,s uuid,t uuid,m uuid,d uuid,l uuid,op text,r uuid,state_hash text,evidence_hash text,reason text,a1 uuid,a2 uuid,expires bigint,provider_sig text,sig1 text,sig2 text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c securepay_private.dispute_cases%ROWTYPE; st securepay_private.dispute_settlements%ROWTYPE;
 leg securepay_private.settlement_legs%ROWTYPE; f securepay_private.provider_funding%ROWTYPE;
 key_bytes bytea;kid text;payload text;balance numeric;
BEGIN
 IF rid IS NULL OR s IS NULL OR t IS NULL OR m IS NULL OR d IS NULL OR a1 IS NULL OR a2 IS NULL OR a1=a2
 OR op IS NULL OR op NOT IN ('confirm','retry_once','clear_conflict','lift_hold')
 OR (op='lift_hold')<>(l IS NULL) OR (op IN ('confirm','clear_conflict'))<>(r IS NOT NULL)
 OR state_hash IS NULL OR state_hash !~ '^[a-f0-9]{64}$' OR evidence_hash IS NULL OR evidence_hash !~ '^[a-f0-9]{64}$'
 OR reason IS NULL OR length(btrim(reason)) NOT BETWEEN 10 AND 1000 OR expires IS NULL
 OR expires NOT BETWEEN floor(extract(epoch FROM clock_timestamp()))::bigint AND floor(extract(epoch FROM clock_timestamp()))::bigint+30
 OR provider_sig IS NULL OR provider_sig !~ '^[a-z0-9-]{1,32}[.][a-f0-9]{64}$' THEN RETURN false; END IF;
 payload:=concat_ws(':','sp-recovery-v1',rid,s,t,m,d,coalesce(l::text,'-'),op,coalesce(r::text,'-'),state_hash,evidence_hash,encode(convert_to(reason,'UTF8'),'hex'),a1,a2,expires);
 kid:=split_part(provider_sig,'.',1);
 SELECT secret INTO key_bytes FROM securepay_private.provider_key WHERE key_id=kid AND active AND (valid_until IS NULL OR valid_until>clock_timestamp());
 IF key_bytes IS NULL OR encode(public.hmac(convert_to(payload||':'||kid,'UTF8'),key_bytes,'sha256'),'hex')<>split_part(provider_sig,'.',2)
 OR securepay_private.dispute_actor_valid(t,a1,payload,expires,sig1) IS DISTINCT FROM 'reconciler'
 OR securepay_private.dispute_actor_valid(t,a2,payload,expires,sig2) IS DISTINCT FROM 'reconciler' THEN RETURN false; END IF;
 PERFORM 1 FROM public.securepay_milestones WHERE tenant_id=t AND id=m AND status IN ('disputed','settled') FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO f FROM securepay_private.provider_funding WHERE tenant_id=t AND milestone_id=m FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO c FROM securepay_private.dispute_cases WHERE case_id=d AND tenant_id=t AND milestone_id=m AND status IN ('authorized','settled') FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO st FROM securepay_private.dispute_settlements WHERE settlement_id=s AND case_id=d AND status IN ('authorized','submitted','confirmed') FOR UPDATE;
 IF NOT FOUND OR a1 IN(c.customer_id,c.owner_id,c.first_reviewer,c.final_reviewer,st.authorizer)
 OR a2 IN(c.customer_id,c.owner_id,c.first_reviewer,c.final_reviewer,st.authorizer)
 OR securepay_private.recovery_state(s,t,m,d) IS DISTINCT FROM state_hash THEN RETURN false; END IF;
 IF l IS NOT NULL THEN
  SELECT * INTO leg FROM securepay_private.settlement_legs WHERE leg_id=l AND settlement_id=s FOR UPDATE;
  IF NOT FOUND OR leg.attempts=0 THEN RETURN false; END IF;
 END IF;
 SELECT remaining_cents INTO balance FROM securepay_private.financial_balance(t,m);
 IF balance<0 OR NOT securepay_private.recovery_people_independent(t,d,a1,a2) THEN RETURN false; END IF;
 IF op='retry_once' THEN
  -- Fourth and final attempt only after signed definitive non-execution.
  IF NOT securepay_private.settlement_dispatch_cleared(t,d,s,st.authorizer) OR f.status<>'funded' OR c.status<>'authorized' OR leg.status<>'not_executed' OR leg.attempts<>3
   OR EXISTS(SELECT 1 FROM securepay_private.settlement_leg_conflicts WHERE case_id=d AND resolved_at IS NULL)
   OR EXISTS(SELECT 1 FROM securepay_private.settlement_legs WHERE settlement_id=s AND leg_id<>l AND status IN ('unknown','submitted','not_executed'))
   OR balance<leg.amount_cents THEN RETURN false; END IF;
 ELSIF op='confirm' THEN
  IF c.status<>'authorized' OR leg.status='confirmed' OR balance<leg.amount_cents THEN RETURN false; END IF;
  -- A quarantined receipt may be adopted only if it belongs exclusively to this leg.
  IF EXISTS(SELECT 1 FROM securepay_private.provider_receipts WHERE receipt=r) AND
   (NOT EXISTS(SELECT 1 FROM securepay_private.settlement_leg_events e JOIN securepay_private.settlement_leg_conflicts x ON x.event_id=e.event_id WHERE e.leg_id=l AND e.receipt=r)
    OR EXISTS(SELECT 1 FROM securepay_private.settlement_leg_events WHERE receipt=r AND leg_id<>l)
    OR EXISTS(SELECT 1 FROM securepay_private.settlement_legs WHERE receipt=r)
    OR EXISTS(SELECT 1 FROM securepay_private.provider_events WHERE transaction_ref=r)
    OR EXISTS(SELECT 1 FROM securepay_private.dispute_settlements WHERE provider_receipt=r)) THEN RETURN false; END IF;
 ELSIF op='clear_conflict' THEN
  -- No rewriting the amount or receipt of an already confirmed leg.
  IF leg.status<>'confirmed' OR leg.receipt<>r OR NOT EXISTS(SELECT 1 FROM securepay_private.settlement_leg_conflicts x JOIN securepay_private.settlement_leg_events e ON e.event_id=x.event_id WHERE e.leg_id=l AND x.resolved_at IS NULL) THEN RETURN false; END IF;
 ELSE
  -- A separately signed provider fact establishes that the funding hold is lifted.
  IF f.status<>'held' OR c.status<>'authorized' OR EXISTS(SELECT 1 FROM securepay_private.settlement_leg_conflicts WHERE case_id=d AND resolved_at IS NULL)
   OR EXISTS(SELECT 1 FROM securepay_private.settlement_legs WHERE settlement_id=s AND status IN ('submitted','unknown')) THEN RETURN false; END IF;
 END IF;
 INSERT INTO securepay_private.settlement_recoveries(resolution_id,case_id,leg_id,action,actor_one,actor_two,state_digest,evidence_digest,reason,receipt)
 VALUES(rid,d,l,op,a1,a2,state_hash,evidence_hash,reason,r);
 IF op='retry_once' THEN
  UPDATE securepay_private.settlement_legs SET status='pending' WHERE leg_id=l;
 ELSIF op IN ('confirm','clear_conflict') THEN
  IF op='confirm' THEN
   INSERT INTO securepay_private.provider_receipts(receipt) VALUES(r) ON CONFLICT DO NOTHING;
   IF NOT FOUND AND (NOT EXISTS(SELECT 1 FROM securepay_private.settlement_leg_events e JOIN securepay_private.settlement_leg_conflicts x ON x.event_id=e.event_id WHERE e.leg_id=l AND e.receipt=r)
    OR EXISTS(SELECT 1 FROM securepay_private.settlement_leg_events WHERE receipt=r AND leg_id<>l)
    OR EXISTS(SELECT 1 FROM securepay_private.settlement_legs WHERE receipt=r)
    OR EXISTS(SELECT 1 FROM securepay_private.provider_events WHERE transaction_ref=r)
    OR EXISTS(SELECT 1 FROM securepay_private.dispute_settlements WHERE provider_receipt=r)) THEN
    RAISE EXCEPTION 'Receipt already allocated' USING ERRCODE='23505';
   END IF;
   UPDATE securepay_private.settlement_legs SET status='confirmed',receipt=r WHERE leg_id=l;
  END IF;
  UPDATE securepay_private.settlement_leg_conflicts x SET resolved_at=clock_timestamp(),resolution_id=rid
   WHERE x.resolved_at IS NULL AND x.event_id IN (SELECT e.event_id FROM securepay_private.settlement_leg_events e WHERE e.leg_id=l);
 ELSE
  UPDATE securepay_private.provider_funding SET status='funded' WHERE tenant_id=t AND milestone_id=m;
  UPDATE securepay_private.provider_reconciliation SET resolved_at=clock_timestamp(),resolution_id=rid WHERE tenant_id=t AND milestone_id=m AND provider_reconciliation.reason='hold_after_dispatch' AND resolved_at IS NULL;
 END IF;
 IF c.status='authorized' AND (f.status='funded' OR op='lift_hold')
 AND NOT EXISTS(SELECT 1 FROM securepay_private.settlement_legs WHERE settlement_id=s AND status<>'confirmed')
 AND NOT EXISTS(SELECT 1 FROM securepay_private.settlement_leg_conflicts WHERE case_id=d AND resolved_at IS NULL) THEN
  SELECT remaining_cents INTO balance FROM securepay_private.financial_balance(t,m);
  IF balance<>0 THEN RAISE EXCEPTION 'Unbalanced settlement'; END IF;
  UPDATE securepay_private.dispute_settlements SET status='confirmed',confirmed_at=clock_timestamp() WHERE settlement_id=s;
  UPDATE securepay_private.dispute_cases SET status='settled' WHERE case_id=d;
  UPDATE securepay_private.provider_funding SET status='settled' WHERE tenant_id=t AND milestone_id=m;
  UPDATE public.securepay_milestones SET status='settled',version=version+1,updated_at=clock_timestamp() WHERE id=m;
 END IF;
 RETURN true;
EXCEPTION WHEN unique_violation THEN RETURN false;
END $$;
GRANT EXECUTE ON FUNCTION securepay_private.retry_settlement_leg(uuid,uuid,uuid,uuid,uuid,uuid,uuid,integer,bigint,text) TO securepay_settlement_dashboard_runtime;
COMMIT;

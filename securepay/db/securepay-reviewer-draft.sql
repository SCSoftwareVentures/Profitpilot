-- Narrow independent reviewer boundary, assigned cases only.
BEGIN;
CREATE ROLE securepay_reviewer_runtime NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS;
GRANT USAGE ON SCHEMA securepay_private TO securepay_reviewer_runtime;
CREATE TABLE securepay_private.reviewer_photo_reads(
 tenant_id uuid NOT NULL,case_id uuid NOT NULL REFERENCES securepay_private.dispute_cases(case_id),reviewer_id uuid NOT NULL,
 source text NOT NULL CHECK(source IN ('completion','dispute')),photo_id uuid NOT NULL,digest text NOT NULL CHECK(digest ~ '^[a-f0-9]{64}$'),read_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(case_id,reviewer_id,source,photo_id,digest)
);
ALTER TABLE securepay_private.reviewer_photo_reads OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.reviewer_photo_reads FROM PUBLIC,securepay_reviewer_runtime,securepay_dispute_runtime;
CREATE TRIGGER sp_chain_review_photo_read AFTER INSERT ON securepay_private.reviewer_photo_reads FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
CREATE FUNCTION securepay_private.reviewer_assigned(t uuid,d uuid,a uuid) RETURNS boolean
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM securepay_private.dispute_photo_reviewers r JOIN securepay_private.dispute_actors x ON x.tenant_id=r.tenant_id AND x.actor_id=r.reviewer_id
 JOIN securepay_private.dispute_cases c ON c.case_id=r.case_id AND c.tenant_id=r.tenant_id
 WHERE r.tenant_id=t AND r.case_id=d AND r.reviewer_id=a AND x.active AND x.role='reviewer' AND a NOT IN(c.customer_id,c.owner_id))
$$;
CREATE FUNCTION securepay_private.reviewer_queue(t uuid,a uuid,expires bigint,sig text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE result jsonb;
BEGIN
 IF securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-review-queue-v1',t,a,expires),expires,sig) IS DISTINCT FROM 'reviewer' THEN RETURN NULL; END IF;
 SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY q.priority,q."dueAt",q."caseId"),'[]'::jsonb) INTO result FROM (
 SELECT c.case_id AS "caseId",c.milestone_id AS "milestoneId",c.severity,c.status,c.repair_phase AS "repairPhase",c.response_due_at AS "dueAt",
 CASE WHEN c.severity='serious' THEN 0 WHEN c.response_escalated_at IS NOT NULL OR c.repair_phase='escalated' THEN 1 ELSE 2 END AS priority
 FROM securepay_private.dispute_cases c WHERE c.tenant_id=t AND c.status<>'settled' AND securepay_private.reviewer_assigned(t,c.case_id,a)
 ORDER BY priority,c.response_due_at,c.case_id LIMIT 101) q;
 IF jsonb_array_length(result)>100 THEN RAISE EXCEPTION 'Reviewer queue exceeds capacity' USING ERRCODE='54000'; END IF;
 RETURN result;
END $$;
CREATE FUNCTION securepay_private.reviewer_snapshot(t uuid,d uuid,a uuid) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r jsonb;
BEGIN
 IF NOT securepay_private.reviewer_assigned(t,d,a) THEN RETURN NULL; END IF;
 IF (SELECT count(*) FROM securepay_private.dispute_events WHERE case_id=d)>200 THEN RAISE EXCEPTION 'Case history exceeds capacity' USING ERRCODE='54000'; END IF;
 SELECT jsonb_build_object('caseId',c.case_id,'milestoneId',c.milestone_id,'severity',c.severity,'status',c.status,'repairPhase',c.repair_phase,
 'amountCents',m.amount_cents::text,'fundingStatus',f.status,'firstReviewByMe',c.first_reviewer IS NOT DISTINCT FROM a,
 'customerEvidence',c.customer_evidence,'ownerEvidence',c.owner_evidence,'customerAck',c.customer_ack,'ownerAck',c.owner_ack,
 'customerAppealEvidence',c.customer_appeal_evidence,'ownerAppealEvidence',c.owner_appeal_evidence,'payoutCents',c.payout_cents::text,'refundCents',c.refund_cents::text,
 'responseDueAt',c.response_due_at,'ownerRespondedAt',c.owner_responded_at,'responseEscalatedAt',c.response_escalated_at,'repairDueAt',c.repair_due_at,'repairReviewDueAt',c.repair_review_due_at,
 'events',(SELECT coalesce(jsonb_agg(jsonb_build_object('eventId',e.event_id,'action',e.action,'details',e.details,'digest',e.evidence_digest,'payoutCents',e.payout_cents::text,'refundCents',e.refund_cents::text,'at',e.occurred_at,'role',CASE WHEN e.actor_id=c.customer_id THEN 'customer' WHEN e.actor_id=c.owner_id THEN 'owner' ELSE 'reviewer_or_authority' END) ORDER BY e.occurred_at,e.event_id),'[]'::jsonb) FROM securepay_private.dispute_events e WHERE e.case_id=d),
 'photos',(SELECT coalesce(jsonb_agg(jsonb_build_object('photoId',p.photo_id,'digest',p.digest,'purged',p.purged_at IS NOT NULL,'source','dispute') ORDER BY p.photo_id),'[]'::jsonb) FROM securepay_private.dispute_photos p WHERE p.case_id=d),
 'linkedCompletions',(SELECT coalesce(jsonb_agg(jsonb_build_object('completionId',w.completion_id,'manifestDigest',l.manifest_digest,'status',w.status,'comments',w.comments,'rejectionReason',w.rejection_reason) ORDER BY w.completion_id),'[]'::jsonb) FROM securepay_private.work_dispute_links l JOIN securepay_private.work_completion w ON w.completion_id=l.completion_id WHERE l.case_id=d AND l.tenant_id=t),
 'linkedPhotos',(SELECT coalesce(jsonb_agg(jsonb_build_object('photoId',p.photo_id,'digest',p.digest,'purged',p.purged_at IS NOT NULL,'source','completion','manifestDigest',l.manifest_digest) ORDER BY p.photo_id),'[]'::jsonb) FROM securepay_private.work_dispute_links l JOIN securepay_private.work_photos p ON p.completion_id=l.completion_id WHERE l.case_id=d AND l.tenant_id=t),
 'deadlines',(SELECT coalesce(jsonb_agg(jsonb_build_object('kind',e.kind,'dueAt',e.due_at) ORDER BY e.due_at,e.kind),'[]'::jsonb) FROM securepay_private.dispute_deadline_events e WHERE e.case_id=d))
 INTO r FROM securepay_private.dispute_cases c JOIN public.securepay_milestones m ON m.tenant_id=c.tenant_id AND m.id=c.milestone_id
 JOIN securepay_private.provider_funding f ON f.tenant_id=c.tenant_id AND f.milestone_id=c.milestone_id WHERE c.tenant_id=t AND c.case_id=d;
 RETURN r;
END $$;
CREATE FUNCTION securepay_private.reviewer_case(t uuid,d uuid,a uuid,expires bigint,sig text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r jsonb;mid uuid;
BEGIN
 IF securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-review-case-v1',t,d,a,expires),expires,sig) IS DISTINCT FROM 'reviewer' OR NOT securepay_private.reviewer_assigned(t,d,a) THEN RETURN NULL; END IF;
 SELECT milestone_id INTO mid FROM securepay_private.dispute_cases WHERE tenant_id=t AND case_id=d;
 PERFORM 1 FROM public.securepay_milestones WHERE tenant_id=t AND id=mid FOR UPDATE;
 PERFORM 1 FROM securepay_private.dispute_cases WHERE tenant_id=t AND case_id=d FOR UPDATE;
 r:=securepay_private.reviewer_snapshot(t,d,a);
 IF r IS NULL THEN RETURN NULL; END IF;
 PERFORM securepay_private.append_audit_chain(t,'reviewer_case','READ',encode(public.digest(convert_to(concat_ws(':',d,a),'UTF8'),'sha256'),'hex'));
 RETURN jsonb_build_object('case',r,'stateDigest',encode(public.digest(convert_to(r::text,'UTF8'),'sha256'),'hex'));
END $$;
CREATE FUNCTION securepay_private.reviewer_photo(t uuid,d uuid,a uuid,p uuid,source text,expires bigint,sig text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE mid uuid;k bytea;inner_sig text;r jsonb;
BEGIN
 IF source IS NULL OR source NOT IN ('dispute','completion') OR p IS NULL OR securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-review-photo-v1',t,d,a,p,source,expires),expires,sig) IS DISTINCT FROM 'reviewer' OR NOT securepay_private.reviewer_assigned(t,d,a) THEN RETURN NULL; END IF;
 SELECT milestone_id INTO mid FROM securepay_private.dispute_cases WHERE tenant_id=t AND case_id=d;
 PERFORM 1 FROM public.securepay_milestones WHERE tenant_id=t AND id=mid FOR UPDATE;
 PERFORM 1 FROM securepay_private.dispute_cases WHERE tenant_id=t AND case_id=d FOR UPDATE;
 IF NOT securepay_private.reviewer_assigned(t,d,a) THEN RETURN NULL; END IF;
 SELECT secret INTO k FROM securepay_private.dispute_actors WHERE tenant_id=t AND actor_id=a AND active AND role='reviewer';
 IF k IS NULL THEN RETURN NULL; END IF;
 IF source='completion' THEN
  inner_sig:=encode(public.hmac(convert_to(concat_ws(':','sp-linked-work-v1',t,mid,d,a,p,expires),'UTF8'),k,'sha256'),'hex');
  r:=securepay_private.dispute_work_evidence(t,mid,d,a,p,expires,inner_sig);
 ELSE
 inner_sig:=encode(public.hmac(convert_to(concat_ws(':','sp-photo-read-v1',p,t,mid,d,a,expires),'UTF8'),k,'sha256'),'hex');
 SELECT jsonb_build_object('photoId',p,'digest',q.digest,'content',replace(encode(q.content,'base64'),chr(10),'')) INTO r FROM securepay_private.read_dispute_photo(p,t,mid,d,a,expires,inner_sig) q WHERE q.media_type='image/png';
 END IF;
 IF r IS NOT NULL THEN INSERT INTO securepay_private.reviewer_photo_reads(tenant_id,case_id,reviewer_id,source,photo_id,digest) VALUES(t,d,a,source,p,r->>'digest') ON CONFLICT DO NOTHING; END IF;
 RETURN r;
END $$;
CREATE FUNCTION securepay_private.reviewer_decision(e uuid,t uuid,d uuid,a uuid,op text,reason text,payout bigint,refund bigint,state_hash text,expires bigint,sig text) RETURNS boolean
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
 IF h<>state_hash OR EXISTS(SELECT 1 FROM jsonb_array_elements((s->'photos')||(s->'linkedPhotos')) p WHERE NOT (p->>'purged')::boolean AND NOT EXISTS(SELECT 1 FROM securepay_private.reviewer_photo_reads r WHERE r.tenant_id=t AND r.case_id=d AND r.reviewer_id=a AND r.source=p->>'source' AND r.photo_id=(p->>'photoId')::uuid AND r.digest=p->>'digest')) THEN RETURN false; END IF;
 SELECT secret INTO k FROM securepay_private.dispute_actors WHERE tenant_id=t AND actor_id=a AND active AND role='reviewer';
 IF k IS NULL THEN RETURN false; END IF;
 inner_sig:=encode(public.hmac(convert_to(concat_ws(':','sp-dispute-v1',e,t,mid,d,a,op,encode(convert_to(reason,'UTF8'),'hex'),h,payout,refund,expires),'UTF8'),k,'sha256'),'hex');
 RETURN securepay_private.dispute_action(e,t,mid,d,a,op,reason,h,payout,refund,expires,inner_sig);
END $$;
ALTER FUNCTION securepay_private.reviewer_assigned(uuid,uuid,uuid) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.reviewer_assigned(uuid,uuid,uuid) FROM PUBLIC;
ALTER FUNCTION securepay_private.reviewer_queue(uuid,uuid,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.reviewer_queue(uuid,uuid,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.reviewer_queue(uuid,uuid,bigint,text) TO securepay_reviewer_runtime;
ALTER FUNCTION securepay_private.reviewer_snapshot(uuid,uuid,uuid) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.reviewer_snapshot(uuid,uuid,uuid) FROM PUBLIC;
ALTER FUNCTION securepay_private.reviewer_case(uuid,uuid,uuid,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.reviewer_case(uuid,uuid,uuid,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.reviewer_case(uuid,uuid,uuid,bigint,text) TO securepay_reviewer_runtime;
ALTER FUNCTION securepay_private.reviewer_photo(uuid,uuid,uuid,uuid,text,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.reviewer_photo(uuid,uuid,uuid,uuid,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.reviewer_photo(uuid,uuid,uuid,uuid,text,bigint,text) TO securepay_reviewer_runtime;
ALTER FUNCTION securepay_private.reviewer_decision(uuid,uuid,uuid,uuid,text,text,bigint,bigint,text,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.reviewer_decision(uuid,uuid,uuid,uuid,text,text,bigint,bigint,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.reviewer_decision(uuid,uuid,uuid,uuid,text,text,bigint,bigint,text,bigint,text) TO securepay_reviewer_runtime;
CREATE OR REPLACE FUNCTION securepay_private.dispute_action(e uuid,t uuid,m uuid,d uuid,a uuid,op text,details text,digest text,payout bigint,refund bigint,expires bigint,sig text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE role_name text; milestone public.securepay_milestones%ROWTYPE; c securepay_private.dispute_cases%ROWTYPE; owner uuid;
BEGIN
 IF e IS NULL OR t IS NULL OR m IS NULL OR d IS NULL OR a IS NULL OR op IS NULL OR details IS NULL
 OR length(details)>4000 OR (digest IS NOT NULL AND digest !~ '^[a-f0-9]{64}$') THEN RETURN false; END IF;
 role_name:=securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-dispute-v1',e,t,m,d,a,op,encode(convert_to(details,'UTF8'),'hex'),coalesce(digest,'-'),coalesce(payout::text,'-'),coalesce(refund::text,'-'),expires),expires,sig);
 IF role_name IS NULL OR role_name='settlement' THEN RETURN false; END IF;
 SELECT * INTO milestone FROM public.securepay_milestones WHERE tenant_id=t AND id=m FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM 1 FROM securepay_private.provider_funding WHERE tenant_id=t AND milestone_id=m AND status IN ('funded','held') FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 IF op='open' THEN
  IF role_name<>'customer' OR a IS DISTINCT FROM milestone.payer_customer_id OR details NOT IN ('minor','moderate','serious') OR digest IS NULL
  OR payout IS NOT NULL OR refund IS NOT NULL OR milestone.status NOT IN ('submitted','approved','release_pending')
  OR EXISTS(SELECT 1 FROM public.securepay_release_requests WHERE tenant_id=t AND milestone_id=m AND status IN ('submitted','confirmed','failed')) THEN RETURN false; END IF;
  SELECT owner_id INTO owner FROM securepay_private.dispute_parties WHERE tenant_id=t AND milestone_id=m;
  IF owner IS NULL OR owner=a OR NOT EXISTS(SELECT 1 FROM securepay_private.dispute_actors WHERE tenant_id=t AND actor_id=owner AND role='owner' AND active) THEN RETURN false; END IF;
  INSERT INTO securepay_private.dispute_cases(case_id,tenant_id,milestone_id,customer_id,owner_id,severity,status,customer_evidence)
  VALUES(d,t,m,a,owner,details,'open',true);
  UPDATE public.securepay_release_requests SET status='failed' WHERE tenant_id=t AND milestone_id=m AND status='pending';
  DELETE FROM public.securepay_release_proofs WHERE tenant_id=t AND milestone_id=m AND consumed_at IS NULL;
  UPDATE public.securepay_milestones SET status='disputed',version=version+1,updated_at=clock_timestamp() WHERE id=m;
 ELSE
  SELECT * INTO c FROM securepay_private.dispute_cases WHERE case_id=d AND tenant_id=t AND milestone_id=m FOR UPDATE;
  IF NOT FOUND OR milestone.status<>'disputed' THEN RETURN false; END IF;
  IF op='evidence' THEN
   IF c.status NOT IN ('open','appealed') OR digest IS NULL OR length(btrim(details))=0 OR payout IS NOT NULL OR refund IS NOT NULL THEN RETURN false; END IF;
   IF role_name='customer' AND a=c.customer_id THEN UPDATE securepay_private.dispute_cases SET customer_evidence=true,customer_appeal_evidence=customer_appeal_evidence OR c.status='appealed' WHERE case_id=d;
   ELSIF role_name='owner' AND a=c.owner_id THEN UPDATE securepay_private.dispute_cases SET owner_evidence=true,owner_appeal_evidence=owner_appeal_evidence OR c.status='appealed' WHERE case_id=d;
   ELSE RETURN false; END IF;
  ELSIF op IN ('decide','finalize') THEN
   IF NOT securepay_private.reviewer_assigned(t,d,a) THEN RETURN false; END IF;
   IF role_name<>'reviewer' OR a IN (c.owner_id,c.customer_id) OR NOT c.customer_evidence OR NOT c.owner_evidence
   OR length(btrim(details))<10 OR digest IS NULL OR payout IS NULL OR refund IS NULL OR payout<0 OR refund<0
   OR payout::numeric+refund::numeric<>milestone.amount_cents THEN RETURN false; END IF;
   IF op='decide' AND c.status='open' AND c.repair_phase IN ('none','escalated','accepted')
    AND (c.repair_phase<>'accepted' OR (payout=milestone.amount_cents AND refund=0)) THEN
    UPDATE securepay_private.dispute_cases SET status='decided',first_reviewer=a,payout_cents=payout,refund_cents=refund WHERE case_id=d;
   ELSIF op='finalize' AND c.status IN ('decided','appealed') AND a IS DISTINCT FROM c.first_reviewer
    AND ((c.status='appealed' AND c.customer_appeal_evidence AND c.owner_appeal_evidence) OR (c.status='decided' AND c.customer_ack AND c.owner_ack))
    AND (c.status='appealed' OR (payout=c.payout_cents AND refund=c.refund_cents)) THEN
    UPDATE securepay_private.dispute_cases SET status='final',final_reviewer=a,payout_cents=payout,refund_cents=refund WHERE case_id=d;
   ELSE RETURN false; END IF;
  ELSIF op IN ('ack','appeal') THEN
   IF op='ack' AND EXISTS(SELECT 1 FROM securepay_private.funded_cancellation_offers WHERE case_id=d) THEN RETURN false; END IF;
   IF c.status<>'decided' OR payout IS NOT NULL OR refund IS NOT NULL OR length(btrim(details))=0
   OR NOT ((role_name='customer' AND a=c.customer_id) OR (role_name='owner' AND a=c.owner_id)) THEN RETURN false; END IF;
   IF op='appeal' THEN
    IF digest IS NULL THEN RETURN false; END IF;
    UPDATE securepay_private.dispute_cases SET status='appealed',customer_appeal_evidence=(a=c.customer_id),owner_appeal_evidence=(a=c.owner_id) WHERE case_id=d;
   ELSIF a=c.customer_id THEN UPDATE securepay_private.dispute_cases SET customer_ack=true WHERE case_id=d;
   ELSE UPDATE securepay_private.dispute_cases SET owner_ack=true WHERE case_id=d; END IF;
  ELSE RETURN false; END IF;
 END IF;
 INSERT INTO securepay_private.dispute_events(event_id,case_id,actor_id,action,details,evidence_digest,payout_cents,refund_cents)
 VALUES(e,d,a,op,details,digest,payout,refund);
 RETURN true;
EXCEPTION WHEN unique_violation THEN RETURN false;
END $$;
CREATE OR REPLACE FUNCTION securepay_private.repair_action(e uuid,t uuid,m uuid,d uuid,a uuid,op text,details text,due bigint,photo uuid,expires bigint,sig text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c securepay_private.dispute_cases%ROWTYPE; role_name text; now_at timestamptz:=clock_timestamp(); photo_digest text;
BEGIN
 IF e IS NULL OR t IS NULL OR m IS NULL OR d IS NULL OR a IS NULL OR op IS NULL OR details IS NULL OR length(btrim(details))=0 OR length(details)>4000 THEN RETURN false; END IF;
 role_name:=securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-repair-v1',e,t,m,d,a,op,encode(convert_to(details,'UTF8'),'hex'),coalesce(due::text,'-'),coalesce(photo::text,'-'),expires),expires,sig);
 IF role_name IS NULL OR role_name NOT IN ('owner','customer','reviewer') THEN RETURN false; END IF;
 PERFORM 1 FROM public.securepay_milestones WHERE tenant_id=t AND id=m AND status='disputed' FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO c FROM securepay_private.dispute_cases WHERE case_id=d AND tenant_id=t AND milestone_id=m AND status='open' FOR UPDATE;
 IF NOT FOUND OR (role_name='owner' AND a<>c.owner_id) OR (role_name='customer' AND a<>c.customer_id)
 OR (role_name='reviewer' AND NOT securepay_private.reviewer_assigned(t,d,a)) THEN RETURN false; END IF;
 now_at:=clock_timestamp();
 IF op IN ('propose','reviewer_plan') THEN
  IF due IS NULL OR due<=extract(epoch FROM now_at) OR due>extract(epoch FROM now_at+interval '90 days') OR photo IS NOT NULL THEN RETURN false; END IF;
  IF op='propose' AND role_name='owner' AND c.severity<>'serious' AND c.repair_phase='none' THEN
   UPDATE securepay_private.dispute_cases SET repair_phase='proposed',repair_due_at=to_timestamp(due) WHERE case_id=d;
  ELSIF op='reviewer_plan' AND role_name='reviewer' AND c.repair_phase IN ('none','proposed') THEN
   UPDATE securepay_private.dispute_cases SET repair_phase='active',repair_due_at=to_timestamp(due),repair_started_at=now_at WHERE case_id=d;
  ELSE RETURN false; END IF;
 ELSIF op='accept_plan' THEN
  IF role_name<>'customer' OR c.repair_phase<>'proposed' OR c.repair_due_at<=now_at OR due IS NOT NULL OR photo IS NOT NULL THEN RETURN false; END IF;
  UPDATE securepay_private.dispute_cases SET repair_phase='active',repair_started_at=now_at WHERE case_id=d;
 ELSIF op='submit_repair' THEN
  IF role_name<>'owner' OR c.repair_phase<>'active' OR due IS NOT NULL OR photo IS NULL THEN RETURN false; END IF;
  SELECT digest INTO photo_digest FROM securepay_private.dispute_photos WHERE photo_id=photo AND case_id=d AND actor_id=a AND created_at>=c.repair_started_at;
  IF NOT FOUND THEN RETURN false; END IF;
  IF c.repair_due_at<=now_at THEN
   INSERT INTO securepay_private.dispute_deadline_events(case_id,kind,due_at) VALUES(d,'repair_overdue',c.repair_due_at) ON CONFLICT DO NOTHING;
   UPDATE securepay_private.dispute_cases SET repair_phase='escalated',repair_photo_id=photo,owner_evidence=true WHERE case_id=d;
  ELSE
   UPDATE securepay_private.dispute_cases SET repair_phase='submitted',repair_photo_id=photo,owner_evidence=true,repair_review_due_at=securepay_private.business_deadline(now_at,2) WHERE case_id=d;
  END IF;
 ELSIF op='accept_repair' THEN
  IF role_name<>'customer' OR c.repair_phase<>'submitted' OR c.repair_review_due_at<=now_at OR photo IS DISTINCT FROM c.repair_photo_id OR due IS NOT NULL THEN RETURN false; END IF;
  UPDATE securepay_private.dispute_cases SET repair_phase='accepted' WHERE case_id=d;
 ELSIF op='escalate' THEN
  IF c.repair_phase NOT IN ('proposed','active','submitted') OR due IS NOT NULL OR photo IS NOT NULL THEN RETURN false; END IF;
  UPDATE securepay_private.dispute_cases SET repair_phase='escalated' WHERE case_id=d;
 ELSE RETURN false; END IF;
 INSERT INTO securepay_private.dispute_events(event_id,case_id,actor_id,action,details,evidence_digest) VALUES(e,d,a,'repair_'||op,details,photo_digest);
 RETURN true;
EXCEPTION WHEN unique_violation THEN RETURN false;
END $$;
-- Durable operational notifications, no external addresses or provider secrets.
CREATE TABLE securepay_private.escalation_outbox(
 notification_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 tenant_id uuid NOT NULL,case_id uuid NOT NULL,kind text NOT NULL,due_at timestamptz NOT NULL,
 attempt_count integer NOT NULL DEFAULT 0 CHECK(attempt_count BETWEEN 0 AND 8),
 next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),lease_id uuid,lease_until timestamptz,
 delivered_at timestamptz,dead_lettered_at timestamptz,delivery_ref text CHECK(length(delivery_ref) BETWEEN 1 AND 200),
 FOREIGN KEY(case_id,kind,due_at) REFERENCES securepay_private.dispute_deadline_events(case_id,kind,due_at),
 UNIQUE(case_id,kind,due_at),CHECK((lease_id IS NULL)=(lease_until IS NULL)),CHECK(delivered_at IS NULL OR dead_lettered_at IS NULL)
);
ALTER TABLE securepay_private.escalation_outbox OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.escalation_outbox FROM PUBLIC,securepay_reviewer_runtime,securepay_notification_runtime,securepay_escalation_runtime;
CREATE INDEX sp_escalation_pending ON securepay_private.escalation_outbox(next_attempt_at,notification_id) WHERE delivered_at IS NULL AND dead_lettered_at IS NULL;
CREATE FUNCTION securepay_private.enqueue_escalation() RETURNS trigger
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 INSERT INTO securepay_private.escalation_outbox(tenant_id,case_id,kind,due_at)
 SELECT tenant_id,NEW.case_id,NEW.kind,NEW.due_at FROM securepay_private.dispute_cases WHERE case_id=NEW.case_id ON CONFLICT DO NOTHING;
 RETURN NEW;
END $$;
ALTER FUNCTION securepay_private.enqueue_escalation() OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.enqueue_escalation() FROM PUBLIC;
CREATE TRIGGER sp_enqueue_escalation AFTER INSERT ON securepay_private.dispute_deadline_events FOR EACH ROW EXECUTE FUNCTION securepay_private.enqueue_escalation();
INSERT INTO securepay_private.escalation_outbox(tenant_id,case_id,kind,due_at)
 SELECT c.tenant_id,e.case_id,e.kind,e.due_at FROM securepay_private.dispute_deadline_events e JOIN securepay_private.dispute_cases c ON c.case_id=e.case_id ON CONFLICT DO NOTHING;
CREATE FUNCTION securepay_private.claim_escalation(l uuid) RETURNS TABLE(notification_id bigint,tenant_id uuid,case_id uuid,kind text,due_at timestamptz,attempt_count integer)
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF l IS NULL THEN RETURN; END IF;
 UPDATE securepay_private.escalation_outbox o SET dead_lettered_at=clock_timestamp(),lease_id=NULL,lease_until=NULL
 WHERE o.notification_id IN(SELECT q.notification_id FROM securepay_private.escalation_outbox q WHERE q.delivered_at IS NULL AND q.dead_lettered_at IS NULL AND q.attempt_count>=8 AND (q.lease_until IS NULL OR q.lease_until<=clock_timestamp()) ORDER BY q.notification_id LIMIT 100 FOR UPDATE SKIP LOCKED);
 RETURN QUERY WITH candidate AS (
 SELECT o.notification_id FROM securepay_private.escalation_outbox o WHERE o.delivered_at IS NULL AND o.dead_lettered_at IS NULL AND o.attempt_count<8
 AND o.next_attempt_at<=clock_timestamp() AND (o.lease_until IS NULL OR o.lease_until<=clock_timestamp())
 ORDER BY o.next_attempt_at,o.notification_id LIMIT 1 FOR UPDATE SKIP LOCKED)
 UPDATE securepay_private.escalation_outbox o SET lease_id=l,lease_until=clock_timestamp()+interval '60 seconds',attempt_count=o.attempt_count+1
 FROM candidate c WHERE o.notification_id=c.notification_id RETURNING o.notification_id,o.tenant_id,o.case_id,o.kind,o.due_at,o.attempt_count;
END $$;
CREATE FUNCTION securepay_private.finish_escalation(n bigint,l uuid,success boolean,ref text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF n IS NULL OR l IS NULL OR success IS NULL OR (success AND (ref IS NULL OR ref !~ '^[a-zA-Z0-9._:-]{1,200}$')) OR (NOT success AND ref IS NOT NULL) THEN RETURN false; END IF;
 UPDATE securepay_private.escalation_outbox o SET delivered_at=CASE WHEN success THEN clock_timestamp() ELSE NULL END,delivery_ref=CASE WHEN success THEN ref ELSE NULL END,
 dead_lettered_at=CASE WHEN NOT success AND o.attempt_count>=8 THEN clock_timestamp() ELSE NULL END,
 next_attempt_at=CASE WHEN success THEN o.next_attempt_at ELSE clock_timestamp()+make_interval(secs=>least(3600,15*(1 << (o.attempt_count-1)))) END,lease_id=NULL,lease_until=NULL
 WHERE o.notification_id=n AND o.lease_id=l AND o.lease_until>clock_timestamp() AND o.delivered_at IS NULL AND o.dead_lettered_at IS NULL;
 RETURN FOUND;
END $$;
ALTER FUNCTION securepay_private.claim_escalation(uuid) OWNER TO securepay_context_owner;
ALTER FUNCTION securepay_private.finish_escalation(bigint,uuid,boolean,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.claim_escalation(uuid),securepay_private.finish_escalation(bigint,uuid,boolean,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.claim_escalation(uuid),securepay_private.finish_escalation(bigint,uuid,boolean,text) TO securepay_notification_runtime;
COMMIT;

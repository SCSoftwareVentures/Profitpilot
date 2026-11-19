-- Funded cancellation: bilateral proposed split, independent adjudication,
-- separate settlement authority and individually confirmed provider legs.
BEGIN;
CREATE TABLE securepay_private.funded_cancellation_offers(
 offer_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,plan_id uuid NOT NULL REFERENCES securepay_private.payment_plans(plan_id),
 milestone_id uuid NOT NULL,owner_id uuid NOT NULL,customer_id uuid NOT NULL,
 payout_cents bigint NOT NULL CHECK(payout_cents>=0),refund_cents bigint NOT NULL CHECK(refund_cents>0),
 reason text NOT NULL CHECK(length(btrim(reason)) BETWEEN 10 AND 2000),
 state_digest text NOT NULL CHECK(state_digest ~ '^[a-f0-9]{64}$'),offer_digest text NOT NULL CHECK(offer_digest ~ '^[a-f0-9]{64}$'),
 status text NOT NULL DEFAULT 'offered' CHECK(status IN ('offered','accepted','withdrawn')),
 case_id uuid UNIQUE REFERENCES securepay_private.dispute_cases(case_id),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),accepted_at timestamptz,
 FOREIGN KEY(tenant_id,milestone_id) REFERENCES public.securepay_milestones(tenant_id,id),
 CHECK((status='accepted')=(case_id IS NOT NULL AND accepted_at IS NOT NULL))
);
CREATE UNIQUE INDEX sp_funded_cancel_pending ON securepay_private.funded_cancellation_offers(tenant_id,milestone_id) WHERE status='offered';
ALTER TABLE securepay_private.funded_cancellation_offers OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.funded_cancellation_offers FROM PUBLIC,securepay_payer_runtime,securepay_completion_runtime,securepay_dispute_runtime,securepay_provider_runtime,securepay_settlement_runtime;
CREATE TRIGGER sp_chain_funded_cancel AFTER INSERT OR UPDATE OR DELETE ON securepay_private.funded_cancellation_offers FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
CREATE FUNCTION securepay_private.funded_cancel_state(t uuid,z uuid,m uuid) RETURNS text
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT encode(public.digest(convert_to(jsonb_build_array('sp-funded-cancel-state-v1',p.plan_id,p.plan_digest,x.id,x.version,x.status,x.amount_cents,
 f.funding_ref,f.status,f.amount_cents,
 (SELECT jsonb_agg(to_jsonb(w) ORDER BY w.completion_id) FROM securepay_private.work_completion w WHERE w.tenant_id=t AND w.milestone_id=m),
 (SELECT jsonb_agg(jsonb_build_array(q.photo_id,q.digest,q.original_digest) ORDER BY q.photo_id) FROM securepay_private.work_photos q JOIN securepay_private.work_completion w ON w.completion_id=q.completion_id WHERE w.tenant_id=t AND w.milestone_id=m),
 (SELECT jsonb_agg(to_jsonb(r) ORDER BY r.id) FROM public.securepay_release_requests r WHERE r.tenant_id=t AND r.milestone_id=m),
 (SELECT jsonb_agg(to_jsonb(j) ORDER BY j.journal_id) FROM securepay_private.financial_journal j WHERE j.tenant_id=t AND j.milestone_id=m)
 )::text,'UTF8'),'sha256'),'hex')
 FROM securepay_private.payment_plans p
 JOIN securepay_private.payment_plan_milestones l ON l.plan_id=p.plan_id AND l.tenant_id=p.tenant_id
 JOIN public.securepay_milestones x ON x.tenant_id=l.tenant_id AND x.id=l.milestone_id
 JOIN securepay_private.provider_funding f ON f.tenant_id=x.tenant_id AND f.milestone_id=x.id
 WHERE p.tenant_id=t AND p.plan_id=z AND p.status='accepted' AND x.id=m AND x.payer_customer_id=p.customer_id
 AND x.status IN ('planned','submitted','approved','release_pending') AND f.status='funded' AND f.amount_cents=x.amount_cents
 AND NOT EXISTS(SELECT 1 FROM public.securepay_release_requests r WHERE r.tenant_id=t AND r.milestone_id=m AND r.status IN ('submitted','confirmed','failed'))
 AND NOT EXISTS(SELECT 1 FROM securepay_private.dispute_cases d WHERE d.tenant_id=t AND d.milestone_id=m)
 AND NOT EXISTS(SELECT 1 FROM securepay_private.provider_reconciliation r WHERE r.tenant_id=t AND r.milestone_id=m AND r.resolved_at IS NULL)
 AND securepay_private.verify_financial_journal(t,m)
 AND (SELECT remaining_cents FROM securepay_private.financial_balance(t,m))=x.amount_cents
$$;
CREATE FUNCTION securepay_private.funded_cancel_hash(v uuid,t uuid,z uuid,m uuid,a uuid,c uuid,payout bigint,refund bigint,reason text,sh text) RETURNS text
 LANGUAGE sql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT encode(public.digest(convert_to(jsonb_build_array('sp-funded-cancel-v1',v,t,z,m,a,c,payout,refund,reason,sh)::text,'UTF8'),'sha256'),'hex')
$$;
CREATE FUNCTION securepay_private.offer_funded_cancel(v uuid,t uuid,z uuid,m uuid,a uuid,payout bigint,refund bigint,reason text,expected_state text,expires bigint,sig text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE p securepay_private.payment_plans%ROWTYPE;x public.securepay_milestones%ROWTYPE;sh text;h text;
BEGIN
 IF v IS NULL OR t IS NULL OR z IS NULL OR m IS NULL OR a IS NULL OR payout IS NULL OR refund IS NULL OR payout<0 OR refund<=0
 OR reason IS NULL OR length(btrim(reason)) NOT BETWEEN 10 AND 2000 OR expected_state IS NULL OR expected_state !~ '^[a-f0-9]{64}$'
 OR securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-funded-cancel-offer-v1',v,t,z,m,a,payout,refund,encode(convert_to(reason,'UTF8'),'hex'),expected_state,expires),expires,sig) IS DISTINCT FROM 'owner' THEN RETURN NULL; END IF;
 SELECT * INTO p FROM securepay_private.payment_plans WHERE tenant_id=t AND plan_id=z AND owner_id=a AND status='accepted' FOR UPDATE;
 IF NOT FOUND OR (SELECT count(*) FROM securepay_private.funded_cancellation_offers WHERE plan_id=z)>=20 THEN RETURN NULL; END IF;
 SELECT * INTO x FROM public.securepay_milestones WHERE tenant_id=t AND id=m FOR UPDATE;
 IF NOT FOUND OR payout::numeric+refund::numeric<>x.amount_cents THEN RETURN NULL; END IF;
 PERFORM 1 FROM securepay_private.provider_funding WHERE tenant_id=t AND milestone_id=m FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL; END IF;
 sh:=securepay_private.funded_cancel_state(t,z,m);
 IF sh IS NULL OR sh<>expected_state THEN RETURN NULL; END IF;
 h:=securepay_private.funded_cancel_hash(v,t,z,m,a,p.customer_id,payout,refund,reason,sh);
 INSERT INTO securepay_private.funded_cancellation_offers(offer_id,tenant_id,plan_id,milestone_id,owner_id,customer_id,payout_cents,refund_cents,reason,state_digest,offer_digest)
 VALUES(v,t,z,m,a,p.customer_id,payout,refund,reason,sh,h);
 RETURN jsonb_build_object('offerId',v,'offerDigest',h,'payoutCents',payout::text,'refundCents',refund::text);
EXCEPTION WHEN unique_violation THEN RETURN NULL;
END $$;
CREATE FUNCTION securepay_private.accept_funded_cancel(t uuid,z uuid,v uuid,d uuid,e uuid,h text,payout bigint,refund bigint) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c uuid;p securepay_private.payment_plans%ROWTYPE;o securepay_private.funded_cancellation_offers%ROWTYPE;mid uuid;sh text;
BEGIN
 c:=securepay_private.current_payer(t);
 IF c IS NULL OR z IS NULL OR v IS NULL OR d IS NULL OR e IS NULL OR h IS NULL OR payout IS NULL OR refund IS NULL THEN RETURN false; END IF;
 SELECT * INTO p FROM securepay_private.payment_plans WHERE tenant_id=t AND plan_id=z AND customer_id=c AND status='accepted' FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT milestone_id INTO mid FROM securepay_private.funded_cancellation_offers WHERE tenant_id=t AND plan_id=z AND offer_id=v AND customer_id=c;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM 1 FROM public.securepay_milestones WHERE tenant_id=t AND id=mid FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM 1 FROM securepay_private.provider_funding WHERE tenant_id=t AND milestone_id=mid FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO o FROM securepay_private.funded_cancellation_offers WHERE tenant_id=t AND plan_id=z AND offer_id=v AND customer_id=c AND status='offered' FOR UPDATE;
 IF NOT FOUND OR o.owner_id<>p.owner_id OR o.offer_digest<>h OR o.payout_cents<>payout OR o.refund_cents<>refund OR
 NOT EXISTS(SELECT 1 FROM securepay_private.dispute_actors WHERE tenant_id=t AND actor_id=o.owner_id AND role='owner' AND active) THEN RETURN false; END IF;
 sh:=securepay_private.funded_cancel_state(t,z,mid);
 IF sh IS NULL OR sh<>o.state_digest OR securepay_private.funded_cancel_hash(v,t,z,mid,o.owner_id,c,payout,refund,o.reason,sh)<>h THEN RETURN false; END IF;
 -- Consent is evidence, not a final decision or transfer authorization.
 INSERT INTO securepay_private.dispute_cases(case_id,tenant_id,milestone_id,customer_id,owner_id,severity,status,customer_evidence,owner_evidence,owner_responded_at)
 VALUES(d,t,mid,c,o.owner_id,'moderate','open',true,true,clock_timestamp());
 INSERT INTO securepay_private.dispute_events(event_id,case_id,actor_id,action,details,evidence_digest,payout_cents,refund_cents)
 VALUES(e,d,c,'negotiated_cancellation',o.reason,h,payout,refund);
 UPDATE securepay_private.funded_cancellation_offers SET status='accepted',case_id=d,accepted_at=clock_timestamp() WHERE offer_id=v;
 UPDATE public.securepay_release_requests SET status='failed' WHERE tenant_id=t AND milestone_id=mid AND status='pending';
 DELETE FROM public.securepay_release_proofs WHERE tenant_id=t AND milestone_id=mid AND consumed_at IS NULL;
 UPDATE public.securepay_milestones SET status='disputed',version=version+1,updated_at=clock_timestamp() WHERE tenant_id=t AND id=mid;
 RETURN true;
EXCEPTION WHEN unique_violation THEN RETURN false;
END $$;
CREATE FUNCTION securepay_private.withdraw_funded_cancel(t uuid,z uuid,v uuid,a uuid,expires bigint,sig text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-funded-cancel-withdraw-v1',t,z,v,a,expires),expires,sig) IS DISTINCT FROM 'owner' THEN RETURN false; END IF;
 PERFORM 1 FROM securepay_private.payment_plans WHERE tenant_id=t AND plan_id=z AND owner_id=a AND status='accepted' FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 UPDATE securepay_private.funded_cancellation_offers SET status='withdrawn' WHERE tenant_id=t AND plan_id=z AND offer_id=v AND owner_id=a AND status='offered';
 RETURN FOUND;
END $$;
CREATE FUNCTION securepay_private.funded_cancel_view(t uuid,z uuid) RETURNS jsonb
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('planId',z,'stages',(SELECT jsonb_agg(jsonb_build_object('milestoneId',m.id,'amountCents',m.amount_cents::text,'description',l.description,'status',m.status,'stateDigest',securepay_private.funded_cancel_state(t,z,m.id)) ORDER BY l.stage)
 FROM securepay_private.payment_plan_milestones l JOIN public.securepay_milestones m ON m.tenant_id=l.tenant_id AND m.id=l.milestone_id WHERE l.tenant_id=t AND l.plan_id=z),
 'offers',(SELECT coalesce(jsonb_agg(jsonb_build_object('offerId',o.offer_id,'milestoneId',o.milestone_id,'payoutCents',o.payout_cents::text,'refundCents',o.refund_cents::text,'reason',o.reason,'offerDigest',o.offer_digest,'status',o.status,
 'current',coalesce(o.status='offered' AND o.state_digest=securepay_private.funded_cancel_state(t,z,o.milestone_id),false),'caseId',o.case_id,'caseStatus',c.status,'decisionPayoutCents',c.payout_cents::text,'decisionRefundCents',c.refund_cents::text,'customerAcknowledged',c.customer_ack,'ownerAcknowledged',c.owner_ack,'decision',(SELECT jsonb_build_object('eventId',e.event_id,'reason',e.details,'evidenceDigest',e.evidence_digest) FROM securepay_private.dispute_events e WHERE e.case_id=c.case_id AND e.action IN ('decide','finalize') ORDER BY e.occurred_at DESC,e.event_id DESC LIMIT 1),'confirmedPayoutCents',b.payout_cents::text,'confirmedRefundCents',b.refund_cents::text,'remainingCents',b.remaining_cents::text) ORDER BY o.created_at,o.offer_id),'[]'::jsonb)
 FROM securepay_private.funded_cancellation_offers o LEFT JOIN securepay_private.dispute_cases c ON c.case_id=o.case_id
 CROSS JOIN LATERAL securepay_private.financial_balance(t,o.milestone_id) b WHERE o.tenant_id=t AND o.plan_id=z))
$$;
CREATE FUNCTION securepay_private.payer_funded_cancel_view(t uuid,z uuid) RETURNS jsonb
 LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT securepay_private.funded_cancel_view(t,z) FROM securepay_private.payment_plans p WHERE p.tenant_id=t AND p.plan_id=z AND p.status='accepted' AND p.customer_id=securepay_private.current_payer(t)
$$;
CREATE FUNCTION securepay_private.owner_funded_cancel_view(t uuid,z uuid,a uuid,expires bigint,sig text) RETURNS jsonb
 LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT securepay_private.funded_cancel_view(t,z) FROM securepay_private.payment_plans p WHERE p.tenant_id=t AND p.plan_id=z AND p.status='accepted' AND p.owner_id=a AND securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-funded-cancel-view-v1',t,z,a,expires),expires,sig)='owner'
$$;
-- Payer acknowledgement of a reasoned provisional decision; the second
-- reviewer and separate authorizer still gate settlement. No automatic release.
CREATE FUNCTION securepay_private.payer_ack_negotiated(t uuid,z uuid,v uuid,e uuid,decision uuid,payout bigint,refund bigint) RETURNS boolean
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
 IF NOT FOUND OR d.customer_ack OR d.payout_cents<>payout OR d.refund_cents<>refund OR NOT EXISTS(SELECT 1 FROM securepay_private.dispute_events WHERE case_id=d.case_id AND event_id=decision AND action='decide' AND payout_cents=payout AND refund_cents=refund) THEN RETURN false; END IF;
 UPDATE securepay_private.dispute_cases SET customer_ack=true WHERE case_id=d.case_id;
 INSERT INTO securepay_private.dispute_events(event_id,case_id,actor_id,action,details,payout_cents,refund_cents)
 VALUES(e,d.case_id,c,'ack','Customer acknowledged exact reasoned provisional decision',payout,refund);
 RETURN true;
EXCEPTION WHEN unique_violation THEN RETURN false;
END $$;
ALTER FUNCTION securepay_private.funded_cancel_state(uuid,uuid,uuid) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.funded_cancel_state(uuid,uuid,uuid) FROM PUBLIC;
ALTER FUNCTION securepay_private.funded_cancel_hash(uuid,uuid,uuid,uuid,uuid,uuid,bigint,bigint,text,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.funded_cancel_hash(uuid,uuid,uuid,uuid,uuid,uuid,bigint,bigint,text,text) FROM PUBLIC;
ALTER FUNCTION securepay_private.offer_funded_cancel(uuid,uuid,uuid,uuid,uuid,bigint,bigint,text,text,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.offer_funded_cancel(uuid,uuid,uuid,uuid,uuid,bigint,bigint,text,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.offer_funded_cancel(uuid,uuid,uuid,uuid,uuid,bigint,bigint,text,text,bigint,text) TO securepay_completion_runtime;
ALTER FUNCTION securepay_private.accept_funded_cancel(uuid,uuid,uuid,uuid,uuid,text,bigint,bigint) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.accept_funded_cancel(uuid,uuid,uuid,uuid,uuid,text,bigint,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.accept_funded_cancel(uuid,uuid,uuid,uuid,uuid,text,bigint,bigint) TO securepay_payer_runtime;
ALTER FUNCTION securepay_private.withdraw_funded_cancel(uuid,uuid,uuid,uuid,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.withdraw_funded_cancel(uuid,uuid,uuid,uuid,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.withdraw_funded_cancel(uuid,uuid,uuid,uuid,bigint,text) TO securepay_completion_runtime;
ALTER FUNCTION securepay_private.funded_cancel_view(uuid,uuid) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.funded_cancel_view(uuid,uuid) FROM PUBLIC;
ALTER FUNCTION securepay_private.payer_funded_cancel_view(uuid,uuid) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.payer_funded_cancel_view(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.payer_funded_cancel_view(uuid,uuid) TO securepay_payer_runtime;
ALTER FUNCTION securepay_private.owner_funded_cancel_view(uuid,uuid,uuid,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.owner_funded_cancel_view(uuid,uuid,uuid,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.owner_funded_cancel_view(uuid,uuid,uuid,bigint,text) TO securepay_completion_runtime;
ALTER FUNCTION securepay_private.payer_ack_negotiated(uuid,uuid,uuid,uuid,uuid,bigint,bigint) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.payer_ack_negotiated(uuid,uuid,uuid,uuid,uuid,bigint,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.payer_ack_negotiated(uuid,uuid,uuid,uuid,uuid,bigint,bigint) TO securepay_payer_runtime;
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
   IF EXISTS(SELECT 1 FROM securepay_private.funded_cancellation_offers WHERE case_id=d) AND NOT EXISTS(SELECT 1 FROM securepay_private.dispute_photo_reviewers WHERE case_id=d AND tenant_id=t AND reviewer_id=a) THEN RETURN false; END IF;
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
CREATE FUNCTION securepay_private.payer_appeal_negotiated(t uuid,z uuid,v uuid,e uuid,decision uuid,reason text,digest text) RETURNS boolean
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
 IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM securepay_private.dispute_events WHERE case_id=d.case_id AND event_id=decision AND action='decide') THEN RETURN false; END IF;
 UPDATE securepay_private.dispute_cases SET status='appealed',customer_appeal_evidence=true,owner_appeal_evidence=false WHERE case_id=d.case_id;
 INSERT INTO securepay_private.dispute_events(event_id,case_id,actor_id,action,details,evidence_digest) VALUES(e,d.case_id,c,'appeal',reason,digest);
 RETURN true;
EXCEPTION WHEN unique_violation THEN RETURN false;
END $$;
ALTER FUNCTION securepay_private.payer_appeal_negotiated(uuid,uuid,uuid,uuid,uuid,text,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.payer_appeal_negotiated(uuid,uuid,uuid,uuid,uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.payer_appeal_negotiated(uuid,uuid,uuid,uuid,uuid,text,text) TO securepay_payer_runtime;

CREATE FUNCTION securepay_private.owner_ack_negotiated(t uuid,z uuid,v uuid,e uuid,decision uuid,a uuid,payout bigint,refund bigint,expires bigint,sig text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE o securepay_private.funded_cancellation_offers%ROWTYPE;d securepay_private.dispute_cases%ROWTYPE;
BEGIN
 IF t IS NULL OR z IS NULL OR v IS NULL OR e IS NULL OR decision IS NULL OR a IS NULL OR payout IS NULL OR refund IS NULL OR securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-negotiated-ack-v1',t,z,v,e,decision,a,payout,refund,expires),expires,sig) IS DISTINCT FROM 'owner' THEN RETURN false; END IF;
 SELECT * INTO o FROM securepay_private.funded_cancellation_offers WHERE tenant_id=t AND plan_id=z AND offer_id=v AND owner_id=a AND status='accepted';
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM 1 FROM public.securepay_milestones WHERE tenant_id=t AND id=o.milestone_id AND status='disputed' FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO d FROM securepay_private.dispute_cases WHERE case_id=o.case_id AND tenant_id=t AND owner_id=a AND status='decided' FOR UPDATE;
 IF NOT FOUND OR d.owner_ack OR d.payout_cents<>payout OR d.refund_cents<>refund OR NOT EXISTS(SELECT 1 FROM securepay_private.dispute_events WHERE case_id=d.case_id AND event_id=decision AND action='decide' AND payout_cents=payout AND refund_cents=refund) THEN RETURN false; END IF;
 UPDATE securepay_private.dispute_cases SET owner_ack=true WHERE case_id=d.case_id;
 INSERT INTO securepay_private.dispute_events(event_id,case_id,actor_id,action,details,payout_cents,refund_cents)
 VALUES(e,d.case_id,a,'ack','Owner acknowledged exact reasoned provisional decision',payout,refund);
 RETURN true;
EXCEPTION WHEN unique_violation THEN RETURN false;
END $$;
ALTER FUNCTION securepay_private.owner_ack_negotiated(uuid,uuid,uuid,uuid,uuid,uuid,bigint,bigint,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.owner_ack_negotiated(uuid,uuid,uuid,uuid,uuid,uuid,bigint,bigint,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.owner_ack_negotiated(uuid,uuid,uuid,uuid,uuid,uuid,bigint,bigint,bigint,text) TO securepay_completion_runtime;

COMMIT;

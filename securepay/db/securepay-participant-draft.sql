-- Scoped ordinary-dispute participant boundary. No settlement or review authority.
BEGIN;
CREATE TABLE securepay_private.participant_photo_reads(
 case_id uuid NOT NULL REFERENCES securepay_private.dispute_cases(case_id),tenant_id uuid NOT NULL,actor_id uuid NOT NULL,photo_id uuid NOT NULL,
 digest text NOT NULL CHECK(digest ~ '^[a-f0-9]{64}$'),read_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(case_id,actor_id,photo_id,digest)
);
ALTER TABLE securepay_private.participant_photo_reads OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.participant_photo_reads FROM PUBLIC,securepay_payer_runtime,securepay_completion_runtime;
CREATE TRIGGER sp_chain_participant_reads AFTER INSERT ON securepay_private.participant_photo_reads FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
-- A verified payer's internal signing actor is provisioned only for its own case.
CREATE FUNCTION securepay_private.ensure_case_customer() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 INSERT INTO securepay_private.dispute_actors(tenant_id,actor_id,role,secret) VALUES(NEW.tenant_id,NEW.customer_id,'customer',public.gen_random_bytes(32)) ON CONFLICT DO NOTHING;
 RETURN NEW;
END $$;
ALTER FUNCTION securepay_private.ensure_case_customer() OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.ensure_case_customer() FROM PUBLIC;
CREATE TRIGGER sp_case_customer_actor AFTER INSERT ON securepay_private.dispute_cases FOR EACH ROW EXECUTE FUNCTION securepay_private.ensure_case_customer();
INSERT INTO securepay_private.dispute_actors(tenant_id,actor_id,role,secret)
 SELECT DISTINCT tenant_id,customer_id,'customer',public.gen_random_bytes(32) FROM securepay_private.dispute_cases ON CONFLICT DO NOTHING;
CREATE FUNCTION securepay_private.participant_snapshot(t uuid,m uuid,a uuid) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c securepay_private.dispute_cases%ROWTYPE;r jsonb;
BEGIN
 SELECT * INTO c FROM securepay_private.dispute_cases WHERE tenant_id=t AND milestone_id=m AND a IN(customer_id,owner_id);
 IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM securepay_private.dispute_actors x WHERE x.tenant_id=t AND x.actor_id=a AND x.active AND x.role=CASE WHEN a=c.customer_id THEN 'customer' ELSE 'owner' END) THEN RETURN NULL; END IF;
 IF (SELECT count(*) FROM securepay_private.dispute_events WHERE case_id=c.case_id)>200 THEN RAISE EXCEPTION 'Case history capacity exceeded'; END IF;
 SELECT jsonb_build_object('caseId',c.case_id,'milestoneId',m,'role',CASE WHEN a=c.customer_id THEN 'customer' ELSE 'owner' END,
 'status',c.status,'severity',c.severity,'repairPhase',c.repair_phase,'repairPhotoId',c.repair_photo_id,'repairDueAt',c.repair_due_at,'repairReviewDueAt',c.repair_review_due_at,
 'responseDueAt',c.response_due_at,'ownerRespondedAt',c.owner_responded_at,'customerEvidence',c.customer_evidence,'ownerEvidence',c.owner_evidence,
 'customerAck',c.customer_ack,'ownerAck',c.owner_ack,'customerAppealEvidence',c.customer_appeal_evidence,'ownerAppealEvidence',c.owner_appeal_evidence,
 'amountCents',x.amount_cents::text,'payoutCents',c.payout_cents::text,'refundCents',c.refund_cents::text,
 'fundingStatus',f.status,'confirmedPayoutCents',b.payout_cents::text,'confirmedRefundCents',b.refund_cents::text,'remainingCents',b.remaining_cents::text,
 'negotiated',EXISTS(SELECT 1 FROM securepay_private.funded_cancellation_offers o WHERE o.case_id=c.case_id),
 'decision',(SELECT jsonb_build_object('eventId',e.event_id,'reason',e.details,'digest',e.evidence_digest) FROM securepay_private.dispute_events e WHERE e.case_id=c.case_id AND c.status<>'open' AND e.action IN ('decide','finalize') ORDER BY e.occurred_at DESC,e.event_id DESC LIMIT 1),
 'events',(SELECT coalesce(jsonb_agg(jsonb_build_object('eventId',e.event_id,'action',e.action,'details',e.details,'at',e.occurred_at,'digest',e.evidence_digest,'role',CASE WHEN e.actor_id=c.owner_id THEN 'owner' WHEN e.actor_id=c.customer_id THEN 'customer' ELSE 'independent' END) ORDER BY e.occurred_at,e.event_id),'[]'::jsonb) FROM securepay_private.dispute_events e WHERE e.case_id=c.case_id AND (e.action IN ('open','open_work','negotiated_cancellation','evidence','decide','finalize','ack','appeal') OR e.action LIKE 'repair_%')),
 'photos',(SELECT coalesce(jsonb_agg(jsonb_build_object('photoId',p.photo_id,'digest',p.digest,'purged',p.purged_at IS NOT NULL,'source','dispute','mine',p.actor_id=a) ORDER BY p.photo_id),'[]'::jsonb) FROM securepay_private.dispute_photos p WHERE p.case_id=c.case_id),
 'linkedPhotos',(SELECT coalesce(jsonb_agg(jsonb_build_object('photoId',p.photo_id,'digest',p.digest,'purged',p.purged_at IS NOT NULL,'source','completion','mine',a=c.owner_id) ORDER BY p.photo_id),'[]'::jsonb) FROM securepay_private.work_dispute_links l JOIN securepay_private.work_photos p ON p.completion_id=l.completion_id WHERE l.case_id=c.case_id AND l.tenant_id=t))
 INTO r FROM public.securepay_milestones x JOIN securepay_private.provider_funding f ON f.tenant_id=x.tenant_id AND f.milestone_id=x.id CROSS JOIN LATERAL securepay_private.financial_balance(t,m) b WHERE x.tenant_id=t AND x.id=m;
 RETURN r;
END $$;
CREATE FUNCTION securepay_private.participant_command(t uuid,m uuid,a uuid,op text,body jsonb) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c securepay_private.dispute_cases%ROWTYPE;s jsonb;k bytea;exp bigint;ev uuid;ph uuid;src text;reason text;h text;inner_sig text;v jsonb;due bigint;act text;blob bytea;dg text;original text;mime text;scan_exp bigint;envelope text;
BEGIN
 IF t IS NULL OR m IS NULL OR a IS NULL OR op IS NULL OR body IS NULL OR jsonb_typeof(body)<>'object' THEN RETURN NULL; END IF;
 PERFORM 1 FROM public.securepay_milestones WHERE tenant_id=t AND id=m FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL; END IF;
 PERFORM 1 FROM securepay_private.provider_funding WHERE tenant_id=t AND milestone_id=m FOR UPDATE;
 SELECT * INTO c FROM securepay_private.dispute_cases WHERE tenant_id=t AND milestone_id=m AND a IN(customer_id,owner_id) FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL; END IF;
 SELECT secret INTO k FROM securepay_private.dispute_actors WHERE tenant_id=t AND actor_id=a AND active AND role=CASE WHEN a=c.customer_id THEN 'customer' ELSE 'owner' END;
 IF k IS NULL THEN RETURN NULL; END IF;
 s:=securepay_private.participant_snapshot(t,m,a);IF s IS NULL THEN RETURN NULL; END IF;
 h:=encode(public.digest(convert_to(s::text,'UTF8'),'sha256'),'hex');
 exp:=floor(extract(epoch FROM clock_timestamp()))::bigint+15;ev:=gen_random_uuid();
 IF op='view' AND body='{}'::jsonb THEN
  PERFORM securepay_private.append_audit_chain(t,'participant_case','READ',encode(public.digest(convert_to(concat_ws(':',c.case_id,a,h),'UTF8'),'sha256'),'hex'));
  RETURN jsonb_build_object('case',s,'stateDigest',h);
 END IF;
 IF body->>'caseId' IS DISTINCT FROM c.case_id::text THEN RETURN NULL; END IF;
 IF op='photo' THEN
  ph:=(body->>'photoId')::uuid;src:=body->>'source';
  IF src='completion' THEN
   inner_sig:=encode(public.hmac(convert_to(concat_ws(':','sp-linked-work-v1',t,m,c.case_id,a,ph,exp),'UTF8'),k,'sha256'),'hex');
   v:=securepay_private.dispute_work_evidence(t,m,c.case_id,a,ph,exp,inner_sig);
  ELSIF src='dispute' THEN
   inner_sig:=encode(public.hmac(convert_to(concat_ws(':','sp-photo-read-v1',ph,t,m,c.case_id,a,exp),'UTF8'),k,'sha256'),'hex');
   SELECT jsonb_build_object('photoId',ph,'digest',p.digest,'content',replace(encode(p.content,'base64'),chr(10),'')) INTO v FROM securepay_private.read_dispute_photo(ph,t,m,c.case_id,a,exp,inner_sig) p WHERE p.media_type='image/png';
   IF v IS NOT NULL THEN INSERT INTO securepay_private.participant_photo_reads(tenant_id,case_id,actor_id,photo_id,digest) VALUES(t,c.case_id,a,ph,v->>'digest') ON CONFLICT DO NOTHING; END IF;
  ELSE RETURN NULL; END IF;
  RETURN v;
 END IF;
 IF op='upload' THEN
  ph:=(body->>'photoId')::uuid;dg:=body->>'digest';original:=body->>'originalDigest';mime:=body->>'originalMediaType';
  scan_exp:=(body->>'scanExpiry')::bigint;envelope:=body->>'scanSignature';
  IF length(body->>'content')>2796204 THEN RETURN NULL; END IF;
  blob:=decode(body->>'content','base64');
  inner_sig:=encode(public.hmac(convert_to(concat_ws(':','sp-photo-v1',ph,t,m,c.case_id,a,'image/png',dg,exp),'UTF8'),k,'sha256'),'hex');
  IF securepay_private.store_screened_photo_v2(ph,t,m,c.case_id,a,'image/png',dg,blob,exp,inner_sig,scan_exp,envelope,mime,original) IS DISTINCT FROM true THEN RETURN NULL; END IF;
  RETURN jsonb_build_object('photoId',ph,'digest',dg);
 END IF;
 IF body->>'stateDigest' IS DISTINCT FROM h THEN RETURN NULL; END IF;
 reason:=body->>'reason';IF reason IS NULL OR length(btrim(reason)) NOT BETWEEN 10 AND 2000 THEN RETURN NULL; END IF;
 IF op IN ('evidence','ack','appeal') THEN
  IF op='evidence' THEN
   IF c.status NOT IN ('open','appealed') THEN RETURN NULL; END IF;
   dg:=encode(public.digest(convert_to(reason,'UTF8'),'sha256'),'hex');
   IF a=c.customer_id THEN UPDATE securepay_private.dispute_cases SET customer_evidence=true,customer_appeal_evidence=customer_appeal_evidence OR c.status='appealed' WHERE case_id=c.case_id;
   ELSE UPDATE securepay_private.dispute_cases SET owner_evidence=true,owner_appeal_evidence=owner_appeal_evidence OR c.status='appealed',owner_responded_at=coalesce(owner_responded_at,clock_timestamp()) WHERE case_id=c.case_id; END IF;
  ELSE
   IF c.status<>'decided' OR body->>'decisionId' IS DISTINCT FROM s->'decision'->>'eventId' OR body->>'payoutCents' IS DISTINCT FROM c.payout_cents::text OR body->>'refundCents' IS DISTINCT FROM c.refund_cents::text THEN RETURN NULL; END IF;
   dg:=s->'decision'->>'digest';
   IF op='appeal' THEN
    dg:=encode(public.digest(convert_to(reason,'UTF8'),'sha256'),'hex');
    UPDATE securepay_private.dispute_cases SET status='appealed',customer_appeal_evidence=(a=c.customer_id),owner_appeal_evidence=(a=c.owner_id) WHERE case_id=c.case_id;
   ELSIF a=c.customer_id AND NOT c.customer_ack THEN UPDATE securepay_private.dispute_cases SET customer_ack=true WHERE case_id=c.case_id;
   ELSIF a=c.owner_id AND NOT c.owner_ack THEN UPDATE securepay_private.dispute_cases SET owner_ack=true WHERE case_id=c.case_id;
   ELSE RETURN NULL; END IF;
  END IF;
  INSERT INTO securepay_private.dispute_events(event_id,case_id,actor_id,action,details,evidence_digest,payout_cents,refund_cents) VALUES(ev,c.case_id,a,op,reason,dg,CASE WHEN op='ack' THEN c.payout_cents END,CASE WHEN op='ack' THEN c.refund_cents END);
  RETURN jsonb_build_object('recorded',true);
 END IF;
 IF op='repair' THEN
  act:=body->>'action';due:=(body->>'dueEpoch')::bigint;ph:=(body->>'photoId')::uuid;
  IF act IS NULL OR act NOT IN ('propose','accept_plan','submit_repair','accept_repair','escalate') THEN RETURN NULL; END IF;
  IF act='accept_repair' AND NOT EXISTS(SELECT 1 FROM securepay_private.participant_photo_reads v JOIN securepay_private.dispute_photos p ON p.photo_id=v.photo_id AND p.case_id=v.case_id AND p.digest=v.digest WHERE v.case_id=c.case_id AND v.actor_id=a AND v.photo_id=ph AND p.purged_at IS NULL) THEN RETURN NULL; END IF;
  inner_sig:=encode(public.hmac(convert_to(concat_ws(':','sp-repair-v1',ev,t,m,c.case_id,a,act,encode(convert_to(reason,'UTF8'),'hex'),coalesce(due::text,'-'),coalesce(ph::text,'-'),exp),'UTF8'),k,'sha256'),'hex');
  IF securepay_private.repair_action(ev,t,m,c.case_id,a,act,reason,due,ph,exp,inner_sig) IS DISTINCT FROM true THEN RETURN NULL; END IF;
  RETURN jsonb_build_object('recorded',true);
 END IF;
 RETURN NULL;
EXCEPTION WHEN unique_violation OR invalid_text_representation OR invalid_parameter_value OR numeric_value_out_of_range THEN RETURN NULL;
END $$;
CREATE FUNCTION securepay_private.payer_participant(t uuid,m uuid,op text,body jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a uuid;
BEGIN
 a:=securepay_private.current_payer(t);IF a IS NULL THEN RETURN NULL; END IF;
 IF NOT EXISTS(SELECT 1 FROM securepay_private.dispute_cases WHERE tenant_id=t AND milestone_id=m AND customer_id=a) THEN RETURN NULL; END IF;
 RETURN securepay_private.participant_command(t,m,a,op,body);
END $$;
CREATE FUNCTION securepay_private.owner_participant(t uuid,m uuid,a uuid,op text,body text,expires bigint,sig text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF body IS NULL OR octet_length(body)>2800000 OR securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-participant-v1',t,m,a,op,encode(public.digest(convert_to(body,'UTF8'),'sha256'),'hex'),expires),expires,sig) IS DISTINCT FROM 'owner' THEN RETURN NULL; END IF;
 IF NOT EXISTS(SELECT 1 FROM securepay_private.dispute_cases WHERE tenant_id=t AND milestone_id=m AND owner_id=a) THEN RETURN NULL; END IF;
 RETURN securepay_private.participant_command(t,m,a,op,body::jsonb);
END $$;
ALTER FUNCTION securepay_private.ensure_case_customer() OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.ensure_case_customer() FROM PUBLIC;
ALTER FUNCTION securepay_private.participant_snapshot(uuid,uuid,uuid) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.participant_snapshot(uuid,uuid,uuid) FROM PUBLIC;
ALTER FUNCTION securepay_private.participant_command(uuid,uuid,uuid,text,jsonb) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.participant_command(uuid,uuid,uuid,text,jsonb) FROM PUBLIC;
ALTER FUNCTION securepay_private.payer_participant(uuid,uuid,text,jsonb) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.payer_participant(uuid,uuid,text,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.payer_participant(uuid,uuid,text,jsonb) TO securepay_payer_runtime;
ALTER FUNCTION securepay_private.owner_participant(uuid,uuid,uuid,text,text,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.owner_participant(uuid,uuid,uuid,text,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.owner_participant(uuid,uuid,uuid,text,text,bigint,text) TO securepay_completion_runtime;
COMMIT;

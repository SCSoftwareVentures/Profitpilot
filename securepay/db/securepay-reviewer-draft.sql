-- Narrow independent reviewer boundary, assigned cases only.
BEGIN;
CREATE ROLE securepay_reviewer_runtime NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS;
GRANT USAGE ON SCHEMA securepay_private TO securepay_reviewer_runtime;
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
  RETURN securepay_private.dispute_work_evidence(t,mid,d,a,p,expires,inner_sig);
 END IF;
 inner_sig:=encode(public.hmac(convert_to(concat_ws(':','sp-photo-read-v1',p,t,mid,d,a,expires),'UTF8'),k,'sha256'),'hex');
 SELECT jsonb_build_object('photoId',p,'digest',q.digest,'content',replace(encode(q.content,'base64'),chr(10),'')) INTO r FROM securepay_private.read_dispute_photo(p,t,mid,d,a,expires,inner_sig) q WHERE q.media_type='image/png';
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
 IF h<>state_hash THEN RETURN false; END IF;
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
COMMIT;

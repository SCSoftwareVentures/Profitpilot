-- Correction assessment: signed, non-executing remedy plan. Never rewrites
-- original allocations, provider receipts, or the financial journal.
BEGIN;
CREATE TABLE securepay_private.settlement_correction_cases(
 correction_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,case_id uuid NOT NULL REFERENCES securepay_private.governed_cases(case_id),
 settlement_id uuid NOT NULL REFERENCES securepay_private.dispute_settlements(settlement_id),
 administrator_id uuid NOT NULL,actor_one uuid NOT NULL,actor_two uuid NOT NULL,
 proposed_payout bigint NOT NULL CHECK(proposed_payout>=0),proposed_refund bigint NOT NULL CHECK(proposed_refund>=0),
 reason text NOT NULL CHECK(length(btrim(reason)) BETWEEN 10 AND 1000),
 snapshot jsonb NOT NULL,state_digest text NOT NULL CHECK(state_digest ~ '^[a-f0-9]{64}$'),
 status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','superseded','endorsed')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),resolved_at timestamptz,
 evidence_digest text CHECK(evidence_digest ~ '^[a-f0-9]{64}$'),provider_key_id text,
 endorsement_digest text CHECK(endorsement_digest ~ '^[a-f0-9]{64}$'),
 CHECK(actor_one<>actor_two),CHECK((status='pending')=(resolved_at IS NULL)),
 CHECK((status='endorsed')=(evidence_digest IS NOT NULL AND provider_key_id IS NOT NULL AND endorsement_digest IS NOT NULL))
);
ALTER TABLE securepay_private.settlement_correction_cases OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.settlement_correction_cases FROM PUBLIC,securepay_dispute_admin_runtime,securepay_reconciliation_runtime,securepay_provider_runtime,securepay_settlement_runtime,securepay_settlement_dashboard_runtime,securepay_reviewer_runtime;
CREATE UNIQUE INDEX sp_correction_pending ON securepay_private.settlement_correction_cases(case_id) WHERE status='pending';
CREATE UNIQUE INDEX sp_correction_endorsed ON securepay_private.settlement_correction_cases(case_id) WHERE status='endorsed';
CREATE TRIGGER sp_chain_correction AFTER INSERT OR UPDATE OR DELETE ON securepay_private.settlement_correction_cases FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
CREATE FUNCTION securepay_private.correction_snapshot(t uuid,d uuid,p bigint,q bigint) RETURNS jsonb
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('caseId',d,'milestoneId',c.milestone_id,'settlementId',s.settlement_id,'fundedCents',b.funded_cents::text,
 'originalPayoutCents',s.payout_cents::text,'originalRefundCents',s.refund_cents::text,'proposedPayoutCents',p::text,'proposedRefundCents',q::text,
 'confirmedPayoutCents',b.payout_cents::text,'confirmedRefundCents',b.refund_cents::text,'remainingCents',b.remaining_cents::text,
 'possibleBusinessRecoveryCents',greatest(b.payout_cents-p,0)::text,'possibleCustomerRecoveryCents',greatest(b.refund_cents-q,0)::text,
 'outstandingBusinessAllocationCents',greatest(p-b.payout_cents,0)::text,'outstandingCustomerAllocationCents',greatest(q-b.refund_cents,0)::text,
 'caseStatus',c.status,'fundingStatus',f.status,'providerStateDigest',securepay_private.recovery_state(s.settlement_id,t,c.milestone_id,d),
 'safeToEndorse',f.status IN ('funded','settled') AND NOT EXISTS(SELECT 1 FROM securepay_private.settlement_legs l WHERE l.settlement_id=s.settlement_id AND l.status IN ('submitted','unknown'))
 AND NOT EXISTS(SELECT 1 FROM securepay_private.provider_reconciliation x WHERE x.tenant_id=t AND x.milestone_id=c.milestone_id AND x.resolved_at IS NULL)
 AND NOT EXISTS(SELECT 1 FROM securepay_private.settlement_leg_conflicts x WHERE x.case_id=d AND x.resolved_at IS NULL))
 FROM securepay_private.dispute_cases c JOIN securepay_private.dispute_settlements s ON s.case_id=c.case_id
 JOIN securepay_private.provider_funding f ON f.tenant_id=t AND f.milestone_id=c.milestone_id
 CROSS JOIN LATERAL securepay_private.financial_balance(t,c.milestone_id) b
 WHERE c.tenant_id=t AND c.case_id=d AND c.status IN ('authorized','settled') AND p>=0 AND q>=0
 AND p::numeric+q::numeric=b.funded_cents AND (p<>s.payout_cents OR q<>s.refund_cents)
 AND b.funded_cents=f.amount_cents AND securepay_private.verify_financial_journal(t,c.milestone_id)
$$;
CREATE FUNCTION securepay_private.correction_people_valid(t uuid,d uuid,a uuid,b uuid) RETURNS boolean
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT securepay_private.recovery_people_independent(t,d,a,b)
 AND EXISTS(SELECT 1 FROM securepay_private.dispute_actors WHERE tenant_id=t AND actor_id=a AND active AND role='reconciler')
 AND EXISTS(SELECT 1 FROM securepay_private.dispute_actors WHERE tenant_id=t AND actor_id=b AND active AND role='reconciler')
$$;
CREATE FUNCTION securepay_private.correction_request(r uuid,t uuid,d uuid,a uuid,u uuid,v uuid,p bigint,q bigint,reason text,expires bigint,sig text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE mid uuid;s jsonb;h text;
BEGIN
 IF r IS NULL OR u IS NULL OR v IS NULL OR p IS NULL OR q IS NULL OR reason IS NULL OR length(btrim(reason)) NOT BETWEEN 10 AND 1000
 OR securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-correction-request-v1',r,t,d,a,u,v,p,q,encode(convert_to(reason,'UTF8'),'hex'),expires),expires,sig) IS DISTINCT FROM 'administrator' THEN RETURN NULL; END IF;
 SELECT milestone_id INTO mid FROM securepay_private.dispute_cases WHERE tenant_id=t AND case_id=d;
 IF NOT FOUND THEN RETURN NULL; END IF;
 PERFORM 1 FROM public.securepay_milestones WHERE tenant_id=t AND id=mid FOR UPDATE;
 PERFORM 1 FROM securepay_private.provider_funding WHERE tenant_id=t AND milestone_id=mid FOR UPDATE;
 PERFORM 1 FROM securepay_private.dispute_cases WHERE tenant_id=t AND case_id=d FOR UPDATE;
 IF NOT EXISTS(SELECT 1 FROM securepay_private.governed_cases WHERE tenant_id=t AND case_id=d AND administrator_id=a)
 OR NOT securepay_private.reassessment_admin_valid(t,d,a) OR NOT securepay_private.correction_people_valid(t,d,u,v)
 OR EXISTS(SELECT 1 FROM securepay_private.settlement_correction_cases WHERE case_id=d AND status='endorsed')
 OR (SELECT count(*) FROM securepay_private.settlement_correction_cases WHERE case_id=d)>=10 THEN RETURN NULL; END IF;
 s:=securepay_private.correction_snapshot(t,d,p,q);
 IF s IS NULL THEN RETURN NULL; END IF;
 h:=encode(public.digest(convert_to(s::text,'UTF8'),'sha256'),'hex');
 UPDATE securepay_private.settlement_correction_cases SET status='superseded',resolved_at=clock_timestamp() WHERE case_id=d AND status='pending';
 INSERT INTO securepay_private.settlement_correction_cases(correction_id,tenant_id,case_id,settlement_id,administrator_id,actor_one,actor_two,proposed_payout,proposed_refund,reason,snapshot,state_digest)
 VALUES(r,t,d,(s->>'settlementId')::uuid,a,u,v,p,q,reason,s,h);
 RETURN jsonb_build_object('correctionId',r,'stateDigest',h,'snapshot',s,'status','pending');
EXCEPTION WHEN unique_violation THEN RETURN NULL;
END $$;
CREATE FUNCTION securepay_private.correction_read(t uuid,r uuid,a uuid,expires bigint,sig text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c securepay_private.settlement_correction_cases%ROWTYPE;role_name text;h text;
BEGIN
 role_name:=securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-correction-read-v1',t,r,a,expires),expires,sig);
 IF role_name IS NULL OR role_name NOT IN ('administrator','reconciler') THEN RETURN NULL; END IF;
 SELECT * INTO c FROM securepay_private.settlement_correction_cases WHERE tenant_id=t AND correction_id=r;
 IF NOT FOUND THEN RETURN NULL; END IF;
 IF role_name='administrator' THEN
  IF NOT EXISTS(SELECT 1 FROM securepay_private.governed_cases WHERE tenant_id=t AND case_id=c.case_id AND administrator_id=a) THEN RETURN NULL; END IF;
 ELSE
  IF a NOT IN(c.actor_one,c.actor_two) OR NOT securepay_private.correction_people_valid(t,c.case_id,c.actor_one,c.actor_two) THEN RETURN NULL; END IF;
 END IF;
 h:=encode(public.digest(convert_to(securepay_private.correction_snapshot(t,c.case_id,c.proposed_payout,c.proposed_refund)::text,'UTF8'),'sha256'),'hex');
 PERFORM securepay_private.append_audit_chain(t,'settlement_correction','READ',encode(public.digest(convert_to(concat_ws(':',r,a),'UTF8'),'sha256'),'hex'));
 RETURN jsonb_build_object('correctionId',r,'caseId',c.case_id,'status',c.status,'reason',c.reason,'stateDigest',c.state_digest,'actorOne',c.actor_one,'actorTwo',c.actor_two,'current',coalesce(h=c.state_digest,false),'snapshot',c.snapshot,'evidenceDigest',c.evidence_digest,'endorsementDigest',c.endorsement_digest);
END $$;
CREATE FUNCTION securepay_private.correction_endorse(r uuid,t uuid,d uuid,h text,evidence text,expires bigint,provider_sig text,sig1 text,sig2 text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE mid uuid;c securepay_private.settlement_correction_cases%ROWTYPE;s jsonb;payload text;kid text;k bytea;
BEGIN
 IF r IS NULL OR t IS NULL OR d IS NULL OR h IS NULL OR h !~ '^[a-f0-9]{64}$' OR evidence IS NULL OR evidence !~ '^[a-f0-9]{64}$'
 OR expires IS NULL OR expires NOT BETWEEN floor(extract(epoch FROM clock_timestamp()))::bigint AND floor(extract(epoch FROM clock_timestamp()))::bigint+30
 OR provider_sig IS NULL OR provider_sig !~ '^[a-z0-9-]{1,32}[.][a-f0-9]{64}$' THEN RETURN false; END IF;
 SELECT * INTO c FROM securepay_private.settlement_correction_cases WHERE correction_id=r AND tenant_id=t AND case_id=d AND status='pending' AND state_digest=h;
 IF NOT FOUND THEN RETURN false; END IF;
 payload:=concat_ws(':','sp-correction-endorse-v1',r,t,d,c.settlement_id,c.proposed_payout,c.proposed_refund,h,evidence,c.actor_one,c.actor_two,expires);
 kid:=split_part(provider_sig,'.',1);
 SELECT secret INTO k FROM securepay_private.provider_key WHERE key_id=kid AND active AND (valid_until IS NULL OR valid_until>clock_timestamp());
 IF k IS NULL OR encode(public.hmac(convert_to(payload||':'||kid,'UTF8'),k,'sha256'),'hex')<>split_part(provider_sig,'.',2)
 OR securepay_private.dispute_actor_valid(t,c.actor_one,payload,expires,sig1) IS DISTINCT FROM 'reconciler'
 OR securepay_private.dispute_actor_valid(t,c.actor_two,payload,expires,sig2) IS DISTINCT FROM 'reconciler' THEN RETURN false; END IF;
 SELECT milestone_id INTO mid FROM securepay_private.dispute_cases WHERE tenant_id=t AND case_id=d;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM 1 FROM public.securepay_milestones WHERE tenant_id=t AND id=mid FOR UPDATE;
 PERFORM 1 FROM securepay_private.provider_funding WHERE tenant_id=t AND milestone_id=mid FOR UPDATE;
 PERFORM 1 FROM securepay_private.dispute_cases WHERE tenant_id=t AND case_id=d FOR UPDATE;
 SELECT * INTO c FROM securepay_private.settlement_correction_cases WHERE correction_id=r AND tenant_id=t AND case_id=d AND status='pending' AND state_digest=h FOR UPDATE;
 IF NOT FOUND OR NOT securepay_private.correction_people_valid(t,d,c.actor_one,c.actor_two)
 OR NOT EXISTS(SELECT 1 FROM securepay_private.governed_cases g JOIN securepay_private.dispute_actors a ON a.tenant_id=g.tenant_id AND a.actor_id=g.administrator_id AND a.active WHERE g.case_id=d AND g.tenant_id=t AND g.administrator_id=c.administrator_id) THEN RETURN false; END IF;
 s:=securepay_private.correction_snapshot(t,d,c.proposed_payout,c.proposed_refund);
 IF s IS NULL OR NOT (s->>'safeToEndorse')::boolean OR encode(public.digest(convert_to(s::text,'UTF8'),'sha256'),'hex')<>h THEN RETURN false; END IF;
 UPDATE securepay_private.settlement_correction_cases SET status='endorsed',resolved_at=clock_timestamp(),evidence_digest=evidence,provider_key_id=kid,endorsement_digest=encode(public.digest(convert_to(concat_ws(':',payload,provider_sig,sig1,sig2),'UTF8'),'sha256'),'hex') WHERE correction_id=r;
 RETURN true;
END $$;
ALTER FUNCTION securepay_private.correction_snapshot(uuid,uuid,bigint,bigint) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.correction_snapshot(uuid,uuid,bigint,bigint) FROM PUBLIC;
ALTER FUNCTION securepay_private.correction_people_valid(uuid,uuid,uuid,uuid) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.correction_people_valid(uuid,uuid,uuid,uuid) FROM PUBLIC;
ALTER FUNCTION securepay_private.correction_request(uuid,uuid,uuid,uuid,uuid,uuid,bigint,bigint,text,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.correction_request(uuid,uuid,uuid,uuid,uuid,uuid,bigint,bigint,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.correction_request(uuid,uuid,uuid,uuid,uuid,uuid,bigint,bigint,text,bigint,text) TO securepay_dispute_admin_runtime;
ALTER FUNCTION securepay_private.correction_read(uuid,uuid,uuid,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.correction_read(uuid,uuid,uuid,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.correction_read(uuid,uuid,uuid,bigint,text) TO securepay_dispute_admin_runtime,securepay_reconciliation_runtime;
ALTER FUNCTION securepay_private.correction_endorse(uuid,uuid,uuid,text,text,bigint,text,text,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.correction_endorse(uuid,uuid,uuid,text,text,bigint,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.correction_endorse(uuid,uuid,uuid,text,text,bigint,text,text,text) TO securepay_reconciliation_runtime;
CREATE OR REPLACE FUNCTION securepay_private.settlement_dispatch_cleared(t uuid,d uuid,s uuid,a uuid) RETURNS boolean
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT NOT EXISTS(SELECT 1 FROM securepay_private.settlement_correction_cases WHERE tenant_id=t AND case_id=d) AND CASE WHEN EXISTS(SELECT 1 FROM securepay_private.post_auth_reviews WHERE case_id=d)
 THEN EXISTS(SELECT 1 FROM securepay_private.post_auth_reviews p WHERE p.tenant_id=t AND p.case_id=d AND p.settlement_id=s AND p.status='reaffirmed' AND securepay_private.post_auth_panel_valid(t,d,p.review_id))
 ELSE securepay_private.governance_settlement_ok(t,d,a) END
$$;
COMMIT;

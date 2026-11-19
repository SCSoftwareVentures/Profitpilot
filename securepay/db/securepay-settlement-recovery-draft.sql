-- Synthetic reconciliation recovery: provider fact + two independent human approvals.
BEGIN;
CREATE ROLE securepay_reconciliation_runtime NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS;
GRANT USAGE ON SCHEMA securepay_private TO securepay_reconciliation_runtime;
ALTER TABLE securepay_private.dispute_actors DROP CONSTRAINT dispute_actors_role_check,
 ADD CONSTRAINT dispute_actors_role_check CHECK(role IN ('owner','customer','reviewer','settlement','reconciler'));
ALTER TABLE securepay_private.settlement_legs DROP CONSTRAINT settlement_legs_attempts_check,
 ADD CONSTRAINT settlement_legs_attempts_check CHECK(attempts BETWEEN 0 AND 4);
ALTER TABLE securepay_private.settlement_leg_conflicts ADD COLUMN resolved_at timestamptz, ADD COLUMN resolution_id uuid;
ALTER TABLE securepay_private.provider_reconciliation ADD COLUMN resolved_at timestamptz, ADD COLUMN resolution_id uuid;
CREATE TABLE securepay_private.settlement_recoveries(
 resolution_id uuid PRIMARY KEY,case_id uuid NOT NULL REFERENCES securepay_private.dispute_cases(case_id),
 leg_id uuid REFERENCES securepay_private.settlement_legs(leg_id),
 action text NOT NULL CHECK(action IN ('confirm','retry_once','clear_conflict','lift_hold')),
 actor_one uuid NOT NULL,actor_two uuid NOT NULL CHECK(actor_one<>actor_two),
 state_digest text NOT NULL,evidence_digest text NOT NULL,reason text NOT NULL,
 receipt uuid,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE securepay_private.settlement_recoveries OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.settlement_recoveries FROM PUBLIC,securepay_reconciliation_runtime,securepay_provider_runtime,securepay_settlement_runtime;
ALTER TABLE securepay_private.settlement_leg_conflicts ADD FOREIGN KEY(resolution_id) REFERENCES securepay_private.settlement_recoveries(resolution_id);
ALTER TABLE securepay_private.provider_reconciliation ADD FOREIGN KEY(resolution_id) REFERENCES securepay_private.settlement_recoveries(resolution_id);
CREATE TRIGGER sp_chain_recoveries AFTER INSERT ON securepay_private.settlement_recoveries FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
-- Snapshot includes all payment legs, conflicts, provider holds and journal balance.
CREATE FUNCTION securepay_private.recovery_state(s uuid,t uuid,m uuid,d uuid) RETURNS text
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT encode(public.digest(convert_to(jsonb_build_array(
  t,m,d,s,c.status,f.status,f.funding_ref,f.amount_cents,st.status,
  (SELECT jsonb_agg(to_jsonb(l) ORDER BY l.leg_id) FROM securepay_private.settlement_legs l WHERE l.settlement_id=s),
  (SELECT jsonb_agg(to_jsonb(e) ORDER BY e.event_id) FROM securepay_private.settlement_leg_events e WHERE e.case_id=d),
  (SELECT jsonb_agg(to_jsonb(x) ORDER BY x.event_id) FROM securepay_private.settlement_leg_conflicts x WHERE x.case_id=d),
  (SELECT jsonb_agg(to_jsonb(x) ORDER BY x.event_id) FROM securepay_private.provider_reconciliation x WHERE x.tenant_id=t AND x.milestone_id=m),
  (SELECT jsonb_agg(to_jsonb(j) ORDER BY j.journal_id) FROM securepay_private.financial_journal j WHERE j.tenant_id=t AND j.milestone_id=m)
 )::text,'UTF8'),'sha256'),'hex')
 FROM securepay_private.dispute_cases c
 JOIN securepay_private.dispute_settlements st ON st.case_id=c.case_id
 JOIN securepay_private.provider_funding f ON f.tenant_id=c.tenant_id AND f.milestone_id=c.milestone_id
 WHERE c.case_id=d AND c.tenant_id=t AND c.milestone_id=m AND st.settlement_id=s
$$;
ALTER FUNCTION securepay_private.recovery_state(uuid,uuid,uuid,uuid) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.recovery_state(uuid,uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.recovery_state(uuid,uuid,uuid,uuid) TO securepay_reconciliation_runtime,securepay_provider_runtime;
CREATE FUNCTION securepay_private.recover_settlement(rid uuid,s uuid,t uuid,m uuid,d uuid,l uuid,op text,r uuid,state_hash text,evidence_hash text,reason text,a1 uuid,a2 uuid,expires bigint,provider_sig text,sig1 text,sig2 text) RETURNS boolean
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
 IF balance<0 THEN RETURN false; END IF;
 IF op='retry_once' THEN
  -- Fourth and final attempt only after signed definitive non-execution.
  IF f.status<>'funded' OR c.status<>'authorized' OR leg.status<>'not_executed' OR leg.attempts<>3
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
ALTER FUNCTION securepay_private.recover_settlement(uuid,uuid,uuid,uuid,uuid,uuid,text,uuid,text,text,text,uuid,uuid,bigint,text,text,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.recover_settlement(uuid,uuid,uuid,uuid,uuid,uuid,text,uuid,text,text,text,uuid,uuid,bigint,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.recover_settlement(uuid,uuid,uuid,uuid,uuid,uuid,text,uuid,text,text,text,uuid,uuid,bigint,text,text,text) TO securepay_reconciliation_runtime;
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
 IF EXISTS(SELECT 1 FROM securepay_private.settlement_legs x WHERE x.settlement_id=s AND x.status IN ('unknown','not_executed'))
 OR EXISTS(SELECT 1 FROM securepay_private.settlement_leg_conflicts x WHERE x.case_id=d AND x.resolved_at IS NULL) THEN RETURN; END IF;
 RETURN QUERY UPDATE securepay_private.settlement_legs x SET status='submitted',attempts=x.attempts+1
 WHERE x.settlement_id=s AND x.kind=k AND x.status='pending' AND x.attempts<4
 RETURNING x.leg_id,x.attempts,x.amount_cents;
 IF FOUND THEN UPDATE securepay_private.dispute_settlements SET status='submitted' WHERE settlement_id=s AND status='authorized'; END IF;
END $$;
CREATE OR REPLACE FUNCTION securepay_private.record_settlement_leg(e uuid,s uuid,t uuid,m uuid,d uuid,l uuid,k text,a bigint,n integer,op text,r uuid,expires bigint,envelope text) RETURNS text
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE secret_key bytea;kid text; funding_status text; leg securepay_private.settlement_legs%ROWTYPE; prev securepay_private.settlement_leg_events%ROWTYPE;
BEGIN
 IF e IS NULL OR s IS NULL OR t IS NULL OR m IS NULL OR d IS NULL OR l IS NULL OR k IS NULL OR k NOT IN ('payout','refund')
 OR a IS NULL OR a<=0 OR n IS NULL OR n NOT BETWEEN 1 AND 4 OR op IS NULL OR op NOT IN ('unknown','not_executed','confirmed')
 OR (op='confirmed')<>(r IS NOT NULL) OR expires IS NULL
 OR expires NOT BETWEEN floor(extract(epoch FROM clock_timestamp()))::bigint AND floor(extract(epoch FROM clock_timestamp()))::bigint+60
 OR envelope IS NULL OR envelope !~ '^[a-z0-9-]{1,32}[.][a-f0-9]{64}$' THEN RETURN 'denied'; END IF;
 kid:=split_part(envelope,'.',1);
 SELECT secret INTO secret_key FROM securepay_private.provider_key WHERE key_id=kid AND active AND (valid_until IS NULL OR valid_until>clock_timestamp());
 IF secret_key IS NULL OR encode(public.hmac(convert_to(concat_ws(':','sp-settlement-leg-v1',e,s,t,m,d,l,k,a,n,op,coalesce(r::text,'-'),expires,kid),'UTF8'),secret_key,'sha256'),'hex')<>split_part(envelope,'.',2) THEN RETURN 'denied'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(e::text,811));
 PERFORM 1 FROM public.securepay_milestones WHERE tenant_id=t AND id=m AND status IN ('disputed','settled') FOR UPDATE;
 IF NOT FOUND THEN RETURN 'denied'; END IF;
 SELECT status INTO funding_status FROM securepay_private.provider_funding WHERE tenant_id=t AND milestone_id=m FOR UPDATE;
 IF NOT FOUND THEN RETURN 'denied'; END IF;
 PERFORM 1 FROM securepay_private.dispute_cases WHERE case_id=d AND tenant_id=t AND milestone_id=m AND status IN ('authorized','settled') FOR UPDATE;
 IF NOT FOUND THEN RETURN 'denied'; END IF;
 PERFORM 1 FROM securepay_private.dispute_settlements WHERE settlement_id=s AND case_id=d AND status IN ('submitted','confirmed') FOR UPDATE;
 IF NOT FOUND THEN RETURN 'denied'; END IF;
 SELECT * INTO leg FROM securepay_private.settlement_legs WHERE leg_id=l AND settlement_id=s AND kind=k AND amount_cents=a FOR UPDATE;
 IF NOT FOUND OR n>leg.attempts THEN RETURN 'denied'; END IF;
 SELECT * INTO prev FROM securepay_private.settlement_leg_events WHERE event_id=e;
 IF FOUND THEN
  IF prev.leg_id=l AND prev.outcome=op AND prev.attempt=n AND prev.receipt IS NOT DISTINCT FROM r THEN RETURN 'duplicate'; END IF;
  RETURN 'denied';
 END IF;
 IF leg.status='confirmed' AND op='confirmed' AND leg.receipt=r THEN RETURN 'duplicate'; END IF;
 -- Never silently discard a contradictory signed receipt. Freeze outstanding
 -- dispatches for independent investigation, never create another transfer.
 IF op='confirmed' AND (leg.status IN ('confirmed','not_executed','pending') OR n<>leg.attempts) THEN
  INSERT INTO securepay_private.provider_receipts(receipt) VALUES(r) ON CONFLICT DO NOTHING;
  INSERT INTO securepay_private.settlement_leg_events(event_id,case_id,leg_id,outcome,attempt,receipt) VALUES(e,d,l,op,n,r);
  INSERT INTO securepay_private.settlement_leg_conflicts(event_id,case_id,reason) VALUES(e,d,'contradictory_receipt');
  RETURN 'reconcile';
 END IF;
 IF n<>leg.attempts OR leg.status NOT IN ('submitted','unknown') THEN RETURN 'denied'; END IF;
 IF op='confirmed' THEN
  INSERT INTO securepay_private.provider_receipts(receipt) VALUES(r);
  UPDATE securepay_private.settlement_legs SET status='confirmed',receipt=r WHERE leg_id=l;
 ELSE
  UPDATE securepay_private.settlement_legs SET status=op WHERE leg_id=l;
 END IF;
 INSERT INTO securepay_private.settlement_leg_events(event_id,case_id,leg_id,outcome,attempt,receipt) VALUES(e,d,l,op,n,r);
 IF funding_status='funded' AND NOT EXISTS(SELECT 1 FROM securepay_private.settlement_legs WHERE settlement_id=s AND status<>'confirmed')
 AND NOT EXISTS(SELECT 1 FROM securepay_private.settlement_leg_conflicts WHERE case_id=d AND resolved_at IS NULL) THEN
  IF (SELECT remaining_cents FROM securepay_private.financial_balance(t,m))<>0 THEN RAISE EXCEPTION 'Unbalanced settlement'; END IF;
  UPDATE securepay_private.dispute_settlements SET status='confirmed',confirmed_at=clock_timestamp() WHERE settlement_id=s;
  UPDATE securepay_private.dispute_cases SET status='settled' WHERE case_id=d;
  UPDATE securepay_private.provider_funding SET status='settled' WHERE tenant_id=t AND milestone_id=m;
  UPDATE public.securepay_milestones SET status='settled',version=version+1,updated_at=clock_timestamp() WHERE id=m;
 END IF;
 RETURN 'applied';
EXCEPTION WHEN unique_violation THEN RETURN 'denied';
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
 IF NOT FOUND OR EXISTS(SELECT 1 FROM securepay_private.settlement_leg_conflicts WHERE case_id=d AND resolved_at IS NULL) THEN RETURN false; END IF;
 UPDATE securepay_private.settlement_legs SET status='pending' WHERE leg_id=l AND settlement_id=s AND status='not_executed' AND attempts=n;
 IF NOT FOUND THEN RETURN false; END IF;
 INSERT INTO securepay_private.settlement_leg_events(event_id,case_id,leg_id,outcome,attempt,actor_id) VALUES(e,d,l,'retry_authorized',n,a);
 RETURN true;
EXCEPTION WHEN unique_violation THEN RETURN false;
END $$;
CREATE OR REPLACE FUNCTION securepay_private.purge_expired_evidence(batch_size integer) RETURNS integer
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c securepay_private.dispute_cases%ROWTYPE; total integer:=0; changed integer; n timestamptz:=clock_timestamp();
BEGIN
 IF batch_size IS NULL OR batch_size NOT BETWEEN 1 AND 100 THEN RETURN 0; END IF;
 FOR c IN SELECT q.* FROM securepay_private.dispute_cases q JOIN securepay_private.evidence_retention_policy p ON p.case_id=q.case_id AND p.tenant_id=q.tenant_id
 WHERE q.status='settled' AND NOT p.legal_hold AND p.retain_until<=n AND NOT EXISTS(SELECT 1 FROM securepay_private.settlement_leg_conflicts f WHERE f.case_id=q.case_id AND f.resolved_at IS NULL)
 AND NOT EXISTS(SELECT 1 FROM securepay_private.provider_reconciliation z WHERE z.tenant_id=q.tenant_id AND z.milestone_id=q.milestone_id AND z.resolved_at IS NULL)
 AND EXISTS(SELECT 1 FROM securepay_private.dispute_photos x WHERE x.case_id=q.case_id AND x.purged_at IS NULL)
 ORDER BY p.retain_until,q.case_id LIMIT batch_size FOR UPDATE OF q SKIP LOCKED LOOP
  PERFORM 1 FROM securepay_private.evidence_retention_policy p WHERE p.case_id=c.case_id AND p.tenant_id=c.tenant_id AND NOT p.legal_hold AND p.retain_until<=clock_timestamp() FOR UPDATE;
  IF NOT FOUND OR EXISTS(SELECT 1 FROM securepay_private.settlement_leg_conflicts f WHERE f.case_id=c.case_id AND f.resolved_at IS NULL) THEN CONTINUE; END IF;
  UPDATE securepay_private.dispute_photos SET content=NULL,purged_at=clock_timestamp() WHERE case_id=c.case_id AND purged_at IS NULL;
  GET DIAGNOSTICS changed=ROW_COUNT;total:=total+changed;
 END LOOP;
 RETURN total;
END $$;
COMMIT;

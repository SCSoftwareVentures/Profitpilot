-- Sandbox per-leg payment reconciliation. Provider receipts are synthetic.
BEGIN;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM securepay_private.dispute_settlements) THEN RAISE EXCEPTION 'Existing settlements require reconciliation before leg migration'; END IF;
END $$;
REVOKE EXECUTE ON FUNCTION securepay_private.begin_settlement_dispatch(uuid,uuid,uuid,uuid),securepay_private.confirm_settlement(uuid,uuid,uuid,uuid,uuid,bigint,bigint,bigint,text) FROM securepay_provider_runtime;
CREATE TABLE securepay_private.settlement_legs(
 leg_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 settlement_id uuid NOT NULL REFERENCES securepay_private.dispute_settlements(settlement_id),
 case_id uuid NOT NULL REFERENCES securepay_private.dispute_cases(case_id),
 kind text NOT NULL CHECK(kind IN ('payout','refund')),
 amount_cents bigint NOT NULL CHECK(amount_cents>0),
 status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','submitted','unknown','not_executed','confirmed')),
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 3),
 receipt uuid UNIQUE,
 CHECK((status='confirmed')=(receipt IS NOT NULL)),
 UNIQUE(settlement_id,kind)
);
CREATE TABLE securepay_private.settlement_leg_events(
 event_id uuid PRIMARY KEY,case_id uuid NOT NULL REFERENCES securepay_private.dispute_cases(case_id),
 leg_id uuid NOT NULL REFERENCES securepay_private.settlement_legs(leg_id),
 outcome text NOT NULL CHECK(outcome IN ('unknown','not_executed','confirmed','retry_authorized')),
 attempt integer NOT NULL,receipt uuid,actor_id uuid,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE securepay_private.settlement_leg_conflicts(
 event_id uuid PRIMARY KEY REFERENCES securepay_private.settlement_leg_events(event_id),
 case_id uuid NOT NULL REFERENCES securepay_private.dispute_cases(case_id),
 reason text NOT NULL CHECK(reason IN ('contradictory_receipt')),
 opened_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE securepay_private.settlement_legs OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.settlement_legs FROM PUBLIC,securepay_provider_runtime,securepay_settlement_runtime,securepay_dispute_runtime,securepay_payer_runtime;
CREATE TRIGGER sp_chain_settlement_legs AFTER INSERT OR UPDATE OR DELETE ON securepay_private.settlement_legs FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
ALTER TABLE securepay_private.settlement_leg_events OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.settlement_leg_events FROM PUBLIC,securepay_provider_runtime,securepay_settlement_runtime,securepay_dispute_runtime,securepay_payer_runtime;
CREATE TRIGGER sp_chain_settlement_leg_events AFTER INSERT OR UPDATE OR DELETE ON securepay_private.settlement_leg_events FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
ALTER TABLE securepay_private.settlement_leg_conflicts OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.settlement_leg_conflicts FROM PUBLIC,securepay_provider_runtime,securepay_settlement_runtime,securepay_dispute_runtime,securepay_payer_runtime;
CREATE TRIGGER sp_chain_settlement_leg_conflicts AFTER INSERT OR UPDATE OR DELETE ON securepay_private.settlement_leg_conflicts FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
CREATE FUNCTION securepay_private.initialize_settlement_legs() RETURNS trigger
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.payout_cents>0 THEN INSERT INTO securepay_private.settlement_legs(settlement_id,case_id,kind,amount_cents) VALUES(NEW.settlement_id,NEW.case_id,'payout',NEW.payout_cents); END IF;
 IF NEW.refund_cents>0 THEN INSERT INTO securepay_private.settlement_legs(settlement_id,case_id,kind,amount_cents) VALUES(NEW.settlement_id,NEW.case_id,'refund',NEW.refund_cents); END IF;
 RETURN NEW;
END $$;
ALTER FUNCTION securepay_private.initialize_settlement_legs() OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.initialize_settlement_legs() FROM PUBLIC;
CREATE TRIGGER sp_create_settlement_legs AFTER INSERT ON securepay_private.dispute_settlements FOR EACH ROW EXECUTE FUNCTION securepay_private.initialize_settlement_legs();

-- A provider hold after any attempted settlement leg blocks further dispatch.
-- Keep the signed provider event and an independent reconciliation marker.
CREATE FUNCTION securepay_private.flag_settlement_hold() RETURNS trigger
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.kind='held' AND EXISTS(
  SELECT 1 FROM securepay_private.dispute_cases c JOIN securepay_private.settlement_legs l ON l.case_id=c.case_id
  WHERE c.tenant_id=NEW.tenant_id AND c.milestone_id=NEW.milestone_id AND l.attempts>0
 ) THEN
  INSERT INTO securepay_private.provider_reconciliation(event_id,tenant_id,milestone_id,reason)
  VALUES(NEW.event_id,NEW.tenant_id,NEW.milestone_id,'hold_after_dispatch') ON CONFLICT DO NOTHING;
 END IF;
 RETURN NEW;
END $$;
ALTER FUNCTION securepay_private.flag_settlement_hold() OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.flag_settlement_hold() FROM PUBLIC;
CREATE TRIGGER sp_settlement_hold AFTER INSERT ON securepay_private.provider_events FOR EACH ROW EXECUTE FUNCTION securepay_private.flag_settlement_hold();
CREATE FUNCTION securepay_private.dispatch_settlement_leg(s uuid,t uuid,m uuid,d uuid,k text)
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
 OR EXISTS(SELECT 1 FROM securepay_private.settlement_leg_conflicts x WHERE x.case_id=d) THEN RETURN; END IF;
 RETURN QUERY UPDATE securepay_private.settlement_legs x SET status='submitted',attempts=x.attempts+1
 WHERE x.settlement_id=s AND x.kind=k AND x.status='pending' AND x.attempts<3
 RETURNING x.leg_id,x.attempts,x.amount_cents;
 IF FOUND THEN UPDATE securepay_private.dispute_settlements SET status='submitted' WHERE settlement_id=s AND status='authorized'; END IF;
END $$;
CREATE FUNCTION securepay_private.record_settlement_leg(e uuid,s uuid,t uuid,m uuid,d uuid,l uuid,k text,a bigint,n integer,op text,r uuid,expires bigint,envelope text) RETURNS text
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE secret_key bytea;kid text; funding_status text; leg securepay_private.settlement_legs%ROWTYPE; prev securepay_private.settlement_leg_events%ROWTYPE;
BEGIN
 IF e IS NULL OR s IS NULL OR t IS NULL OR m IS NULL OR d IS NULL OR l IS NULL OR k IS NULL OR k NOT IN ('payout','refund')
 OR a IS NULL OR a<=0 OR n IS NULL OR n NOT BETWEEN 1 AND 3 OR op IS NULL OR op NOT IN ('unknown','not_executed','confirmed')
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
 AND NOT EXISTS(SELECT 1 FROM securepay_private.settlement_leg_conflicts WHERE case_id=d) THEN
  UPDATE securepay_private.dispute_settlements SET status='confirmed',confirmed_at=clock_timestamp() WHERE settlement_id=s;
  UPDATE securepay_private.dispute_cases SET status='settled' WHERE case_id=d;
  UPDATE securepay_private.provider_funding SET status='settled' WHERE tenant_id=t AND milestone_id=m;
  UPDATE public.securepay_milestones SET status='settled',version=version+1,updated_at=clock_timestamp() WHERE id=m;
 END IF;
 RETURN 'applied';
EXCEPTION WHEN unique_violation THEN RETURN 'denied';
END $$;
-- Only an independent settlement authorizer can retry after signed definitive
-- non-execution, never after unknown outcome. Keep the stable leg idempotency key.
CREATE FUNCTION securepay_private.retry_settlement_leg(e uuid,s uuid,t uuid,m uuid,d uuid,l uuid,a uuid,n integer,expires bigint,sig text) RETURNS boolean
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
 IF NOT FOUND OR EXISTS(SELECT 1 FROM securepay_private.settlement_leg_conflicts WHERE case_id=d) THEN RETURN false; END IF;
 UPDATE securepay_private.settlement_legs SET status='pending' WHERE leg_id=l AND settlement_id=s AND status='not_executed' AND attempts=n;
 IF NOT FOUND THEN RETURN false; END IF;
 INSERT INTO securepay_private.settlement_leg_events(event_id,case_id,leg_id,outcome,attempt,actor_id) VALUES(e,d,l,'retry_authorized',n,a);
 RETURN true;
EXCEPTION WHEN unique_violation THEN RETURN false;
END $$;
ALTER FUNCTION securepay_private.dispatch_settlement_leg(uuid,uuid,uuid,uuid,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.dispatch_settlement_leg(uuid,uuid,uuid,uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.dispatch_settlement_leg(uuid,uuid,uuid,uuid,text) TO securepay_provider_runtime;
ALTER FUNCTION securepay_private.record_settlement_leg(uuid,uuid,uuid,uuid,uuid,uuid,text,bigint,integer,text,uuid,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.record_settlement_leg(uuid,uuid,uuid,uuid,uuid,uuid,text,bigint,integer,text,uuid,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.record_settlement_leg(uuid,uuid,uuid,uuid,uuid,uuid,text,bigint,integer,text,uuid,bigint,text) TO securepay_provider_runtime;
ALTER FUNCTION securepay_private.retry_settlement_leg(uuid,uuid,uuid,uuid,uuid,uuid,uuid,integer,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.retry_settlement_leg(uuid,uuid,uuid,uuid,uuid,uuid,uuid,integer,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.retry_settlement_leg(uuid,uuid,uuid,uuid,uuid,uuid,uuid,integer,bigint,text) TO securepay_settlement_runtime;
COMMIT;

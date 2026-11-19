-- SANDBOX ONLY. Dispute decisions are not payment instructions.
BEGIN;
CREATE ROLE securepay_dispute_runtime NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS;
CREATE ROLE securepay_settlement_runtime NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS;
GRANT USAGE ON SCHEMA securepay_private TO securepay_dispute_runtime,securepay_settlement_runtime;
ALTER TABLE public.securepay_milestones DROP CONSTRAINT securepay_milestones_status_check,
 ADD CONSTRAINT securepay_milestones_status_check CHECK(status IN ('planned','submitted','disputed','approved','release_pending','released','settled'));
ALTER TABLE securepay_private.provider_funding DROP CONSTRAINT provider_funding_status_check,
 ADD CONSTRAINT provider_funding_status_check CHECK(status IN ('funded','held','released','settled'));
-- Separately provisioned actor accounts. One role per actor per tenant.
CREATE TABLE securepay_private.dispute_actors(
 tenant_id uuid NOT NULL, actor_id uuid NOT NULL, role text NOT NULL CHECK(role IN ('owner','customer','reviewer','settlement')),
 secret bytea NOT NULL CHECK(octet_length(secret)=32), active boolean NOT NULL DEFAULT true,
 PRIMARY KEY(tenant_id,actor_id)
);
CREATE TABLE securepay_private.dispute_parties(
 tenant_id uuid NOT NULL, milestone_id uuid NOT NULL, owner_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,milestone_id),
 FOREIGN KEY(tenant_id,milestone_id) REFERENCES public.securepay_milestones(tenant_id,id),
 FOREIGN KEY(tenant_id,owner_id) REFERENCES securepay_private.dispute_actors(tenant_id,actor_id)
);
CREATE TABLE securepay_private.dispute_cases(
 case_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,milestone_id uuid NOT NULL,customer_id uuid NOT NULL,owner_id uuid NOT NULL,
 severity text NOT NULL CHECK(severity IN ('minor','moderate','serious')),
 status text NOT NULL CHECK(status IN ('open','decided','appealed','final','authorized','settled')),
 customer_evidence boolean NOT NULL DEFAULT false,owner_evidence boolean NOT NULL DEFAULT false,
 customer_ack boolean NOT NULL DEFAULT false,owner_ack boolean NOT NULL DEFAULT false,
 customer_appeal_evidence boolean NOT NULL DEFAULT false,owner_appeal_evidence boolean NOT NULL DEFAULT false,
 first_reviewer uuid,final_reviewer uuid,payout_cents bigint,refund_cents bigint,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,milestone_id),FOREIGN KEY(tenant_id,milestone_id) REFERENCES public.securepay_milestones(tenant_id,id)
);
CREATE TABLE securepay_private.dispute_events(
 event_id uuid PRIMARY KEY,case_id uuid NOT NULL REFERENCES securepay_private.dispute_cases(case_id),
 actor_id uuid NOT NULL,action text NOT NULL,details text NOT NULL,evidence_digest text,
 payout_cents bigint,refund_cents bigint,occurred_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE securepay_private.dispute_settlements(
 settlement_id uuid PRIMARY KEY,case_id uuid UNIQUE NOT NULL REFERENCES securepay_private.dispute_cases(case_id),
 authorizer uuid NOT NULL,payout_cents bigint NOT NULL CHECK(payout_cents>=0),refund_cents bigint NOT NULL CHECK(refund_cents>=0),
 status text NOT NULL CHECK(status IN ('authorized','submitted','confirmed')),provider_receipt uuid UNIQUE,
 authorized_at timestamptz NOT NULL DEFAULT clock_timestamp(),confirmed_at timestamptz
);
ALTER TABLE securepay_private.dispute_actors OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.dispute_actors FROM PUBLIC,securepay_payer_runtime,securepay_provider_runtime,securepay_notification_runtime,securepay_dispute_runtime,securepay_settlement_runtime;
ALTER TABLE securepay_private.dispute_parties OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.dispute_parties FROM PUBLIC,securepay_payer_runtime,securepay_provider_runtime,securepay_notification_runtime,securepay_dispute_runtime,securepay_settlement_runtime;
ALTER TABLE securepay_private.dispute_cases OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.dispute_cases FROM PUBLIC,securepay_payer_runtime,securepay_provider_runtime,securepay_notification_runtime,securepay_dispute_runtime,securepay_settlement_runtime;
ALTER TABLE securepay_private.dispute_events OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.dispute_events FROM PUBLIC,securepay_payer_runtime,securepay_provider_runtime,securepay_notification_runtime,securepay_dispute_runtime,securepay_settlement_runtime;
ALTER TABLE securepay_private.dispute_settlements OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.dispute_settlements FROM PUBLIC,securepay_payer_runtime,securepay_provider_runtime,securepay_notification_runtime,securepay_dispute_runtime,securepay_settlement_runtime;
-- A synthetic provider receipt is globally single-use across ordinary releases
-- and aggregate dispute settlements, including concurrent confirmations.
CREATE TABLE securepay_private.provider_receipts(receipt uuid PRIMARY KEY);
ALTER TABLE securepay_private.provider_receipts OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.provider_receipts FROM PUBLIC,securepay_payer_runtime,securepay_provider_runtime,securepay_notification_runtime,securepay_dispute_runtime,securepay_settlement_runtime;
INSERT INTO securepay_private.provider_receipts(receipt) SELECT transaction_ref FROM securepay_private.provider_events WHERE transaction_ref IS NOT NULL;
CREATE FUNCTION securepay_private.register_provider_receipt() RETURNS trigger
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $
BEGIN
 IF TG_TABLE_NAME='provider_events' THEN
  IF NEW.transaction_ref IS NOT NULL THEN INSERT INTO securepay_private.provider_receipts VALUES(NEW.transaction_ref); END IF;
 ELSIF NEW.provider_receipt IS NOT NULL AND NEW.provider_receipt IS DISTINCT FROM OLD.provider_receipt THEN
  INSERT INTO securepay_private.provider_receipts VALUES(NEW.provider_receipt);
 END IF;
 RETURN NEW;
END $;
ALTER FUNCTION securepay_private.register_provider_receipt() OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.register_provider_receipt() FROM PUBLIC;
CREATE TRIGGER sp_unique_ordinary_receipt BEFORE INSERT ON securepay_private.provider_events FOR EACH ROW EXECUTE FUNCTION securepay_private.register_provider_receipt();
CREATE TRIGGER sp_unique_dispute_receipt BEFORE UPDATE OF provider_receipt ON securepay_private.dispute_settlements FOR EACH ROW EXECUTE FUNCTION securepay_private.register_provider_receipt();

CREATE FUNCTION securepay_private.dispute_actor_valid(t uuid,a uuid,payload text,expires bigint,sig text) RETURNS text
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE k bytea; actor_role text; n bigint;
BEGIN
 n:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 IF expires IS NULL OR expires<n OR expires>n+30 OR sig IS NULL OR sig !~ '^[a-f0-9]{64}$' THEN RETURN NULL; END IF;
 SELECT secret,role INTO k,actor_role FROM securepay_private.dispute_actors WHERE tenant_id=t AND actor_id=a AND active;
 IF k IS NULL OR encode(public.hmac(convert_to(payload,'UTF8'),k,'sha256'),'hex')<>sig THEN RETURN NULL; END IF;
 RETURN actor_role;
END $$;
CREATE FUNCTION securepay_private.dispute_action(e uuid,t uuid,m uuid,d uuid,a uuid,op text,details text,digest text,payout bigint,refund bigint,expires bigint,sig text) RETURNS boolean
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
   IF role_name<>'reviewer' OR a IN (c.owner_id,c.customer_id) OR NOT c.customer_evidence OR NOT c.owner_evidence
   OR length(btrim(details))<10 OR digest IS NULL OR payout IS NULL OR refund IS NULL OR payout<0 OR refund<0
   OR payout::numeric+refund::numeric<>milestone.amount_cents THEN RETURN false; END IF;
   IF op='decide' AND c.status='open' THEN
    UPDATE securepay_private.dispute_cases SET status='decided',first_reviewer=a,payout_cents=payout,refund_cents=refund WHERE case_id=d;
   ELSIF op='finalize' AND c.status IN ('decided','appealed') AND a IS DISTINCT FROM c.first_reviewer
    AND ((c.status='appealed' AND c.customer_appeal_evidence AND c.owner_appeal_evidence) OR (c.status='decided' AND c.customer_ack AND c.owner_ack))
    AND (c.status='appealed' OR (payout=c.payout_cents AND refund=c.refund_cents)) THEN
    UPDATE securepay_private.dispute_cases SET status='final',final_reviewer=a,payout_cents=payout,refund_cents=refund WHERE case_id=d;
   ELSE RETURN false; END IF;
  ELSIF op IN ('ack','appeal') THEN
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
CREATE FUNCTION securepay_private.authorize_settlement(s uuid,t uuid,m uuid,d uuid,a uuid,payout bigint,refund bigint,expires bigint,sig text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c securepay_private.dispute_cases%ROWTYPE; milestone public.securepay_milestones%ROWTYPE;
BEGIN
 IF s IS NULL OR t IS NULL OR m IS NULL OR d IS NULL OR a IS NULL OR payout IS NULL OR refund IS NULL OR payout<0 OR refund<0 OR
 securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-settlement-v1',s,t,m,d,a,payout,refund,expires),expires,sig) IS DISTINCT FROM 'settlement' THEN RETURN false; END IF;
 SELECT * INTO milestone FROM public.securepay_milestones WHERE tenant_id=t AND id=m FOR UPDATE;
 IF NOT FOUND OR milestone.status<>'disputed' OR payout::numeric+refund::numeric<>milestone.amount_cents THEN RETURN false; END IF;
 PERFORM 1 FROM securepay_private.provider_funding WHERE tenant_id=t AND milestone_id=m AND status='funded' AND amount_cents=milestone.amount_cents FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO c FROM securepay_private.dispute_cases WHERE case_id=d AND tenant_id=t AND milestone_id=m FOR UPDATE;
 IF NOT FOUND OR c.status<>'final' OR a IN (c.customer_id,c.owner_id,c.first_reviewer,c.final_reviewer) OR
 payout<>c.payout_cents OR refund<>c.refund_cents THEN RETURN false; END IF;
 INSERT INTO securepay_private.dispute_settlements(settlement_id,case_id,authorizer,payout_cents,refund_cents,status) VALUES(s,d,a,payout,refund,'authorized');
 UPDATE securepay_private.dispute_cases SET status='authorized' WHERE case_id=d;
 RETURN true;
EXCEPTION WHEN unique_violation THEN RETURN false;
END $$;
CREATE FUNCTION securepay_private.begin_settlement_dispatch(s uuid,t uuid,m uuid,d uuid) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $
DECLARE amount bigint;
BEGIN
 SELECT amount_cents INTO amount FROM public.securepay_milestones WHERE tenant_id=t AND id=m AND status='disputed' FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM 1 FROM securepay_private.provider_funding WHERE tenant_id=t AND milestone_id=m AND status='funded' AND amount_cents=amount FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM 1 FROM securepay_private.dispute_cases WHERE case_id=d AND tenant_id=t AND milestone_id=m AND status='authorized' FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 UPDATE securepay_private.dispute_settlements SET status='submitted' WHERE settlement_id=s AND case_id=d AND status='authorized' AND payout_cents::numeric+refund_cents::numeric=amount;
 RETURN FOUND;
END $;
ALTER FUNCTION securepay_private.begin_settlement_dispatch(uuid,uuid,uuid,uuid) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.begin_settlement_dispatch(uuid,uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.begin_settlement_dispatch(uuid,uuid,uuid,uuid) TO securepay_provider_runtime;

-- Synthetic aggregate confirmation of both legs only; no real transfer or partial-leg execution.
CREATE FUNCTION securepay_private.confirm_settlement(s uuid,t uuid,m uuid,d uuid,receipt uuid,payout bigint,refund bigint,expires bigint,envelope text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE k bytea; kid text; c securepay_private.dispute_cases%ROWTYPE; st securepay_private.dispute_settlements%ROWTYPE; milestone public.securepay_milestones%ROWTYPE;
BEGIN
 IF s IS NULL OR t IS NULL OR m IS NULL OR d IS NULL OR receipt IS NULL OR payout IS NULL OR refund IS NULL OR expires IS NULL OR
 expires<floor(extract(epoch FROM clock_timestamp()))::bigint OR expires>floor(extract(epoch FROM clock_timestamp()))::bigint+60
 OR envelope IS NULL OR envelope !~ '^[a-z0-9-]{1,32}[.][a-f0-9]{64}$' THEN RETURN false; END IF;
 kid:=split_part(envelope,'.',1);
 SELECT secret INTO k FROM securepay_private.provider_key WHERE key_id=kid AND active AND (valid_until IS NULL OR valid_until>clock_timestamp());
 IF k IS NULL OR encode(public.hmac(convert_to(concat_ws(':','sp-settlement-receipt-v1',s,t,m,d,receipt,payout,refund,expires,kid),'UTF8'),k,'sha256'),'hex')<>split_part(envelope,'.',2) THEN RETURN false; END IF;
 SELECT * INTO milestone FROM public.securepay_milestones WHERE tenant_id=t AND id=m FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO c FROM securepay_private.dispute_cases WHERE case_id=d AND tenant_id=t AND milestone_id=m FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO st FROM securepay_private.dispute_settlements WHERE settlement_id=s AND case_id=d FOR UPDATE;
 IF NOT FOUND OR st.payout_cents<>payout OR st.refund_cents<>refund THEN RETURN false; END IF;
 IF st.status='confirmed' THEN RETURN st.provider_receipt=receipt; END IF;
 IF c.status<>'authorized' OR milestone.status<>'disputed' OR st.status<>'submitted' THEN RETURN false; END IF;
 PERFORM 1 FROM securepay_private.provider_funding WHERE tenant_id=t AND milestone_id=m AND status='funded' AND amount_cents=payout::numeric+refund::numeric FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 UPDATE securepay_private.dispute_settlements SET status='confirmed',provider_receipt=receipt,confirmed_at=clock_timestamp() WHERE settlement_id=s;
 UPDATE securepay_private.dispute_cases SET status='settled' WHERE case_id=d;
 UPDATE securepay_private.provider_funding SET status='settled' WHERE tenant_id=t AND milestone_id=m;
 UPDATE public.securepay_milestones SET status='settled',version=version+1,updated_at=clock_timestamp() WHERE id=m;
 RETURN true;
EXCEPTION WHEN unique_violation THEN RETURN false;
END $$;
ALTER FUNCTION securepay_private.dispute_actor_valid(uuid,uuid,text,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.dispute_actor_valid(uuid,uuid,text,bigint,text) FROM PUBLIC;
ALTER FUNCTION securepay_private.dispute_action(uuid,uuid,uuid,uuid,uuid,text,text,text,bigint,bigint,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.dispute_action(uuid,uuid,uuid,uuid,uuid,text,text,text,bigint,bigint,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.dispute_action(uuid,uuid,uuid,uuid,uuid,text,text,text,bigint,bigint,bigint,text) TO securepay_dispute_runtime;
ALTER FUNCTION securepay_private.authorize_settlement(uuid,uuid,uuid,uuid,uuid,bigint,bigint,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.authorize_settlement(uuid,uuid,uuid,uuid,uuid,bigint,bigint,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.authorize_settlement(uuid,uuid,uuid,uuid,uuid,bigint,bigint,bigint,text) TO securepay_settlement_runtime;
ALTER FUNCTION securepay_private.confirm_settlement(uuid,uuid,uuid,uuid,uuid,bigint,bigint,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.confirm_settlement(uuid,uuid,uuid,uuid,uuid,bigint,bigint,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.confirm_settlement(uuid,uuid,uuid,uuid,uuid,bigint,bigint,bigint,text) TO securepay_provider_runtime;
COMMIT;

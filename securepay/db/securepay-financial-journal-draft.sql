-- Sandbox financial journal: immutable balanced transfer pairs. No custody.
BEGIN;
CREATE TABLE securepay_private.financial_journal(
 journal_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 tenant_id uuid NOT NULL,milestone_id uuid NOT NULL,
 kind text NOT NULL CHECK(kind IN ('funding','ordinary_payout','settlement_payout','settlement_refund')),
 source_ref uuid NOT NULL UNIQUE,amount_cents bigint NOT NULL CHECK(amount_cents>0),
 debit_account text NOT NULL,credit_account text NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,milestone_id) REFERENCES public.securepay_milestones(tenant_id,id),
 CHECK((kind='funding' AND debit_account='provider_funds' AND credit_account='customer_funding_liability')
 OR (kind IN ('ordinary_payout','settlement_payout') AND debit_account='customer_funding_liability' AND credit_account='business_disbursement')
 OR (kind='settlement_refund' AND debit_account='customer_funding_liability' AND credit_account='customer_refund'))
);
ALTER TABLE securepay_private.financial_journal OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.financial_journal FROM PUBLIC,securepay_provider_runtime,securepay_payer_runtime,securepay_settlement_runtime,securepay_dispute_runtime,securepay_audit_runtime;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM securepay_private.provider_events) OR EXISTS(SELECT 1 FROM securepay_private.settlement_legs)
 THEN RAISE EXCEPTION 'Existing financial activity requires reviewed journal baseline'; END IF;
END $$;
CREATE FUNCTION securepay_private.post_financial_journal() RETURNS trigger
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE t uuid;m uuid;k text;ref uuid;amount bigint;funded numeric;paid numeric;
BEGIN
 IF TG_TABLE_NAME='provider_events' THEN
  IF NEW.kind NOT IN ('funded','released') THEN RETURN NEW; END IF;
  t:=NEW.tenant_id;m:=NEW.milestone_id;amount:=NEW.amount_cents;
  IF NEW.kind='funded' THEN k:='funding';ref:=NEW.funding_ref; ELSE k:='ordinary_payout';ref:=NEW.transaction_ref; END IF;
 ELSE
  IF NEW.status<>'confirmed' OR OLD.status='confirmed' THEN RETURN NEW; END IF;
  SELECT tenant_id,milestone_id INTO t,m FROM securepay_private.dispute_cases WHERE case_id=NEW.case_id;
  k:='settlement_'||NEW.kind;ref:=NEW.receipt;amount:=NEW.amount_cents;
 END IF;
 PERFORM 1 FROM public.securepay_milestones WHERE tenant_id=t AND id=m FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Missing journal scope'; END IF;
 SELECT coalesce(sum(amount_cents) FILTER(WHERE kind='funding'),0),coalesce(sum(amount_cents) FILTER(WHERE kind<>'funding'),0)
 INTO funded,paid FROM securepay_private.financial_journal WHERE tenant_id=t AND milestone_id=m;
 IF k='funding' THEN
  IF funded<>0 THEN RAISE EXCEPTION 'Duplicate funding journal'; END IF;
 ELSIF paid+amount>funded THEN RAISE EXCEPTION 'Journal overdraw'; END IF;
 INSERT INTO securepay_private.financial_journal(tenant_id,milestone_id,kind,source_ref,amount_cents,debit_account,credit_account)
 VALUES(t,m,k,ref,amount,CASE WHEN k='funding' THEN 'provider_funds' ELSE 'customer_funding_liability' END,
 CASE WHEN k='funding' THEN 'customer_funding_liability' WHEN k='settlement_refund' THEN 'customer_refund' ELSE 'business_disbursement' END);
 RETURN NEW;
END $$;
ALTER FUNCTION securepay_private.post_financial_journal() OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.post_financial_journal() FROM PUBLIC;
CREATE TRIGGER sp_post_provider_journal AFTER INSERT ON securepay_private.provider_events FOR EACH ROW EXECUTE FUNCTION securepay_private.post_financial_journal();
CREATE TRIGGER sp_post_leg_journal AFTER UPDATE OF status ON securepay_private.settlement_legs FOR EACH ROW EXECUTE FUNCTION securepay_private.post_financial_journal();
CREATE TRIGGER sp_chain_financial_journal AFTER INSERT ON securepay_private.financial_journal FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
CREATE FUNCTION securepay_private.financial_balance(t uuid,m uuid)
 RETURNS TABLE(funded_cents numeric,payout_cents numeric,refund_cents numeric,remaining_cents numeric)
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT coalesce(sum(amount_cents) FILTER(WHERE kind='funding'),0),
 coalesce(sum(amount_cents) FILTER(WHERE kind IN ('ordinary_payout','settlement_payout')),0),
 coalesce(sum(amount_cents) FILTER(WHERE kind='settlement_refund'),0),
 coalesce(sum(CASE WHEN kind='funding' THEN amount_cents ELSE -amount_cents END),0)
 FROM securepay_private.financial_journal WHERE tenant_id=t AND milestone_id=m
$$;
ALTER FUNCTION securepay_private.financial_balance(uuid,uuid) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.financial_balance(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.financial_balance(uuid,uuid) TO securepay_audit_runtime;
COMMIT;

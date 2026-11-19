-- Draft audit ledger. Append-only against ordinary runtime roles; administrators
-- remain trusted. External immutable retention and independent anchoring are later gates.
BEGIN;
CREATE TABLE securepay_private.audit_events(
 event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 tenant_id uuid NOT NULL, customer_id uuid,
 event_type text NOT NULL CHECK(event_type IN ('grant_issued','grant_consumed','pin_enrolled','pin_changed','pin_failure','pin_counter_reset','release_reserved')),
 reference_id uuid, amount_cents bigint, failure_count integer
);
ALTER TABLE securepay_private.audit_events OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.audit_events FROM PUBLIC,securepay_payer_runtime;
CREATE FUNCTION securepay_private.audit_changes() RETURNS trigger
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE kind text; payer uuid; ref uuid; cents bigint; failures integer;
BEGIN
 IF TG_TABLE_NAME='securepay_pin_change_grants' THEN
  payer:=NEW.customer_id; ref:=NEW.grant_ref;
  IF TG_OP='INSERT' THEN kind:='grant_issued';
  ELSIF OLD.consumed_at IS NULL AND NEW.consumed_at IS NOT NULL THEN kind:='grant_consumed';
  END IF;
 ELSIF TG_TABLE_NAME='securepay_customer_pins' THEN
  payer:=NEW.customer_id;
  IF TG_OP='INSERT' THEN kind:='pin_enrolled';
  ELSIF NEW.pin_hash IS DISTINCT FROM OLD.pin_hash OR NEW.salt IS DISTINCT FROM OLD.salt THEN kind:='pin_changed';
  ELSIF NEW.failed_attempts>0 AND NEW.failed_attempts IS DISTINCT FROM OLD.failed_attempts THEN kind:='pin_failure'; failures:=NEW.failed_attempts;
  ELSIF NEW.failed_attempts=0 AND OLD.failed_attempts>0 THEN kind:='pin_counter_reset';
  END IF;
 ELSIF TG_TABLE_NAME='securepay_release_requests' THEN
  kind:='release_reserved'; ref:=NEW.id; cents:=NEW.amount_cents;
  SELECT payer_customer_id INTO payer FROM public.securepay_milestones WHERE tenant_id=NEW.tenant_id AND id=NEW.milestone_id;
 END IF;
 IF kind IS NOT NULL THEN
  INSERT INTO securepay_private.audit_events(tenant_id,customer_id,event_type,reference_id,amount_cents,failure_count)
  VALUES(NEW.tenant_id,payer,kind,ref,cents,failures);
 END IF;
 RETURN NEW;
END $$;
ALTER FUNCTION securepay_private.audit_changes() OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.audit_changes() FROM PUBLIC,securepay_payer_runtime;
CREATE TRIGGER sp_audit_grants AFTER INSERT OR UPDATE ON public.securepay_pin_change_grants FOR EACH ROW EXECUTE FUNCTION securepay_private.audit_changes();
CREATE TRIGGER sp_audit_pins AFTER INSERT OR UPDATE ON public.securepay_customer_pins FOR EACH ROW EXECUTE FUNCTION securepay_private.audit_changes();
CREATE TRIGGER sp_audit_release AFTER INSERT ON public.securepay_release_requests FOR EACH ROW EXECUTE FUNCTION securepay_private.audit_changes();
COMMIT;

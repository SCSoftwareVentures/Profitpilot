-- Sandbox migration: revoke older customer sessions on successful PIN recovery.
-- Queue durable notification intent in the same transaction; delivery is separate.
BEGIN;
ALTER TABLE public.securepay_payer_identities
 ADD COLUMN session_revoked_at timestamptz;
GRANT UPDATE(session_revoked_at) ON public.securepay_payer_identities TO securepay_context_owner;
CREATE TABLE securepay_private.recovery_notification_outbox(
 notification_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 tenant_id uuid NOT NULL, customer_id uuid NOT NULL,
 event_type text NOT NULL CHECK(event_type IN ('pin_enrolled','pin_recovered')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 delivered_at timestamptz,
 FOREIGN KEY(tenant_id,customer_id) REFERENCES public.securepay_payer_identities(tenant_id,customer_id)
);
ALTER TABLE securepay_private.recovery_notification_outbox OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.recovery_notification_outbox FROM PUBLIC,securepay_payer_runtime;
CREATE FUNCTION securepay_private.on_pin_security_change() RETURNS trigger
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  INSERT INTO securepay_private.recovery_notification_outbox(tenant_id,customer_id,event_type)
  SELECT NEW.tenant_id,NEW.customer_id,'pin_enrolled'
  WHERE EXISTS(SELECT 1 FROM public.securepay_payer_identities WHERE tenant_id=NEW.tenant_id AND customer_id=NEW.customer_id);
 ELSIF NEW.pin_hash IS DISTINCT FROM OLD.pin_hash OR NEW.salt IS DISTINCT FROM OLD.salt THEN
  UPDATE public.securepay_payer_identities SET session_revoked_at=clock_timestamp()
   WHERE tenant_id=NEW.tenant_id AND customer_id=NEW.customer_id;
  IF FOUND THEN
   INSERT INTO securepay_private.recovery_notification_outbox(tenant_id,customer_id,event_type)
   VALUES(NEW.tenant_id,NEW.customer_id,'pin_recovered');
  END IF;
 END IF;
 RETURN NEW;
END $$;
ALTER FUNCTION securepay_private.on_pin_security_change() OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.on_pin_security_change() FROM PUBLIC,securepay_payer_runtime;
CREATE TRIGGER sp_pin_security_change AFTER INSERT OR UPDATE ON public.securepay_customer_pins
 FOR EACH ROW EXECUTE FUNCTION securepay_private.on_pin_security_change();
COMMIT;

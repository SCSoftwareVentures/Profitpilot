-- Sandbox-only notification delivery boundary. No provider credentials or addresses.
BEGIN;
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='securepay_notification_runtime') THEN
  CREATE ROLE securepay_notification_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
 END IF;
END $$;
ALTER TABLE securepay_private.recovery_notification_outbox
 ADD COLUMN attempt_count integer NOT NULL DEFAULT 0 CHECK(attempt_count BETWEEN 0 AND 8),
 ADD COLUMN next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 ADD COLUMN lease_id uuid,
 ADD COLUMN lease_until timestamptz,
 ADD COLUMN dead_lettered_at timestamptz,
 ADD COLUMN delivery_ref text CHECK(length(delivery_ref) BETWEEN 1 AND 200),
 ADD CONSTRAINT sp_notification_lease_pair CHECK((lease_id IS NULL)=(lease_until IS NULL)),
 ADD CONSTRAINT sp_notification_terminal CHECK(delivered_at IS NULL OR dead_lettered_at IS NULL);
CREATE INDEX sp_notification_pending ON securepay_private.recovery_notification_outbox(next_attempt_at,notification_id)
 WHERE delivered_at IS NULL AND dead_lettered_at IS NULL;
GRANT USAGE ON SCHEMA securepay_private TO securepay_notification_runtime;
REVOKE ALL ON securepay_private.recovery_notification_outbox FROM securepay_notification_runtime;
CREATE FUNCTION securepay_private.claim_notification(l uuid)
 RETURNS TABLE(notification_id bigint,tenant_id uuid,customer_id uuid,event_type text,attempt_count integer)
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF l IS NULL THEN RETURN; END IF;
 -- Exhausted leases may have reached the provider; dead-letter for reconciliation.
 UPDATE securepay_private.recovery_notification_outbox o
 SET dead_lettered_at=clock_timestamp(),lease_id=NULL,lease_until=NULL
 WHERE o.delivered_at IS NULL AND o.dead_lettered_at IS NULL AND o.attempt_count>=8
 AND (o.lease_until IS NULL OR o.lease_until<=clock_timestamp());
 RETURN QUERY WITH candidate AS (
 SELECT o.notification_id FROM securepay_private.recovery_notification_outbox o
 WHERE o.delivered_at IS NULL AND o.dead_lettered_at IS NULL AND o.attempt_count<8
 AND o.next_attempt_at<=clock_timestamp() AND (o.lease_until IS NULL OR o.lease_until<=clock_timestamp())
 ORDER BY o.next_attempt_at,o.notification_id LIMIT 1 FOR UPDATE SKIP LOCKED)
 UPDATE securepay_private.recovery_notification_outbox o
 SET lease_id=l,lease_until=clock_timestamp()+interval '60 seconds',attempt_count=o.attempt_count+1
 FROM candidate WHERE o.notification_id=candidate.notification_id
 RETURNING o.notification_id,o.tenant_id,o.customer_id,o.event_type,o.attempt_count;
END $$;
CREATE FUNCTION securepay_private.finish_notification(n bigint,l uuid,success boolean,ref text)
 RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF n IS NULL OR l IS NULL OR success IS NULL OR
 (success AND (ref IS NULL OR length(ref) NOT BETWEEN 1 AND 200)) OR
 (NOT success AND ref IS NOT NULL) THEN RETURN false; END IF;
 UPDATE securepay_private.recovery_notification_outbox o
 SET delivered_at=CASE WHEN success THEN clock_timestamp() ELSE NULL END,
 delivery_ref=CASE WHEN success THEN ref ELSE NULL END,
 dead_lettered_at=CASE WHEN NOT success AND o.attempt_count>=8 THEN clock_timestamp() ELSE NULL END,
 next_attempt_at=CASE WHEN success THEN o.next_attempt_at ELSE clock_timestamp()+make_interval(secs=>least(3600,15*(1 << (o.attempt_count-1)))) END,
 lease_id=NULL,lease_until=NULL
 WHERE o.notification_id=n AND o.lease_id=l AND o.lease_until>clock_timestamp()
 AND o.delivered_at IS NULL AND o.dead_lettered_at IS NULL;
 RETURN FOUND;
END $$;
ALTER FUNCTION securepay_private.claim_notification(uuid) OWNER TO securepay_context_owner;
ALTER FUNCTION securepay_private.finish_notification(bigint,uuid,boolean,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.claim_notification(uuid),securepay_private.finish_notification(bigint,uuid,boolean,text) FROM PUBLIC,securepay_payer_runtime;
GRANT EXECUTE ON FUNCTION securepay_private.claim_notification(uuid),securepay_private.finish_notification(bigint,uuid,boolean,text) TO securepay_notification_runtime;
COMMIT;

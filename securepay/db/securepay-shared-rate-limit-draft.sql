-- Shared authenticated-customer rate limiting, sandbox only.
BEGIN;
CREATE TABLE securepay_private.abuse_global(
 singleton boolean PRIMARY KEY CHECK(singleton),window_id bigint NOT NULL,used integer NOT NULL CHECK(used BETWEEN 0 AND 600)
);
INSERT INTO securepay_private.abuse_global VALUES(true,0,0);
CREATE TABLE securepay_private.abuse_buckets(
 subject_digest text PRIMARY KEY CHECK(subject_digest ~ '^[a-f0-9]{64}$'),
 window_id bigint NOT NULL,used integer NOT NULL CHECK(used BETWEEN 1 AND 20)
);
ALTER TABLE securepay_private.abuse_global OWNER TO securepay_context_owner;
ALTER TABLE securepay_private.abuse_buckets OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.abuse_global,securepay_private.abuse_buckets FROM PUBLIC,securepay_payer_runtime,securepay_provider_runtime,securepay_dispute_runtime;
CREATE FUNCTION securepay_private.take_customer_budget(subject_digest text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE w bigint; current_window bigint; global_used integer; account_used integer;
BEGIN
 IF subject_digest IS NULL OR subject_digest !~ '^[a-f0-9]{64}$' THEN RETURN false; END IF;
 SELECT window_id,used INTO current_window,global_used FROM securepay_private.abuse_global WHERE singleton FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 w:=floor(extract(epoch FROM clock_timestamp())/60)::bigint;
 IF current_window>w THEN RETURN false; END IF;
 IF current_window<w THEN
  DELETE FROM securepay_private.abuse_buckets;
  UPDATE securepay_private.abuse_global SET window_id=w,used=0 WHERE singleton;
  global_used:=0;
 END IF;
 IF global_used>=600 THEN RETURN false; END IF;
 INSERT INTO securepay_private.abuse_buckets(subject_digest,window_id,used) VALUES(subject_digest,w,1)
 ON CONFLICT ON CONSTRAINT abuse_buckets_pkey DO UPDATE SET used=abuse_buckets.used+1
 WHERE abuse_buckets.window_id=w AND abuse_buckets.used<20
 RETURNING used INTO account_used;
 IF NOT FOUND THEN RETURN false; END IF;
 UPDATE securepay_private.abuse_global SET used=used+1 WHERE singleton;
 RETURN true;
END $$;
ALTER FUNCTION securepay_private.take_customer_budget(text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.take_customer_budget(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.take_customer_budget(text) TO securepay_payer_runtime;
COMMIT;

-- Isolated scanner role. Never grant it to the API role or a tenant user.
BEGIN;
DO $role$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='profitpilot_scanner') THEN
  CREATE ROLE profitpilot_scanner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
 END IF;
END $role$;
GRANT USAGE ON SCHEMA private TO profitpilot_scanner;
ALTER TABLE private.quarantined_files ALTER COLUMN ciphertext DROP NOT NULL;
ALTER TABLE private.quarantined_files
 ADD COLUMN scan_state text NOT NULL DEFAULT 'pending' CHECK(scan_state IN ('pending','scanning','clean','infected','error','disposed')),
 ADD COLUMN lease_id uuid,
 ADD COLUMN lease_until timestamptz,
 ADD COLUMN scanned_at timestamptz,
 ADD COLUMN disposed_at timestamptz,
 ADD COLUMN attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 3),
 ADD CONSTRAINT quarantine_bytes_state CHECK(
  (scan_state='disposed' AND ciphertext IS NULL AND disposed_at IS NOT NULL)
  OR (scan_state<>'disposed' AND ciphertext IS NOT NULL AND disposed_at IS NULL)),
 ADD CONSTRAINT quarantine_lease_state CHECK(
  (scan_state='scanning' AND lease_id IS NOT NULL AND lease_until IS NOT NULL)
  OR (scan_state<>'scanning' AND lease_id IS NULL AND lease_until IS NULL));
CREATE TABLE private.quarantine_lifecycle_events(
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 tenant_id uuid NOT NULL,
 batch_id uuid NOT NULL,
 event_type text NOT NULL CHECK(event_type IN ('claimed','clean','infected','error','disposed')),
 occurred_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON private.quarantine_lifecycle_events, private.quarantined_files FROM PUBLIC,profitpilot_app,profitpilot_scanner;

CREATE FUNCTION private.claim_quarantine_scan()
RETURNS TABLE(tenant_id uuid,batch_id uuid,file_sha256 text,key_id text,nonce bytea,auth_tag bytea,ciphertext bytea,lease_id uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE candidate private.quarantined_files%ROWTYPE;
BEGIN
 SELECT q.* INTO candidate FROM private.quarantined_files q
 WHERE q.created_at>clock_timestamp()-interval '24 hours' AND q.attempts<3
 AND (q.scan_state IN ('pending','error') OR (q.scan_state='scanning' AND q.lease_until<clock_timestamp()))
 ORDER BY q.created_at,q.batch_id LIMIT 1 FOR UPDATE SKIP LOCKED;
 IF NOT FOUND THEN RETURN; END IF;
 UPDATE private.quarantined_files q SET scan_state='scanning',lease_id=gen_random_uuid(),
 lease_until=clock_timestamp()+interval '2 minutes',attempts=q.attempts+1
 WHERE q.tenant_id=candidate.tenant_id AND q.batch_id=candidate.batch_id RETURNING q.* INTO candidate;
 INSERT INTO private.quarantine_lifecycle_events(tenant_id,batch_id,event_type)
 VALUES(candidate.tenant_id,candidate.batch_id,'claimed');
 RETURN QUERY SELECT candidate.tenant_id,candidate.batch_id,candidate.file_sha256,candidate.key_id,candidate.nonce,candidate.auth_tag,candidate.ciphertext,candidate.lease_id;
END $fn$;

CREATE FUNCTION private.finish_quarantine_scan(p_tenant uuid,p_batch uuid,p_lease uuid,p_verdict text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
BEGIN
 IF p_verdict IS NULL OR p_verdict NOT IN ('clean','infected','error') THEN RAISE EXCEPTION 'Invalid scan verdict'; END IF;
 UPDATE private.quarantined_files q SET scan_state=p_verdict,lease_id=NULL,lease_until=NULL,scanned_at=clock_timestamp()
 WHERE q.tenant_id=p_tenant AND q.batch_id=p_batch AND q.scan_state='scanning'
 AND q.lease_id=p_lease AND q.lease_until>=clock_timestamp();
 IF NOT FOUND THEN RETURN false; END IF;
 INSERT INTO private.quarantine_lifecycle_events(tenant_id,batch_id,event_type) VALUES(p_tenant,p_batch,p_verdict);
 RETURN true;
END $fn$;

-- After 24 hours remove only transient binary ciphertext, preserving the
-- import batch, audit, nonce uniqueness and permanent blocked-ingestion marker.
-- Hold changes and the sweep serialize on the import batch row.
CREATE FUNCTION private.expire_quarantine_bytes()
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE c record; removed integer:=0;
BEGIN
 FOR c IN SELECT b.tenant_id,b.id AS batch_id FROM public.import_batches b
 JOIN private.quarantined_files q ON q.tenant_id=b.tenant_id AND q.batch_id=b.id
 WHERE q.created_at<=clock_timestamp()-interval '24 hours' AND q.scan_state<>'disposed'
 ORDER BY q.created_at,b.id LIMIT 100 FOR UPDATE OF b SKIP LOCKED
 LOOP
  IF EXISTS(SELECT 1 FROM private.import_disposal_controls h WHERE h.tenant_id=c.tenant_id AND h.batch_id=c.batch_id AND h.hold_active) THEN CONTINUE; END IF;
  UPDATE private.quarantined_files q SET ciphertext=NULL,scan_state='disposed',lease_id=NULL,lease_until=NULL,disposed_at=clock_timestamp()
  WHERE q.tenant_id=c.tenant_id AND q.batch_id=c.batch_id AND q.scan_state<>'disposed'
  AND q.created_at<=clock_timestamp()-interval '24 hours'
  AND (q.scan_state<>'scanning' OR q.lease_until<clock_timestamp());
  IF FOUND THEN
   INSERT INTO private.quarantine_lifecycle_events(tenant_id,batch_id,event_type) VALUES(c.tenant_id,c.batch_id,'disposed');
   removed:=removed+1;
  END IF;
 END LOOP;
 RETURN removed;
END $fn$;
REVOKE ALL ON FUNCTION private.claim_quarantine_scan(),private.finish_quarantine_scan(uuid,uuid,uuid,text),private.expire_quarantine_bytes() FROM PUBLIC,profitpilot_app;
GRANT EXECUTE ON FUNCTION private.claim_quarantine_scan(),private.finish_quarantine_scan(uuid,uuid,uuid,text),private.expire_quarantine_bytes() TO profitpilot_scanner;
COMMIT;

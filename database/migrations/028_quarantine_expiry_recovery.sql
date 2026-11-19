-- Recovery-only replay of authoritative quarantine expiry receipts.
-- It deletes transient ciphertext only; accounting rows and audit history remain.
BEGIN;
ALTER TABLE private.quarantine_lifecycle_events
 DROP CONSTRAINT quarantine_lifecycle_events_event_type_check;
ALTER TABLE private.quarantine_lifecycle_events
 ADD CONSTRAINT quarantine_lifecycle_events_event_type_check
 CHECK(event_type IN ('claimed','clean','infected','error','disposed','content_validated','content_rejected','promotion_approved','promotion_claimed','promoted','promotion_failed','promotion_expired','expiry_replayed'));
CREATE TABLE private.quarantine_expiry_receipts(
 tenant_id uuid NOT NULL,
 batch_id uuid NOT NULL,
 file_sha256 text NOT NULL CHECK(file_sha256 ~ '^[a-f0-9]{64}$'),
 disposed_at timestamptz NOT NULL CHECK(isfinite(disposed_at)),
 PRIMARY KEY(tenant_id,batch_id),
 FOREIGN KEY(tenant_id,batch_id) REFERENCES private.quarantined_files(tenant_id,batch_id)
);
REVOKE ALL ON private.quarantine_expiry_receipts FROM PUBLIC,profitpilot_app,profitpilot_scanner;
INSERT INTO private.quarantine_expiry_receipts(tenant_id,batch_id,file_sha256,disposed_at)
 SELECT tenant_id,batch_id,file_sha256,disposed_at FROM private.quarantined_files WHERE scan_state='disposed';
CREATE TRIGGER quarantine_expiry_receipt_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON private.quarantine_expiry_receipts
 FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();
CREATE FUNCTION private.record_quarantine_expiry()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
BEGIN
 IF OLD.scan_state='disposed' THEN
  IF NEW IS DISTINCT FROM OLD THEN RAISE EXCEPTION 'Disposed quarantine marker is immutable'; END IF;
 ELSIF NEW.scan_state='disposed' THEN
  INSERT INTO private.quarantine_expiry_receipts(tenant_id,batch_id,file_sha256,disposed_at)
  VALUES(NEW.tenant_id,NEW.batch_id,NEW.file_sha256,NEW.disposed_at);
 END IF;
 RETURN NEW;
END $fn$;
CREATE TRIGGER quarantine_expiry_receipt AFTER UPDATE ON private.quarantined_files
 FOR EACH ROW EXECUTE FUNCTION private.record_quarantine_expiry();
CREATE FUNCTION private.replay_quarantine_expiry(p_tenant uuid,p_batch uuid,p_sha text,p_disposed timestamptz)
RETURNS boolean LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE q private.quarantined_files%ROWTYPE;
BEGIN
 IF p_tenant IS NULL OR p_batch IS NULL OR p_sha IS NULL OR p_sha !~ '^[a-f0-9]{64}$'
 OR p_disposed IS NULL OR NOT isfinite(p_disposed) OR p_disposed>clock_timestamp()
 THEN RAISE EXCEPTION 'Invalid authoritative expiry receipt'; END IF;
 PERFORM 1 FROM public.import_batches WHERE tenant_id=p_tenant AND id=p_batch FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Recovery batch not found'; END IF;
 SELECT * INTO q FROM private.quarantined_files WHERE tenant_id=p_tenant AND batch_id=p_batch FOR UPDATE;
 IF NOT FOUND OR q.file_sha256<>p_sha OR p_disposed<q.created_at+interval '24 hours'
 THEN RAISE EXCEPTION 'Restored quarantine does not match authoritative expiry receipt'; END IF;
 IF EXISTS(SELECT 1 FROM private.import_disposal_controls WHERE tenant_id=p_tenant AND batch_id=p_batch AND hold_active)
 THEN RAISE EXCEPTION 'Active legal hold blocks recovery expiry'; END IF;
 IF q.scan_state='disposed' THEN
  IF NOT EXISTS(SELECT 1 FROM private.quarantine_expiry_receipts WHERE tenant_id=p_tenant AND batch_id=p_batch AND file_sha256=p_sha AND disposed_at=p_disposed)
  THEN RAISE EXCEPTION 'Conflicting expiry receipt'; END IF;
  RETURN false;
 END IF;
 IF q.scan_state='scanning' AND q.lease_until>=clock_timestamp()
 THEN RAISE EXCEPTION 'Recovery requires scanner to be stopped'; END IF;
 UPDATE private.quarantined_files SET ciphertext=NULL,scan_state='disposed',lease_id=NULL,lease_until=NULL,disposed_at=p_disposed
 WHERE tenant_id=p_tenant AND batch_id=p_batch;
 INSERT INTO private.quarantine_lifecycle_events(tenant_id,batch_id,event_type)
 VALUES(p_tenant,p_batch,'expiry_replayed');
 RETURN true;
END $fn$;
REVOKE ALL ON FUNCTION private.record_quarantine_expiry(),private.replay_quarantine_expiry(uuid,uuid,text,timestamptz) FROM PUBLIC,profitpilot_app,profitpilot_scanner;
COMMIT;

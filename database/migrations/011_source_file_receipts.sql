-- Byte-verified CSV receipts; original bytes not readable by the application role.
BEGIN;
CREATE TABLE import_source_receipts (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id uuid NOT NULL,
 batch_id uuid NOT NULL,
 sha256 text NOT NULL CHECK(sha256 ~ '^[a-f0-9]{64}$'),
 byte_count integer NOT NULL CHECK(byte_count BETWEEN 1 AND 524288),
 row_count integer NOT NULL CHECK(row_count BETWEEN 1 AND 2000),
 parser_version text NOT NULL CHECK(parser_version='strict-csv-0.1.0'),
 original_bytes bytea NOT NULL,
 received_by uuid NOT NULL,
 received_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,batch_id),
 FOREIGN KEY(tenant_id,batch_id) REFERENCES import_batches(tenant_id,id),
 FOREIGN KEY(tenant_id,received_by) REFERENCES tenant_memberships(tenant_id,user_id),
 CHECK(byte_count=octet_length(original_bytes)),
 CHECK(sha256=encode(public.digest(original_bytes,'sha256'),'hex'))
);
ALTER TABLE import_source_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE import_source_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON import_source_receipts
 USING(tenant_id=private.current_tenant_id()) WITH CHECK(tenant_id=private.current_tenant_id());
GRANT SELECT(id,tenant_id,batch_id,sha256,byte_count,row_count,parser_version,received_by,received_at) ON import_source_receipts TO profitpilot_app;
GRANT INSERT(tenant_id,batch_id,sha256,byte_count,row_count,parser_version,original_bytes,received_by) ON import_source_receipts TO profitpilot_app;
CREATE FUNCTION private.guard_source_receipt() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,private AS $$
DECLARE b import_batches%ROWTYPE; actual_count bigint; first_row integer; last_row integer;
BEGIN
 SELECT * INTO b FROM import_batches WHERE tenant_id=NEW.tenant_id AND id=NEW.batch_id FOR UPDATE;
 IF NOT FOUND OR b.status<>'uploaded' OR b.file_sha256 IS DISTINCT FROM NEW.sha256
 THEN RAISE EXCEPTION 'Source receipt does not match open batch' USING ERRCODE='23514'; END IF;
 IF current_user='profitpilot_app' AND NOT EXISTS(
 SELECT 1 FROM users u JOIN tenant_memberships m ON m.user_id=u.id
 WHERE u.id=NEW.received_by AND u.auth_subject=nullif(current_setting('app.tenant_subject',true),'')
 AND m.tenant_id=NEW.tenant_id AND m.status='active' AND m.role IN ('owner','admin','analyst'))
 THEN RAISE EXCEPTION 'Invalid source receipt actor' USING ERRCODE='42501'; END IF;
 SELECT count(*),min(row_number),max(row_number) INTO actual_count,first_row,last_row
 FROM raw_import_rows WHERE tenant_id=NEW.tenant_id AND batch_id=NEW.batch_id;
 IF actual_count<>NEW.row_count OR first_row<>1 OR last_row<>NEW.row_count
 OR EXISTS(SELECT 1 FROM mapping_decisions m JOIN raw_import_rows r ON r.id=m.raw_row_id AND r.tenant_id=m.tenant_id WHERE r.tenant_id=NEW.tenant_id AND r.batch_id=NEW.batch_id)
 THEN RAISE EXCEPTION 'Source receipt row coverage mismatch' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER source_receipt_guard BEFORE INSERT ON import_source_receipts FOR EACH ROW EXECUTE FUNCTION private.guard_source_receipt();
CREATE FUNCTION private.guard_raw_source_append() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,private AS $$
DECLARE b_status text;
BEGIN
 SELECT status INTO b_status FROM import_batches WHERE tenant_id=NEW.tenant_id AND id=NEW.batch_id FOR UPDATE;
 IF NOT FOUND OR EXISTS(SELECT 1 FROM import_source_receipts WHERE tenant_id=NEW.tenant_id AND batch_id=NEW.batch_id)
 THEN RAISE EXCEPTION 'Verified source rows are sealed' USING ERRCODE='23514'; END IF;
 IF current_user='profitpilot_app' AND (b_status NOT IN ('uploaded','review') OR EXISTS(
 SELECT 1 FROM mapping_decisions m JOIN raw_import_rows r ON r.id=m.raw_row_id AND r.tenant_id=m.tenant_id
 WHERE r.tenant_id=NEW.tenant_id AND r.batch_id=NEW.batch_id))
 THEN RAISE EXCEPTION 'Import rows are sealed' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER raw_source_append_guard BEFORE INSERT ON raw_import_rows FOR EACH ROW EXECUTE FUNCTION private.guard_raw_source_append();
COMMIT;

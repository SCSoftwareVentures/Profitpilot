-- Signed recovery packages expose only minimal privacy receipts and active
-- legal-hold identifiers to a dedicated offline export role.
BEGIN;
CREATE TRIGGER import_disposal_tombstone_immutable
 BEFORE UPDATE OR DELETE OR TRUNCATE ON private.import_disposal_tombstones
 FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();
CREATE TRIGGER import_disposal_event_immutable
 BEFORE UPDATE OR DELETE OR TRUNCATE ON private.import_disposal_events
 FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();
ALTER TABLE private.import_disposal_tombstones
 ADD CONSTRAINT import_disposal_finite_timestamp CHECK(isfinite(disposed_at)),
 ADD CONSTRAINT import_disposal_opaque_authority CHECK(private.disposal_reference_valid(authority_ref));

DO $role$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='profitpilot_recovery_reader') THEN
  CREATE ROLE profitpilot_recovery_reader NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
 END IF;
END $role$;
GRANT USAGE ON SCHEMA private TO profitpilot_recovery_reader;
REVOKE CREATE ON SCHEMA public,private FROM profitpilot_recovery_reader;

CREATE FUNCTION private.privacy_recovery_inventory()
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE disposals jsonb; expiries jsonb; holds jsonb;
BEGIN
 SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY x.tenant_id,x.batch_id),'[]'::jsonb) INTO disposals
 FROM (SELECT tenant_id,batch_id,file_sha256,authority_ref,
 to_char(disposed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS disposed_at
 FROM private.import_disposal_tombstones ORDER BY tenant_id,batch_id LIMIT 100001) x;
 SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY x.tenant_id,x.batch_id),'[]'::jsonb) INTO expiries
 FROM (SELECT tenant_id,batch_id,file_sha256,
 to_char(disposed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS disposed_at
 FROM private.quarantine_expiry_receipts ORDER BY tenant_id,batch_id LIMIT 100001) x;
 SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY x.tenant_id,x.batch_id),'[]'::jsonb) INTO holds
 FROM (SELECT tenant_id,batch_id FROM private.import_disposal_controls WHERE hold_active ORDER BY tenant_id,batch_id LIMIT 100001) x;
 IF jsonb_array_length(disposals)+jsonb_array_length(expiries)+jsonb_array_length(holds)>100000 THEN
  RAISE EXCEPTION 'Privacy recovery inventory exceeds reviewed capacity' USING ERRCODE='54000';
 END IF;
 RETURN jsonb_build_object('disposals',disposals,'expiries',expiries,'holds',holds);
END $fn$;
REVOKE ALL ON FUNCTION private.privacy_recovery_inventory() FROM PUBLIC,profitpilot_app,profitpilot_scanner,profitpilot_recovery_reader;
GRANT EXECUTE ON FUNCTION private.privacy_recovery_inventory() TO profitpilot_recovery_reader;
COMMIT;

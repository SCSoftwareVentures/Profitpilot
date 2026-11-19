-- A dedicated auditor can read only verified hash/count metadata, not events or financial data.
BEGIN;
DO $role$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='profitpilot_audit_reader') THEN
  CREATE ROLE profitpilot_audit_reader NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
 END IF;
END $role$;
GRANT USAGE ON SCHEMA private TO profitpilot_audit_reader;
CREATE FUNCTION private.audit_checkpoint_heads()
RETURNS TABLE(tenant_id uuid,entry_count bigint,head_hash text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE t uuid;
BEGIN
 FOR t IN SELECT id FROM public.tenants ORDER BY id LOOP
  IF NOT private.verify_audit_chain(t) THEN RAISE EXCEPTION 'Audit integrity verification failed' USING ERRCODE='55000'; END IF;
 END LOOP;
 RETURN QUERY SELECT h.tenant_id,h.entry_count,h.head_hash FROM private.audit_chain_heads h ORDER BY h.tenant_id;
END $fn$;

-- Compare an external checkpoint with the historical prefix, not just the latest head.
CREATE FUNCTION private.audit_checkpoint_matches(p_tenant uuid,p_seq bigint,p_hash text)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
BEGIN
 IF p_tenant IS NULL OR p_seq IS NULL OR p_seq<=0 OR p_hash IS NULL OR p_hash !~ '^[a-f0-9]{64}$' THEN RETURN false; END IF;
 RETURN private.verify_audit_chain(p_tenant) AND EXISTS(SELECT 1 FROM private.audit_chain_entries
 WHERE tenant_id=p_tenant AND sequence_no=p_seq AND event_hash=p_hash);
END $fn$;
REVOKE ALL ON FUNCTION private.audit_checkpoint_heads(),private.audit_checkpoint_matches(uuid,bigint,text) FROM PUBLIC,profitpilot_app;
GRANT EXECUTE ON FUNCTION private.audit_checkpoint_heads(),private.audit_checkpoint_matches(uuid,bigint,text) TO profitpilot_audit_reader;
COMMIT;

-- Distinguish malware verdict from strict invoice format/privacy preflight.
-- Neither verdict grants permission to ingest or download any quarantined bytes.
BEGIN;
ALTER TABLE private.quarantined_files
 ADD COLUMN content_state text NOT NULL DEFAULT 'not_checked'
 CHECK(content_state IN ('not_checked','validated','rejected')),
 ADD CONSTRAINT quarantine_content_state_check CHECK(
  content_state='not_checked' OR scan_state IN ('clean','disposed'));
ALTER TABLE private.quarantine_lifecycle_events
 DROP CONSTRAINT quarantine_lifecycle_events_event_type_check;
ALTER TABLE private.quarantine_lifecycle_events
 ADD CONSTRAINT quarantine_lifecycle_events_event_type_check
 CHECK(event_type IN ('claimed','clean','infected','error','disposed','content_validated','content_rejected'));

CREATE FUNCTION private.finish_quarantine_scan_with_content(p_tenant uuid,p_batch uuid,p_lease uuid,p_verdict text,p_content text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
BEGIN
 IF p_verdict IS NULL OR p_content IS NULL OR
  (p_verdict='clean' AND p_content NOT IN ('validated','rejected')) OR
  (p_verdict IN ('infected','error') AND p_content<>'not_checked') OR
  p_verdict NOT IN ('clean','infected','error') THEN
  RAISE EXCEPTION 'Invalid malware and content verdict combination' USING ERRCODE='22023';
 END IF;
 IF NOT private.finish_quarantine_scan(p_tenant,p_batch,p_lease,p_verdict) THEN RETURN false; END IF;
 IF p_verdict='clean' THEN
  UPDATE private.quarantined_files SET content_state=p_content
  WHERE tenant_id=p_tenant AND batch_id=p_batch;
  INSERT INTO private.quarantine_lifecycle_events(tenant_id,batch_id,event_type)
  VALUES(p_tenant,p_batch,CASE p_content WHEN 'validated' THEN 'content_validated' ELSE 'content_rejected' END);
 END IF;
 RETURN true;
END $fn$;
REVOKE ALL ON FUNCTION private.finish_quarantine_scan(uuid,uuid,uuid,text) FROM profitpilot_scanner;
REVOKE ALL ON FUNCTION private.finish_quarantine_scan_with_content(uuid,uuid,uuid,text,text) FROM PUBLIC,profitpilot_app;
GRANT EXECUTE ON FUNCTION private.finish_quarantine_scan_with_content(uuid,uuid,uuid,text,text) TO profitpilot_scanner;
COMMIT;

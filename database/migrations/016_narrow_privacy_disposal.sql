-- Narrow operational disposal of unused client-declared imports; never a blanket erasure.
BEGIN;
ALTER TABLE import_batches ADD COLUMN retention_hold boolean NOT NULL DEFAULT true;
ALTER TABLE import_batches ADD COLUMN retention_release_reference text
 CHECK(retention_release_reference ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{2,119}$');
ALTER TABLE import_batches ADD CONSTRAINT import_retention_release_check
 CHECK(retention_hold OR retention_release_reference IS NOT NULL);
-- Runtime UPDATE privileges remain limited to status. Only a privileged operator can release a hold.
CREATE FUNCTION private.dispose_unused_import(p_tenant uuid,p_batch uuid,p_case uuid,p_policy text)
 RETURNS integer LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public,private AS $$
DECLARE b import_batches%ROWTYPE; r privacy_requests%ROWTYPE; n integer;
BEGIN
 IF p_policy IS NULL OR p_policy !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{2,119}$'
 THEN RAISE EXCEPTION 'Approved policy reference required' USING ERRCODE='23514'; END IF;
 SELECT * INTO r FROM privacy_requests WHERE tenant_id=p_tenant AND id=p_case FOR UPDATE;
 IF NOT FOUND OR r.request_type<>'erasure' OR r.status<>'reviewing' OR r.review_reference IS DISTINCT FROM p_policy
 OR NOT EXISTS(SELECT 1 FROM tenant_memberships m JOIN users u ON u.id=m.user_id WHERE m.tenant_id=p_tenant AND m.user_id=r.reviewed_by AND m.status='active' AND m.role IN ('owner','admin') AND u.status='active')
 THEN RAISE EXCEPTION 'Eligible independently reviewed erasure request required' USING ERRCODE='23514'; END IF;
 SELECT * INTO b FROM import_batches WHERE tenant_id=p_tenant AND id=p_batch FOR UPDATE;
 IF NOT FOUND OR b.created_by<>r.requester_id OR b.status<>'uploaded' OR b.retention_hold
 OR b.retention_release_reference IS DISTINCT FROM p_policy
 OR EXISTS(SELECT 1 FROM import_source_receipts s WHERE s.tenant_id=p_tenant AND s.batch_id=p_batch)
 OR EXISTS(SELECT 1 FROM payroll_pools p WHERE p.tenant_id=p_tenant AND p.batch_id=p_batch)
 OR EXISTS(SELECT 1 FROM raw_import_rows rr JOIN mapping_decisions m ON m.tenant_id=rr.tenant_id AND m.raw_row_id=rr.id WHERE rr.tenant_id=p_tenant AND rr.batch_id=p_batch)
 OR EXISTS(SELECT 1 FROM raw_import_rows rr JOIN invoice_lines l ON l.tenant_id=rr.tenant_id AND l.source_row_id=rr.id WHERE rr.tenant_id=p_tenant AND rr.batch_id=p_batch)
 OR EXISTS(SELECT 1 FROM raw_import_rows rr JOIN invoice_identity_claims c ON c.tenant_id=rr.tenant_id AND c.raw_row_id=rr.id WHERE rr.tenant_id=p_tenant AND rr.batch_id=p_batch)
 OR EXISTS(SELECT 1 FROM audit_events a WHERE a.tenant_id=p_tenant AND a.object_id=p_batch)
 THEN RAISE EXCEPTION 'Import retained or ineligible for narrow disposal' USING ERRCODE='23514'; END IF;
 DELETE FROM raw_import_rows WHERE tenant_id=p_tenant AND batch_id=p_batch;
 GET DIAGNOSTICS n=ROW_COUNT;
 DELETE FROM import_batches WHERE tenant_id=p_tenant AND id=p_batch;
 IF NOT FOUND OR EXISTS(SELECT 1 FROM raw_import_rows WHERE tenant_id=p_tenant AND batch_id=p_batch)
 THEN RAISE EXCEPTION 'Disposal verification failed' USING ERRCODE='23514'; END IF;
 INSERT INTO audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata)
 VALUES(p_tenant,r.reviewed_by,'unused_import_disposed','privacy_request',p_case,'Privileged operator disposed eligible unused import',
 jsonb_build_object('batchId',p_batch,'deletedRows',n,'policyReference',p_policy,'scope','primary_database_only','operatorRole',current_user));
 RETURN n;
END $$;
REVOKE ALL ON FUNCTION private.dispose_unused_import(uuid,uuid,uuid,text) FROM PUBLIC,profitpilot_app;
COMMIT;

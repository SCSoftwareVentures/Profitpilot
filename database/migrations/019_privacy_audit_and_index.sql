BEGIN;
CREATE INDEX privacy_request_subject_page_idx ON privacy_requests(tenant_id,requester_id,created_at DESC,id DESC);
CREATE POLICY privacy_audit_visibility ON audit_events AS RESTRICTIVE FOR SELECT TO profitpilot_app
 USING(object_type<>'privacy_request' OR private.actor_role() IN ('owner','admin') OR EXISTS(
 SELECT 1 FROM privacy_requests p WHERE p.tenant_id=audit_events.tenant_id AND p.id=audit_events.object_id AND p.requester_id=private.actor_id()));
DROP INDEX raw_invoice_reference_review_idx;
CREATE INDEX raw_invoice_reference_review_idx ON raw_import_rows(tenant_id,md5(private.invoice_review_alias(payload->>'invoice_id'))) WHERE jsonb_typeof(payload->'invoice_id')='string';
COMMIT;

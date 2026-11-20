-- S10: separation of duties for privacy case final decisions, safe administrator paging.
-- Existing closed cases have no reconstructable initiation actor in the table;
-- preserve their audit history without inventing one. Enforce on new transitions.
BEGIN;
ALTER TABLE privacy_requests ADD COLUMN review_started_by uuid;
ALTER TABLE privacy_requests ADD CONSTRAINT privacy_case_initiator_same_tenant
  FOREIGN KEY(tenant_id,review_started_by) REFERENCES tenant_memberships(tenant_id,user_id);
ALTER TABLE privacy_requests ADD CONSTRAINT privacy_case_initiator_not_requester
  CHECK(review_started_by IS NULL OR review_started_by<>requester_id);
UPDATE privacy_requests SET review_started_by=reviewed_by WHERE status='reviewing';
CREATE INDEX privacy_requests_tenant_page ON privacy_requests(tenant_id,created_at DESC,id DESC);
-- The app never receives direct UPDATE privilege for review_started_by.
CREATE FUNCTION private.require_separate_privacy_closure() RETURNS trigger
 LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public,private AS $$
BEGIN
 IF OLD.status='requested' AND NEW.status='reviewing' THEN
   IF NEW.reviewed_by IS NULL OR NEW.reviewed_by=OLD.requester_id THEN
     RAISE EXCEPTION 'Independent initial reviewer required' USING ERRCODE='23514';
   END IF;
   NEW.review_started_by:=NEW.reviewed_by;
 ELSIF OLD.status='reviewing' AND NEW.status IN ('closed_attested','declined') THEN
   IF OLD.review_started_by IS NULL
      OR NEW.review_started_by IS DISTINCT FROM OLD.review_started_by
      OR NEW.reviewed_by IS NULL
      OR NEW.reviewed_by=OLD.review_started_by
      OR NEW.reviewed_by=OLD.requester_id THEN
     RAISE EXCEPTION 'A distinct authorised closure reviewer is required' USING ERRCODE='23514';
   END IF;
 ELSIF NEW.review_started_by IS DISTINCT FROM OLD.review_started_by THEN
   RAISE EXCEPTION 'Review initiator may not be modified' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- Runs before privacy_review_guard's event insertion; all changes are atomic.
CREATE TRIGGER privacy_00_separation_guard BEFORE UPDATE ON privacy_requests
 FOR EACH ROW EXECUTE FUNCTION private.require_separate_privacy_closure();
COMMIT;

-- Tenant-scoped privacy case tracking, not automated erasure.
BEGIN;
CREATE TABLE privacy_requests (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id uuid NOT NULL,
 requester_id uuid NOT NULL,
 client_request_id uuid NOT NULL,
 request_type text NOT NULL CHECK(request_type IN ('access','correction','erasure','restriction')),
 status text NOT NULL DEFAULT 'requested' CHECK(status IN ('requested','reviewing','closed_attested','declined')),
 created_at timestamptz NOT NULL DEFAULT now(),
 reviewed_by uuid,
 reviewed_at timestamptz,
 review_reference text CHECK(review_reference ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{2,119}$'),
 UNIQUE(tenant_id,requester_id,client_request_id),
 FOREIGN KEY(tenant_id,requester_id) REFERENCES tenant_memberships(tenant_id,user_id),
 FOREIGN KEY(tenant_id,reviewed_by) REFERENCES tenant_memberships(tenant_id,user_id),
 CHECK((status='requested' AND reviewed_by IS NULL AND reviewed_at IS NULL AND review_reference IS NULL)
 OR (status<>'requested' AND reviewed_by IS NOT NULL AND reviewed_by<>requester_id AND reviewed_at IS NOT NULL AND review_reference IS NOT NULL))
);
ALTER TABLE privacy_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE privacy_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY privacy_request_read ON privacy_requests FOR SELECT TO profitpilot_app
 USING(tenant_id=private.current_tenant_id() AND (requester_id=private.actor_id() OR private.actor_role() IN ('owner','admin')));
CREATE POLICY privacy_request_insert ON privacy_requests FOR INSERT TO profitpilot_app
 WITH CHECK(tenant_id=private.current_tenant_id() AND requester_id=private.actor_id() AND status='requested');
CREATE POLICY privacy_request_review ON privacy_requests FOR UPDATE TO profitpilot_app
 USING(tenant_id=private.current_tenant_id() AND private.actor_role() IN ('owner','admin') AND requester_id<>private.actor_id() AND status IN ('requested','reviewing'))
 WITH CHECK(tenant_id=private.current_tenant_id() AND private.actor_role() IN ('owner','admin') AND reviewed_by=private.actor_id() AND requester_id<>private.actor_id());
GRANT SELECT ON privacy_requests TO profitpilot_app;
GRANT INSERT(tenant_id,requester_id,client_request_id,request_type) ON privacy_requests TO profitpilot_app;
GRANT UPDATE(status,reviewed_by,reviewed_at,review_reference) ON privacy_requests TO profitpilot_app;
CREATE FUNCTION private.guard_privacy_review() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,private AS $$
BEGIN
 IF NOT ((OLD.status='requested' AND NEW.status='reviewing') OR
 (OLD.status='reviewing' AND NEW.status IN ('closed_attested','declined'))) THEN
 RAISE EXCEPTION 'Invalid privacy review transition' USING ERRCODE='23514'; END IF;
 IF current_user='profitpilot_app' THEN
 INSERT INTO audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata)
 VALUES(NEW.tenant_id,private.actor_id(),'privacy_request_review','privacy_request',NEW.id,'Privacy case review recorded',
 jsonb_build_object('previous',OLD.status,'status',NEW.status,'reference',NEW.review_reference,'externalFulfilmentVerified',false));
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER privacy_review_guard BEFORE UPDATE ON privacy_requests FOR EACH ROW EXECUTE FUNCTION private.guard_privacy_review();
COMMIT;

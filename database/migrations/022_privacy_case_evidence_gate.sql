-- S11: operator-supplied fulfilment references; NOT verification of downstream action.
BEGIN;
ALTER TABLE privacy_requests ADD CONSTRAINT privacy_requests_tenant_id_id_unique UNIQUE(tenant_id,id);
CREATE TABLE private.privacy_case_evidence(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id uuid NOT NULL,
 case_id uuid NOT NULL,
 scope text NOT NULL CHECK(scope IN ('identity','primary','backups','processors','logs','decision')),
 outcome text NOT NULL CHECK(outcome IN ('fulfilled','not_applicable','lawful_exception')),
 evidence_reference text NOT NULL CHECK(evidence_reference ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{2,119}$'),
 recorded_by uuid NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,case_id,scope),
 FOREIGN KEY(tenant_id,case_id) REFERENCES privacy_requests(tenant_id,id),
 FOREIGN KEY(tenant_id,recorded_by) REFERENCES tenant_memberships(tenant_id,user_id),
 CHECK(scope<>'identity' OR outcome='fulfilled'),
 CHECK(scope<>'decision' OR outcome='lawful_exception')
);
ALTER TABLE private.privacy_case_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.privacy_case_evidence FORCE ROW LEVEL SECURITY;
CREATE POLICY evidence_read ON private.privacy_case_evidence FOR SELECT TO profitpilot_app USING(
 tenant_id=private.current_tenant_id() AND
 (private.actor_role() IN ('owner','admin')
 OR EXISTS(SELECT 1 FROM privacy_requests p WHERE p.tenant_id=privacy_case_evidence.tenant_id
 AND p.id=privacy_case_evidence.case_id AND p.requester_id=private.actor_id()))
);
GRANT SELECT ON private.privacy_case_evidence TO profitpilot_app;
CREATE FUNCTION private.guard_privacy_case_evidence() RETURNS trigger
 LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public,private AS $$
DECLARE case_status text; requester uuid;
BEGIN
 SELECT status,requester_id INTO case_status,requester
 FROM privacy_requests WHERE tenant_id=NEW.tenant_id AND id=NEW.case_id;
 IF case_status IS DISTINCT FROM 'reviewing' OR requester=NEW.recorded_by
 OR NOT EXISTS(SELECT 1 FROM tenant_memberships m JOIN users u ON u.id=m.user_id
  WHERE m.tenant_id=NEW.tenant_id AND m.user_id=NEW.recorded_by
  AND m.status='active' AND m.role IN ('owner','admin') AND u.status='active')
 THEN RAISE EXCEPTION 'Reviewing case and independent active evidence operator required' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER privacy_case_evidence_guard BEFORE INSERT ON private.privacy_case_evidence
 FOR EACH ROW EXECUTE FUNCTION private.guard_privacy_case_evidence();
CREATE FUNCTION private.log_privacy_case_evidence() RETURNS trigger
 LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public,private AS $$
BEGIN
 INSERT INTO audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata)
 VALUES(NEW.tenant_id,NEW.recorded_by,'privacy_evidence_recorded','privacy_request',NEW.case_id,
 'Operator asserted privacy evidence reference',
 jsonb_build_object('scope',NEW.scope,'outcome',NEW.outcome,'reference',NEW.evidence_reference,'externalFulfilmentVerified',false));
 RETURN NEW;
END $$;
CREATE TRIGGER privacy_case_evidence_audit AFTER INSERT ON private.privacy_case_evidence
 FOR EACH ROW EXECUTE FUNCTION private.log_privacy_case_evidence();
CREATE FUNCTION private.require_case_fulfilment_scope() RETURNS trigger
 LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public,private AS $$
DECLARE scopes integer;
BEGIN
 IF OLD.status='reviewing' AND NEW.status='closed_attested' THEN
  SELECT count(*) INTO scopes FROM private.privacy_case_evidence e
  WHERE e.tenant_id=NEW.tenant_id AND e.case_id=NEW.id
  AND e.scope IN ('identity','primary','backups','processors','logs');
  IF scopes<>5 THEN RAISE EXCEPTION 'All five operator evidence scopes required before attested closure' USING ERRCODE='23514'; END IF;
 ELSIF OLD.status='reviewing' AND NEW.status='declined' THEN
  IF NOT EXISTS(SELECT 1 FROM private.privacy_case_evidence e
    WHERE e.tenant_id=NEW.tenant_id AND e.case_id=NEW.id AND e.scope='decision' AND e.outcome='lawful_exception')
  THEN RAISE EXCEPTION 'Documented decision basis required before decline' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER privacy_01_case_evidence_guard BEFORE UPDATE ON privacy_requests
 FOR EACH ROW EXECUTE FUNCTION private.require_case_fulfilment_scope();
COMMIT;

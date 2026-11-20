-- S9: constrain audit data to accountable actors and protect runtime audit semantics.
-- This is not tamper-proof against a privileged database owner or a compromised app process.
BEGIN;

-- Audit metadata may contain contract, source and reviewer details. Read-only users
-- must not see arbitrary tenant audit contents, and analysts review only their own.
CREATE POLICY audit_need_to_know ON audit_events AS RESTRICTIVE FOR SELECT TO profitpilot_app
 USING (
  private.actor_role() IN ('owner','admin')
  OR (object_type='privacy_request' AND EXISTS (
   SELECT 1 FROM privacy_requests p WHERE p.tenant_id=audit_events.tenant_id
   AND p.id=audit_events.object_id AND p.requester_id=private.actor_id()))
  OR (object_type<>'privacy_request' AND actor_user_id=private.actor_id()
      AND private.actor_role() IN ('analyst','reviewer'))
 );

-- There must be a real source object for every runtime audit event, never an
-- arbitrary actor-supplied action name or object-type pair. This protects the
-- semantics of the event vocabulary, not the truth of privileged administrators.
CREATE FUNCTION private.guard_runtime_audit() RETURNS trigger
 LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public,private AS $$
BEGIN
 IF current_user <> 'profitpilot_app' THEN RETURN NEW; END IF;
 IF NEW.actor_user_id IS DISTINCT FROM private.actor_id() THEN
  RAISE EXCEPTION 'Audit actor does not match verified tenant identity' USING ERRCODE='42501';
 END IF;
 IF NEW.object_id IS NULL OR jsonb_typeof(NEW.metadata) <> 'object'
 OR octet_length(NEW.metadata::text) > 262144
 OR (NEW.reason IS NOT NULL AND (length(NEW.reason)>2000 OR NEW.reason ~ '[[:cntrl:]]'))
 OR NOT (
  (NEW.action='source_file_verified' AND NEW.object_type='import_batch'
    AND EXISTS(SELECT 1 FROM import_source_receipts r WHERE r.tenant_id=NEW.tenant_id AND r.batch_id=NEW.object_id))
  OR (NEW.action='invoice_identity_reserved' AND NEW.object_type='invoice_identity_claim'
    AND EXISTS(SELECT 1 FROM invoice_identity_claims r WHERE r.tenant_id=NEW.tenant_id AND r.id=NEW.object_id))
  OR (NEW.action='payroll_reconciled' AND NEW.object_type='allocation_run'
    AND EXISTS(SELECT 1 FROM allocation_runs r WHERE r.tenant_id=NEW.tenant_id AND r.id=NEW.object_id AND r.status='confirmed'))
  OR (NEW.action='invoice_match_decision' AND NEW.object_type='match_review'
    AND EXISTS(SELECT 1 FROM match_reviews r WHERE r.tenant_id=NEW.tenant_id AND r.id=NEW.object_id AND r.decision IN ('confirmed','held','rejected')))
  OR (NEW.action='calculation_created' AND NEW.object_type='calculation_run'
    AND EXISTS(SELECT 1 FROM calculation_runs r WHERE r.tenant_id=NEW.tenant_id AND r.id=NEW.object_id))
  OR (NEW.action='privacy_request_review' AND NEW.object_type='privacy_request'
    AND EXISTS(SELECT 1 FROM privacy_requests r WHERE r.tenant_id=NEW.tenant_id AND r.id=NEW.object_id))
  OR (NEW.action='invoice_confirmation_rehearsed' AND NEW.object_type='invoice_confirmation_rehearsal'
    AND EXISTS(SELECT 1 FROM invoice_confirmation_rehearsals r WHERE r.tenant_id=NEW.tenant_id AND r.id=NEW.object_id))
  OR (NEW.action='payroll_contract_rehearsed' AND NEW.object_type='payroll_contract_rehearsal'
    AND EXISTS(SELECT 1 FROM payroll_contract_rehearsals r WHERE r.tenant_id=NEW.tenant_id AND r.id=NEW.object_id))
 )
 THEN RAISE EXCEPTION 'Invalid audited event or source evidence' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER runtime_audit_guard BEFORE INSERT ON audit_events FOR EACH ROW
 EXECUTE FUNCTION private.guard_runtime_audit();

-- Direct runtime SQL must reject bidi-control payloads just like the HTTP parser.
-- An additional trigger is used to preserve the existing raw-row source guard.
CREATE FUNCTION private.reject_bidi_raw_payload() RETURNS trigger
 LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public,private AS $$
DECLARE controls text:=chr(8234)||chr(8235)||chr(8236)||chr(8237)||chr(8238)||
 chr(8294)||chr(8295)||chr(8296)||chr(8297);
BEGIN
 IF current_user='profitpilot_app' AND EXISTS(
  SELECT 1 FROM jsonb_each(NEW.payload) e WHERE jsonb_typeof(e.value)='string'
  AND translate(e.value#>>'{}',controls,'') IS DISTINCT FROM e.value#>>'{}'
 ) THEN
  RAISE EXCEPTION 'Bidi control characters prohibited in source fields' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER raw_bidi_rejection BEFORE INSERT ON raw_import_rows FOR EACH ROW
 EXECUTE FUNCTION private.reject_bidi_raw_payload();
COMMIT;

-- SP-S7: append-only administrative withdrawal of synthetic party-key claims.
-- Does not prove that a real-world party revoked their consent or identity.
BEGIN;
ALTER TABLE securepay_signed_party_claims
 ADD CONSTRAINT securepay_signed_claim_revocation_scope_unique UNIQUE(tenant_id,case_id,evidence_id,id);
CREATE TABLE securepay_signed_claim_revocations (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id uuid NOT NULL,
 case_id uuid NOT NULL,
 evidence_id uuid NOT NULL,
 claim_id uuid NOT NULL,
 client_request_id uuid NOT NULL,
 revoked_by uuid NOT NULL,
 reason_code text NOT NULL CHECK(reason_code IN
  ('operator_withdrawal','suspected_key_compromise','provenance_disputed','administrative_hold')),
 revocation_reference text NOT NULL CHECK(revocation_reference ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{2,119}$'),
 recorded_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,id),
 UNIQUE(tenant_id,case_id,evidence_id,claim_id),
 UNIQUE(tenant_id,revoked_by,client_request_id),
 FOREIGN KEY(tenant_id,case_id,evidence_id,claim_id)
  REFERENCES securepay_signed_party_claims(tenant_id,case_id,evidence_id,id),
 FOREIGN KEY(tenant_id,revoked_by) REFERENCES tenant_memberships(tenant_id,user_id)
);
CREATE INDEX securepay_revocation_case_lookup ON securepay_signed_claim_revocations(tenant_id,case_id,claim_id);
ALTER TABLE securepay_signed_claim_revocations ENABLE ROW LEVEL SECURITY;
ALTER TABLE securepay_signed_claim_revocations FORCE ROW LEVEL SECURITY;
CREATE POLICY securepay_revocation_read ON securepay_signed_claim_revocations FOR SELECT TO profitpilot_app
 USING(tenant_id=private.current_tenant_id() AND private.actor_role() IN ('owner','admin','reviewer'));
CREATE POLICY securepay_revocation_insert ON securepay_signed_claim_revocations FOR INSERT TO profitpilot_app
 WITH CHECK(tenant_id=private.current_tenant_id() AND revoked_by=private.actor_id()
 AND private.actor_role() IN ('owner','admin','reviewer')
 AND EXISTS(SELECT 1 FROM securepay_signed_party_claims c WHERE
  c.tenant_id=securepay_signed_claim_revocations.tenant_id
  AND c.case_id=securepay_signed_claim_revocations.case_id
  AND c.evidence_id=securepay_signed_claim_revocations.evidence_id
  AND c.id=securepay_signed_claim_revocations.claim_id
  AND (private.actor_role() IN ('owner','admin') OR c.recorded_by=private.actor_id())));
GRANT SELECT ON securepay_signed_claim_revocations TO profitpilot_app;
GRANT INSERT(tenant_id,case_id,evidence_id,claim_id,client_request_id,revoked_by,reason_code,revocation_reference)
 ON securepay_signed_claim_revocations TO profitpilot_app;
CREATE TRIGGER securepay_revocation_append_only BEFORE UPDATE OR DELETE ON securepay_signed_claim_revocations
 FOR EACH ROW EXECUTE FUNCTION private.securepay_reject_mutation();
COMMIT;

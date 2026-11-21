-- SP-S6 cryptographically verifiable self-supplied Ed25519-key claim receipts.
-- This verifies signatures only. Trust anchor, party identity, job authority and contents
-- are NOT verified; no payments and no binding decisions can be authorised.
BEGIN;
ALTER TABLE securepay_evidence_provenance_receipts
 ADD CONSTRAINT securepay_provenance_scoped_claim_fk UNIQUE(tenant_id,case_id,evidence_id,id);
CREATE TABLE securepay_signed_party_claims (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id uuid NOT NULL,
 case_id uuid NOT NULL,
 evidence_id uuid NOT NULL,
 provenance_receipt_id uuid NOT NULL,
 client_request_id uuid NOT NULL,
 recorded_by uuid NOT NULL,
 claimed_party_role text NOT NULL CHECK(claimed_party_role IN ('customer','tradesperson')),
 key_spki text NOT NULL CHECK(key_spki ~ '^[A-Za-z0-9_-]{59}$'),
 claim_nonce uuid NOT NULL,
 claimed_content_sha256 text NOT NULL CHECK(claimed_content_sha256 ~ '^[a-f0-9]{64}$'),
 signature text NOT NULL CHECK(signature ~ '^[A-Za-z0-9_-]{86}$'),
 statement_sha256 text NOT NULL CHECK(statement_sha256 ~ '^[a-f0-9]{64}$'),
 key_spki_sha256 text NOT NULL CHECK(key_spki_sha256 ~ '^[a-f0-9]{64}$'),
 issuer_trusted boolean NOT NULL DEFAULT false CHECK(issuer_trusted=false),
 party_identity_verified boolean NOT NULL DEFAULT false CHECK(party_identity_verified=false),
 job_authority_verified boolean NOT NULL DEFAULT false CHECK(job_authority_verified=false),
 content_verified boolean NOT NULL DEFAULT false CHECK(content_verified=false),
 decision_authority boolean NOT NULL DEFAULT false CHECK(decision_authority=false),
 payment_authority boolean NOT NULL DEFAULT false CHECK(payment_authority=false),
 recorded_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,id),
 UNIQUE(tenant_id,case_id,evidence_id,recorded_by,client_request_id),
 FOREIGN KEY(tenant_id,case_id,evidence_id,provenance_receipt_id)
  REFERENCES securepay_evidence_provenance_receipts(tenant_id,case_id,evidence_id,id),
 FOREIGN KEY(tenant_id,recorded_by) REFERENCES tenant_memberships(tenant_id,user_id)
);
CREATE INDEX securepay_signed_party_claims_list ON securepay_signed_party_claims(tenant_id,case_id,evidence_id,recorded_at DESC,id DESC);
ALTER TABLE securepay_signed_party_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE securepay_signed_party_claims FORCE ROW LEVEL SECURITY;
CREATE POLICY securepay_signed_claims_read ON securepay_signed_party_claims FOR SELECT TO profitpilot_app
 USING(tenant_id=private.current_tenant_id() AND private.actor_role() IN ('owner','admin','reviewer'));
CREATE POLICY securepay_signed_claims_insert ON securepay_signed_party_claims FOR INSERT TO profitpilot_app
 WITH CHECK(tenant_id=private.current_tenant_id() AND recorded_by=private.actor_id()
 AND private.actor_role() IN ('owner','admin','reviewer')
 AND EXISTS(
  SELECT 1 FROM securepay_evidence_provenance_receipts p
   JOIN securepay_evidence_rehearsals e ON e.tenant_id=p.tenant_id AND e.case_id=p.case_id AND e.id=p.evidence_id
   JOIN securepay_case_rehearsals c ON c.tenant_id=p.tenant_id AND c.id=p.case_id
  WHERE p.tenant_id=securepay_signed_party_claims.tenant_id
   AND p.case_id=securepay_signed_party_claims.case_id
   AND p.evidence_id=securepay_signed_party_claims.evidence_id
   AND p.id=securepay_signed_party_claims.provenance_receipt_id
   AND c.synthetic=true AND c.funds_moved=false
   AND ((securepay_signed_party_claims.claimed_party_role='customer' AND p.reported_origin='reported_customer' AND e.evidence_type='claim_reported') OR
        (securepay_signed_party_claims.claimed_party_role='tradesperson' AND p.reported_origin='reported_business' AND e.evidence_type='business_response_reported'))
 ));
GRANT SELECT ON securepay_signed_party_claims TO profitpilot_app;
GRANT INSERT(tenant_id,case_id,evidence_id,provenance_receipt_id,client_request_id,recorded_by,
 claimed_party_role,key_spki,claim_nonce,claimed_content_sha256,signature,statement_sha256,key_spki_sha256)
 ON securepay_signed_party_claims TO profitpilot_app;
CREATE TRIGGER securepay_signed_claim_append_only BEFORE UPDATE OR DELETE ON securepay_signed_party_claims
 FOR EACH ROW EXECUTE FUNCTION private.securepay_reject_mutation();
COMMIT;

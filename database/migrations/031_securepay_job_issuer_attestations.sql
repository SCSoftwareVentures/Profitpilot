-- SP-S8: append-only hashes of independently signed short-lived JWT metadata.
-- Not a trusted person/job grant; never accepts production authority or payments.
BEGIN;
CREATE TABLE securepay_job_issuer_attestations (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id uuid NOT NULL,
 case_id uuid NOT NULL,
 evidence_id uuid NOT NULL,
 claim_id uuid NOT NULL,
 client_request_id uuid NOT NULL,
 recorded_by uuid NOT NULL,
 issuer text NOT NULL CHECK(length(issuer) BETWEEN 10 AND 300 AND issuer LIKE 'https://%'),
 token_jti uuid NOT NULL,
 issuer_subject_sha256 text NOT NULL CHECK(issuer_subject_sha256 ~ '^[a-f0-9]{64}$'),
 token_sha256 text NOT NULL CHECK(token_sha256 ~ '^[a-f0-9]{64}$'),
 issued_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 identity_verified boolean NOT NULL DEFAULT false CHECK(identity_verified=false),
 job_authority_verified boolean NOT NULL DEFAULT false CHECK(job_authority_verified=false),
 content_verified boolean NOT NULL DEFAULT false CHECK(content_verified=false),
 decision_authority boolean NOT NULL DEFAULT false CHECK(decision_authority=false),
 payment_authority boolean NOT NULL DEFAULT false CHECK(payment_authority=false),
 recorded_at timestamptz NOT NULL DEFAULT now(),
 CHECK(expires_at>issued_at AND expires_at<=issued_at+interval '10 minutes'),
 UNIQUE(tenant_id,id),
 UNIQUE(tenant_id,case_id,evidence_id,claim_id,recorded_by,client_request_id),
 UNIQUE(tenant_id,issuer,token_jti),
 FOREIGN KEY(tenant_id,case_id,evidence_id,claim_id)
  REFERENCES securepay_signed_party_claims(tenant_id,case_id,evidence_id,id),
 FOREIGN KEY(tenant_id,recorded_by) REFERENCES tenant_memberships(tenant_id,user_id)
);
CREATE INDEX securepay_job_attestation_list ON securepay_job_issuer_attestations(tenant_id,case_id,claim_id,recorded_at DESC,id DESC);
ALTER TABLE securepay_job_issuer_attestations ENABLE ROW LEVEL SECURITY;
ALTER TABLE securepay_job_issuer_attestations FORCE ROW LEVEL SECURITY;
CREATE POLICY securepay_job_attestations_read ON securepay_job_issuer_attestations FOR SELECT TO profitpilot_app
 USING(tenant_id=private.current_tenant_id() AND private.actor_role() IN ('owner','admin','reviewer'));
CREATE POLICY securepay_job_attestations_insert ON securepay_job_issuer_attestations FOR INSERT TO profitpilot_app
 WITH CHECK(tenant_id=private.current_tenant_id() AND recorded_by=private.actor_id()
 AND private.actor_role() IN ('owner','admin','reviewer')
 AND NOT EXISTS(SELECT 1 FROM securepay_signed_claim_revocations r WHERE
 r.tenant_id=securepay_job_issuer_attestations.tenant_id AND r.case_id=securepay_job_issuer_attestations.case_id
 AND r.evidence_id=securepay_job_issuer_attestations.evidence_id AND r.claim_id=securepay_job_issuer_attestations.claim_id));
GRANT SELECT ON securepay_job_issuer_attestations TO profitpilot_app;
GRANT INSERT(tenant_id,case_id,evidence_id,claim_id,client_request_id,recorded_by,issuer,token_jti,issuer_subject_sha256,token_sha256,issued_at,expires_at)
 ON securepay_job_issuer_attestations TO profitpilot_app;
CREATE TRIGGER securepay_issuer_receipt_append_only BEFORE UPDATE OR DELETE ON securepay_job_issuer_attestations
 FOR EACH ROW EXECUTE FUNCTION private.securepay_reject_mutation();
COMMIT;

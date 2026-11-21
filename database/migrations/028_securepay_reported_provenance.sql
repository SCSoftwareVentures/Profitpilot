-- SP-S5: append-only, operator-reported metadata receipts for existing synthetic evidence.
-- A SHA-256 metadata checksum does not authenticate documents, people or job authority.
BEGIN;
ALTER TABLE securepay_evidence_rehearsals ADD CONSTRAINT securepay_evidence_tenant_case_id_unique UNIQUE(tenant_id,case_id,id);
CREATE TABLE securepay_evidence_provenance_receipts (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id uuid NOT NULL,
 case_id uuid NOT NULL,
 evidence_id uuid NOT NULL,
 client_request_id uuid NOT NULL,
 recorded_by uuid NOT NULL,
 reported_origin text NOT NULL CHECK(reported_origin IN ('reported_customer','reported_business','reported_third_party','operator_observed','unknown')),
 acquisition_method text NOT NULL CHECK(acquisition_method IN ('operator_relay','document_reference_only','unknown')),
 source_reference text NOT NULL CHECK(source_reference ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{2,119}$'),
 metadata_sha256 text NOT NULL CHECK(metadata_sha256 ~ '^[a-f0-9]{64}$'),
 origin_verified boolean NOT NULL DEFAULT false CHECK(origin_verified=false),
 job_authority_verified boolean NOT NULL DEFAULT false CHECK(job_authority_verified=false),
 content_verified boolean NOT NULL DEFAULT false CHECK(content_verified=false),
 decision_authority boolean NOT NULL DEFAULT false CHECK(decision_authority=false),
 payment_authority boolean NOT NULL DEFAULT false CHECK(payment_authority=false),
 recorded_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,id),
 UNIQUE(tenant_id,case_id,evidence_id,recorded_by,client_request_id),
 FOREIGN KEY(tenant_id,case_id,evidence_id) REFERENCES securepay_evidence_rehearsals(tenant_id,case_id,id),
 FOREIGN KEY(tenant_id,recorded_by) REFERENCES tenant_memberships(tenant_id,user_id)
);
CREATE INDEX securepay_provenance_list ON securepay_evidence_provenance_receipts(tenant_id,case_id,evidence_id,recorded_at DESC,id DESC);
ALTER TABLE securepay_evidence_provenance_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE securepay_evidence_provenance_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY securepay_provenance_read ON securepay_evidence_provenance_receipts FOR SELECT TO profitpilot_app
 USING(tenant_id=private.current_tenant_id() AND private.actor_role() IN ('owner','admin','reviewer'));
CREATE POLICY securepay_provenance_insert ON securepay_evidence_provenance_receipts FOR INSERT TO profitpilot_app
 WITH CHECK(tenant_id=private.current_tenant_id() AND recorded_by=private.actor_id()
 AND private.actor_role() IN ('owner','admin','reviewer')
 AND EXISTS(SELECT 1 FROM securepay_evidence_rehearsals e
  WHERE e.tenant_id=securepay_evidence_provenance_receipts.tenant_id
   AND e.case_id=securepay_evidence_provenance_receipts.case_id
   AND e.id=securepay_evidence_provenance_receipts.evidence_id
   AND e.externally_verified=false));
GRANT SELECT ON securepay_evidence_provenance_receipts TO profitpilot_app;
GRANT INSERT(tenant_id,case_id,evidence_id,client_request_id,recorded_by,reported_origin,acquisition_method,source_reference,metadata_sha256)
 ON securepay_evidence_provenance_receipts TO profitpilot_app;
CREATE TRIGGER securepay_provenance_append_only BEFORE UPDATE OR DELETE ON securepay_evidence_provenance_receipts
 FOR EACH ROW EXECUTE FUNCTION private.securepay_reject_mutation();
COMMIT;

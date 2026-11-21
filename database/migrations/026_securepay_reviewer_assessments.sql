-- SP-S3: internal reviewer binding; operator-reported synthetic evidence only.
BEGIN;
CREATE TABLE securepay_reviewer_assessments (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id uuid NOT NULL,
 case_id uuid NOT NULL,
 client_request_id uuid NOT NULL,
 reviewer_id uuid NOT NULL,
 review_reference text NOT NULL CHECK(review_reference ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{2,119}$'),
 evidence_count integer NOT NULL CHECK(evidence_count BETWEEN 3 AND 500),
 evidence_snapshot_sha256 text NOT NULL CHECK(evidence_snapshot_sha256 ~ '^[a-f0-9]{64}$'),
 decision_authority boolean NOT NULL DEFAULT false CHECK(decision_authority=false),
 payment_authority boolean NOT NULL DEFAULT false CHECK(payment_authority=false),
 recorded_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,id),
 UNIQUE(tenant_id,case_id,reviewer_id,client_request_id),
 FOREIGN KEY(tenant_id,case_id) REFERENCES securepay_case_rehearsals(tenant_id,id),
 FOREIGN KEY(tenant_id,reviewer_id) REFERENCES tenant_memberships(tenant_id,user_id)
);
CREATE INDEX securepay_reviewer_assessments_list ON securepay_reviewer_assessments(tenant_id,case_id,recorded_at DESC,id DESC);
ALTER TABLE securepay_reviewer_assessments ENABLE ROW LEVEL SECURITY;
ALTER TABLE securepay_reviewer_assessments FORCE ROW LEVEL SECURITY;
CREATE POLICY securepay_assessments_read ON securepay_reviewer_assessments FOR SELECT TO profitpilot_app
 USING(tenant_id=private.current_tenant_id() AND private.actor_role() IN ('owner','admin','reviewer'));
CREATE POLICY securepay_assessments_insert ON securepay_reviewer_assessments FOR INSERT TO profitpilot_app
 WITH CHECK(tenant_id=private.current_tenant_id() AND reviewer_id=private.actor_id()
 AND private.actor_role()='reviewer'
 AND EXISTS(SELECT 1 FROM securepay_case_rehearsals c WHERE c.tenant_id=securepay_reviewer_assessments.tenant_id
  AND c.id=securepay_reviewer_assessments.case_id AND c.opened_by<>private.actor_id()
  AND c.synthetic=true AND c.funds_moved=false)
 AND NOT EXISTS(SELECT 1 FROM securepay_evidence_rehearsals e WHERE e.tenant_id=securepay_reviewer_assessments.tenant_id
  AND e.case_id=securepay_reviewer_assessments.case_id AND e.recorded_by=private.actor_id()));
GRANT SELECT ON securepay_reviewer_assessments TO profitpilot_app;
GRANT INSERT(tenant_id,case_id,client_request_id,reviewer_id,review_reference,evidence_count,evidence_snapshot_sha256) ON securepay_reviewer_assessments TO profitpilot_app;
CREATE TRIGGER securepay_assessment_append_only BEFORE UPDATE OR DELETE ON securepay_reviewer_assessments
 FOR EACH ROW EXECUTE FUNCTION private.securepay_reject_mutation();
COMMIT;

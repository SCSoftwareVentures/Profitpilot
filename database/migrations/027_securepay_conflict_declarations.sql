-- SP-S4: append-only self-reported reviewer conflict declarations. Never payment authority.
-- Existing S3 review rows remain HISTORICAL and can have NULL declaration links.
-- New app-role inserts must carry a same-tenant, same-case, same-reviewer no-conflict
-- declaration. Any previously reported potential conflict blocks later reviews.
BEGIN;
CREATE TABLE securepay_reviewer_declarations (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id uuid NOT NULL,
 case_id uuid NOT NULL,
 client_request_id uuid NOT NULL,
 reviewer_id uuid NOT NULL,
 declaration_status text NOT NULL CHECK(declaration_status IN ('no_conflict_declared','potential_conflict')),
 conflict_code text CHECK(conflict_code IN ('financial_interest','personal_connection','prior_involvement','other')),
 disclosure_reference text CHECK(disclosure_reference ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{2,119}$'),
 independently_screened boolean NOT NULL DEFAULT false CHECK(independently_screened=false),
 identity_verified boolean NOT NULL DEFAULT false CHECK(identity_verified=false),
 decision_authority boolean NOT NULL DEFAULT false CHECK(decision_authority=false),
 payment_authority boolean NOT NULL DEFAULT false CHECK(payment_authority=false),
 recorded_at timestamptz NOT NULL DEFAULT now(),
 CHECK(
  (declaration_status='no_conflict_declared' AND conflict_code IS NULL AND disclosure_reference IS NULL) OR
  (declaration_status='potential_conflict' AND conflict_code IS NOT NULL AND disclosure_reference IS NOT NULL)
 ),
 UNIQUE(tenant_id,id),
 UNIQUE(tenant_id,case_id,reviewer_id,id),
 UNIQUE(tenant_id,case_id,reviewer_id,client_request_id),
 FOREIGN KEY(tenant_id,case_id) REFERENCES securepay_case_rehearsals(tenant_id,id),
 FOREIGN KEY(tenant_id,reviewer_id) REFERENCES tenant_memberships(tenant_id,user_id)
);
CREATE INDEX securepay_conflicts_case_list ON securepay_reviewer_declarations(tenant_id,case_id,recorded_at DESC,id DESC);
ALTER TABLE securepay_reviewer_declarations ENABLE ROW LEVEL SECURITY;
ALTER TABLE securepay_reviewer_declarations FORCE ROW LEVEL SECURITY;
CREATE POLICY securepay_conflicts_read ON securepay_reviewer_declarations FOR SELECT TO profitpilot_app
 USING(tenant_id=private.current_tenant_id() AND private.actor_role() IN ('owner','admin','reviewer'));
CREATE POLICY securepay_conflicts_insert ON securepay_reviewer_declarations FOR INSERT TO profitpilot_app
 WITH CHECK(tenant_id=private.current_tenant_id() AND reviewer_id=private.actor_id()
 AND private.actor_role()='reviewer'
 AND EXISTS(SELECT 1 FROM securepay_case_rehearsals c
  WHERE c.tenant_id=securepay_reviewer_declarations.tenant_id
  AND c.id=securepay_reviewer_declarations.case_id
  AND c.synthetic=true AND c.funds_moved=false AND c.status='evidence_pending'));
GRANT SELECT ON securepay_reviewer_declarations TO profitpilot_app;
GRANT INSERT(tenant_id,case_id,client_request_id,reviewer_id,declaration_status,conflict_code,disclosure_reference) ON securepay_reviewer_declarations TO profitpilot_app;
CREATE TRIGGER securepay_conflicts_append_only BEFORE UPDATE OR DELETE ON securepay_reviewer_declarations
 FOR EACH ROW EXECUTE FUNCTION private.securepay_reject_mutation();

ALTER TABLE securepay_reviewer_assessments ADD COLUMN conflict_declaration_id uuid;
ALTER TABLE securepay_reviewer_assessments ADD CONSTRAINT securepay_assessment_declaration_fk
 FOREIGN KEY(tenant_id,case_id,reviewer_id,conflict_declaration_id)
 REFERENCES securepay_reviewer_declarations(tenant_id,case_id,reviewer_id,id);
GRANT INSERT(conflict_declaration_id) ON securepay_reviewer_assessments TO profitpilot_app;
DROP POLICY securepay_assessments_insert ON securepay_reviewer_assessments;
CREATE POLICY securepay_assessments_insert ON securepay_reviewer_assessments FOR INSERT TO profitpilot_app
 WITH CHECK(tenant_id=private.current_tenant_id() AND reviewer_id=private.actor_id()
 AND private.actor_role()='reviewer'
 AND conflict_declaration_id IS NOT NULL
 AND EXISTS(SELECT 1 FROM securepay_reviewer_declarations d
  WHERE d.tenant_id=securepay_reviewer_assessments.tenant_id
   AND d.case_id=securepay_reviewer_assessments.case_id
   AND d.reviewer_id=private.actor_id()
   AND d.id=securepay_reviewer_assessments.conflict_declaration_id
   AND d.declaration_status='no_conflict_declared')
 AND NOT EXISTS(SELECT 1 FROM securepay_reviewer_declarations d
  WHERE d.tenant_id=securepay_reviewer_assessments.tenant_id
   AND d.case_id=securepay_reviewer_assessments.case_id
   AND d.reviewer_id=private.actor_id()
   AND d.declaration_status='potential_conflict')
 AND EXISTS(SELECT 1 FROM securepay_case_rehearsals c
  WHERE c.tenant_id=securepay_reviewer_assessments.tenant_id AND c.id=securepay_reviewer_assessments.case_id
   AND c.opened_by<>private.actor_id() AND c.synthetic=true AND c.funds_moved=false AND c.status='evidence_pending')
 AND NOT EXISTS(SELECT 1 FROM securepay_evidence_rehearsals e
  WHERE e.tenant_id=securepay_reviewer_assessments.tenant_id AND e.case_id=securepay_reviewer_assessments.case_id
   AND e.recorded_by=private.actor_id()));
COMMIT;

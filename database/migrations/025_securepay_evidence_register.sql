-- SP-S2 synthetic-only operator evidence register. Never a payment ledger.
BEGIN;
CREATE TABLE securepay_case_rehearsals (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id uuid NOT NULL REFERENCES tenants(id),
 client_request_id uuid NOT NULL,
 job_reference text NOT NULL CHECK(job_reference ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{2,119}$'),
 claim_reference text NOT NULL CHECK(claim_reference ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{2,119}$'),
 opened_by uuid NOT NULL,
 status text NOT NULL DEFAULT 'evidence_pending' CHECK(status='evidence_pending'),
 synthetic boolean NOT NULL DEFAULT true CHECK(synthetic=true),
 funds_moved boolean NOT NULL DEFAULT false CHECK(funds_moved=false),
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,id),
 UNIQUE(tenant_id,opened_by,client_request_id),
 FOREIGN KEY(tenant_id,opened_by) REFERENCES tenant_memberships(tenant_id,user_id)
);
CREATE INDEX securepay_case_list ON securepay_case_rehearsals(tenant_id,created_at DESC,id DESC);
CREATE TABLE securepay_evidence_rehearsals (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id uuid NOT NULL,
 case_id uuid NOT NULL,
 client_request_id uuid NOT NULL,
 recorded_by uuid NOT NULL,
 evidence_type text NOT NULL CHECK(evidence_type IN (
 'claim_reported','business_response_reported','operator_review_note','rectification_reported','appeal_reported')),
 evidence_reference text NOT NULL CHECK(evidence_reference ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{2,119}$'),
 externally_verified boolean NOT NULL DEFAULT false CHECK(externally_verified=false),
 recorded_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,case_id,client_request_id),
 FOREIGN KEY(tenant_id,case_id) REFERENCES securepay_case_rehearsals(tenant_id,id),
 FOREIGN KEY(tenant_id,recorded_by) REFERENCES tenant_memberships(tenant_id,user_id)
);
CREATE INDEX securepay_evidence_list ON securepay_evidence_rehearsals(tenant_id,case_id,recorded_at DESC,id DESC);
ALTER TABLE securepay_case_rehearsals ENABLE ROW LEVEL SECURITY;
ALTER TABLE securepay_case_rehearsals FORCE ROW LEVEL SECURITY;
ALTER TABLE securepay_evidence_rehearsals ENABLE ROW LEVEL SECURITY;
ALTER TABLE securepay_evidence_rehearsals FORCE ROW LEVEL SECURITY;
CREATE POLICY securepay_cases_read ON securepay_case_rehearsals FOR SELECT TO profitpilot_app
 USING(tenant_id=private.current_tenant_id() AND private.actor_role() IN ('owner','admin','reviewer'));
CREATE POLICY securepay_cases_insert ON securepay_case_rehearsals FOR INSERT TO profitpilot_app
 WITH CHECK(tenant_id=private.current_tenant_id() AND opened_by=private.actor_id()
 AND private.actor_role() IN ('owner','admin','reviewer'));
CREATE POLICY securepay_evidence_read ON securepay_evidence_rehearsals FOR SELECT TO profitpilot_app
 USING(tenant_id=private.current_tenant_id() AND private.actor_role() IN ('owner','admin','reviewer'));
CREATE POLICY securepay_evidence_insert ON securepay_evidence_rehearsals FOR INSERT TO profitpilot_app
 WITH CHECK(tenant_id=private.current_tenant_id() AND recorded_by=private.actor_id()
 AND private.actor_role() IN ('owner','admin','reviewer')
 AND EXISTS(SELECT 1 FROM securepay_case_rehearsals c WHERE c.tenant_id=securepay_evidence_rehearsals.tenant_id AND c.id=case_id));
GRANT SELECT ON securepay_case_rehearsals,securepay_evidence_rehearsals TO profitpilot_app;
GRANT INSERT(tenant_id,client_request_id,job_reference,claim_reference,opened_by) ON securepay_case_rehearsals TO profitpilot_app;
GRANT INSERT(tenant_id,case_id,client_request_id,recorded_by,evidence_type,evidence_reference) ON securepay_evidence_rehearsals TO profitpilot_app;
-- Append-only even for accidental privileged UPDATE/DELETE; restore uses INSERT.
CREATE FUNCTION private.securepay_reject_mutation() RETURNS trigger LANGUAGE plpgsql
 SECURITY INVOKER SET search_path=pg_catalog,public,private AS $$
BEGIN
 RAISE EXCEPTION 'SecurePay evidence register is append-only' USING ERRCODE='42501';
END $$;
REVOKE ALL ON FUNCTION private.securepay_reject_mutation() FROM PUBLIC;
CREATE TRIGGER securepay_case_immutable BEFORE UPDATE OR DELETE ON securepay_case_rehearsals
 FOR EACH ROW EXECUTE FUNCTION private.securepay_reject_mutation();
CREATE TRIGGER securepay_evidence_immutable BEFORE UPDATE OR DELETE ON securepay_evidence_rehearsals
 FOR EACH ROW EXECUTE FUNCTION private.securepay_reject_mutation();
COMMIT;

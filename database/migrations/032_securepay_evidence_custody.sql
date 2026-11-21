-- SP-S9: original SYNTHETIC evidence bytes. Not authenticated origin or independent custody.
BEGIN;
CREATE TABLE securepay_evidence_custody_receipts (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id uuid NOT NULL,
 case_id uuid NOT NULL,
 evidence_id uuid NOT NULL,
 client_request_id uuid NOT NULL,
 received_by uuid NOT NULL,
 sha256 text NOT NULL CHECK(sha256 ~ '^[a-f0-9]{64}$'),
 byte_count integer NOT NULL CHECK(byte_count BETWEEN 1 AND 524288),
 media_type text NOT NULL CHECK(media_type IN ('text/plain','application/pdf','image/png','image/jpeg')),
 scan_status text NOT NULL DEFAULT 'scanner_reported_clean' CHECK(scan_status='scanner_reported_clean'),
 original_bytes bytea NOT NULL,
 origin_verified boolean NOT NULL DEFAULT false CHECK(origin_verified=false),
 source_identity_verified boolean NOT NULL DEFAULT false CHECK(source_identity_verified=false),
 independent_custody_verified boolean NOT NULL DEFAULT false CHECK(independent_custody_verified=false),
 decision_authority boolean NOT NULL DEFAULT false CHECK(decision_authority=false),
 payment_authority boolean NOT NULL DEFAULT false CHECK(payment_authority=false),
 recorded_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,id),
 UNIQUE(tenant_id,case_id,evidence_id),
 UNIQUE(tenant_id,received_by,client_request_id),
 FOREIGN KEY(tenant_id,case_id,evidence_id) REFERENCES securepay_evidence_rehearsals(tenant_id,case_id,id),
 FOREIGN KEY(tenant_id,received_by) REFERENCES tenant_memberships(tenant_id,user_id),
 CHECK(byte_count=octet_length(original_bytes)),
 CHECK(sha256=encode(public.digest(original_bytes,'sha256'),'hex'))
);
CREATE INDEX securepay_custody_case_idx ON securepay_evidence_custody_receipts(tenant_id,case_id,recorded_at DESC,id DESC);
ALTER TABLE securepay_evidence_custody_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE securepay_evidence_custody_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY securepay_custody_read ON securepay_evidence_custody_receipts FOR SELECT TO profitpilot_app
 USING(tenant_id=private.current_tenant_id() AND private.actor_role() IN ('owner','admin','reviewer'));
CREATE POLICY securepay_custody_insert ON securepay_evidence_custody_receipts FOR INSERT TO profitpilot_app
 WITH CHECK(tenant_id=private.current_tenant_id() AND received_by=private.actor_id()
 AND private.actor_role() IN ('owner','admin','reviewer')
 AND EXISTS(SELECT 1 FROM securepay_evidence_rehearsals e
 JOIN securepay_case_rehearsals k ON k.tenant_id=e.tenant_id AND k.id=e.case_id
 WHERE e.tenant_id=securepay_evidence_custody_receipts.tenant_id
 AND e.case_id=securepay_evidence_custody_receipts.case_id
 AND e.id=securepay_evidence_custody_receipts.evidence_id
 AND e.externally_verified=false AND k.synthetic=true AND k.funds_moved=false));
-- No runtime application SELECT permission on original_bytes.
GRANT SELECT(id,tenant_id,case_id,evidence_id,client_request_id,received_by,
 sha256,byte_count,media_type,scan_status,origin_verified,source_identity_verified,
 independent_custody_verified,decision_authority,payment_authority,recorded_at)
 ON securepay_evidence_custody_receipts TO profitpilot_app;
GRANT INSERT(tenant_id,case_id,evidence_id,client_request_id,received_by,sha256,byte_count,
 media_type,scan_status,original_bytes) ON securepay_evidence_custody_receipts TO profitpilot_app;
CREATE TRIGGER securepay_custody_append_only BEFORE UPDATE OR DELETE ON securepay_evidence_custody_receipts
 FOR EACH ROW EXECUTE FUNCTION private.securepay_reject_mutation();
COMMIT;

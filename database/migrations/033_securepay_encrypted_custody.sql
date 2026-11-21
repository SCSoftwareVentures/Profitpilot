-- SP-S10: new encrypted-only custody storage. S9 plaintext remains legacy/review-only.
BEGIN;
-- Block any further runtime plaintext insertion. Existing records are NOT
-- converted, deleted or falsely described as encrypted.
DROP POLICY securepay_custody_insert ON securepay_evidence_custody_receipts;
REVOKE INSERT(tenant_id,case_id,evidence_id,client_request_id,received_by,sha256,byte_count,media_type,scan_status,original_bytes)
 ON securepay_evidence_custody_receipts FROM profitpilot_app;

CREATE TABLE securepay_encrypted_custody_receipts (
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
 scan_observed_at timestamptz NOT NULL,
 scanner_attestation_mac text NOT NULL CHECK(scanner_attestation_mac ~ '^[a-f0-9]{64}$'),
 encryption_algorithm text NOT NULL DEFAULT 'aes-256-gcm' CHECK(encryption_algorithm='aes-256-gcm'),
 key_id text NOT NULL CHECK(key_id ~ '^[a-zA-Z0-9][a-zA-Z0-9._:-]{2,63}$'),
 aad_sha256 text NOT NULL CHECK(aad_sha256 ~ '^[a-f0-9]{64}$'),
 ciphertext_sha256 text NOT NULL CHECK(ciphertext_sha256 ~ '^[a-f0-9]{64}$'),
 nonce bytea NOT NULL CHECK(octet_length(nonce)=12),
 auth_tag bytea NOT NULL CHECK(octet_length(auth_tag)=16),
 ciphertext bytea NOT NULL,
 origin_verified boolean NOT NULL DEFAULT false CHECK(origin_verified=false),
 source_identity_verified boolean NOT NULL DEFAULT false CHECK(source_identity_verified=false),
 independent_scanner_verified boolean NOT NULL DEFAULT false CHECK(independent_scanner_verified=false),
 independent_custody_verified boolean NOT NULL DEFAULT false CHECK(independent_custody_verified=false),
 retention_policy_enforced boolean NOT NULL DEFAULT false CHECK(retention_policy_enforced=false),
 decision_authority boolean NOT NULL DEFAULT false CHECK(decision_authority=false),
 payment_authority boolean NOT NULL DEFAULT false CHECK(payment_authority=false),
 recorded_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,id),
 UNIQUE(tenant_id,case_id,evidence_id),
 UNIQUE(tenant_id,received_by,client_request_id),
 FOREIGN KEY(tenant_id,case_id,evidence_id) REFERENCES securepay_evidence_rehearsals(tenant_id,case_id,id),
 FOREIGN KEY(tenant_id,received_by) REFERENCES tenant_memberships(tenant_id,user_id),
 CHECK(byte_count=octet_length(ciphertext)),
 CHECK(ciphertext_sha256=encode(public.digest(ciphertext,'sha256'),'hex')),
 CHECK(scan_observed_at<=recorded_at + interval '5 minutes')
);
CREATE INDEX securepay_encrypted_custody_case_lookup ON securepay_encrypted_custody_receipts(tenant_id,case_id,recorded_at DESC,id DESC);
ALTER TABLE securepay_encrypted_custody_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE securepay_encrypted_custody_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY securepay_encrypted_read ON securepay_encrypted_custody_receipts FOR SELECT TO profitpilot_app
 USING(tenant_id=private.current_tenant_id() AND private.actor_role() IN ('owner','admin','reviewer'));
CREATE POLICY securepay_encrypted_insert ON securepay_encrypted_custody_receipts FOR INSERT TO profitpilot_app
 WITH CHECK(tenant_id=private.current_tenant_id() AND received_by=private.actor_id()
 AND private.actor_role() IN ('owner','admin','reviewer')
 AND NOT EXISTS(SELECT 1 FROM securepay_evidence_custody_receipts old WHERE
  old.tenant_id=securepay_encrypted_custody_receipts.tenant_id
  AND old.case_id=securepay_encrypted_custody_receipts.case_id
  AND old.evidence_id=securepay_encrypted_custody_receipts.evidence_id)
 AND EXISTS(SELECT 1 FROM securepay_evidence_rehearsals e
  JOIN securepay_case_rehearsals k ON k.tenant_id=e.tenant_id AND k.id=e.case_id
  WHERE e.tenant_id=securepay_encrypted_custody_receipts.tenant_id
  AND e.case_id=securepay_encrypted_custody_receipts.case_id
  AND e.id=securepay_encrypted_custody_receipts.evidence_id
  AND e.externally_verified=false AND k.synthetic=true AND k.funds_moved=false));
-- The runtime role may inspect only metadata; it cannot recover ciphertext,
-- nonce or authentication tag, even with SELECT *.
GRANT SELECT(id,tenant_id,case_id,evidence_id,client_request_id,received_by,sha256,byte_count,media_type,
 scan_status,scan_observed_at,scanner_attestation_mac,encryption_algorithm,key_id,aad_sha256,
 ciphertext_sha256,origin_verified,source_identity_verified,independent_scanner_verified,
 independent_custody_verified,retention_policy_enforced,decision_authority,payment_authority,recorded_at)
 ON securepay_encrypted_custody_receipts TO profitpilot_app;
GRANT INSERT(tenant_id,case_id,evidence_id,client_request_id,received_by,sha256,byte_count,media_type,
 scan_observed_at,scanner_attestation_mac,encryption_algorithm,key_id,aad_sha256,ciphertext_sha256,
 nonce,auth_tag,ciphertext)
 ON securepay_encrypted_custody_receipts TO profitpilot_app;
CREATE TRIGGER securepay_encrypted_custody_append_only BEFORE UPDATE OR DELETE ON securepay_encrypted_custody_receipts
 FOR EACH ROW EXECUTE FUNCTION private.securepay_reject_mutation();
COMMIT;

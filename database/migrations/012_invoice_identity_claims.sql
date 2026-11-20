-- Reviewed invoice identity reservations. No automatic financial inclusion or issuer authentication.
BEGIN;
CREATE FUNCTION private.invoice_review_alias(ref text) RETURNS text
 LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE SET search_path=pg_catalog
 AS $$ SELECT CASE WHEN btrim(ref) ~ '^[0-9]+$' THEN coalesce(nullif(ltrim(btrim(ref),'0'),''),'0') ELSE lower(btrim(ref) COLLATE "C") END $$;
REVOKE ALL ON FUNCTION private.invoice_review_alias(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.invoice_review_alias(text) TO profitpilot_app;
CREATE INDEX raw_invoice_reference_review_idx ON raw_import_rows(tenant_id,private.invoice_review_alias(payload->>'invoice_id')) WHERE jsonb_typeof(payload->'invoice_id')='string';
CREATE TABLE invoice_identity_claims (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id uuid NOT NULL,
 raw_row_id uuid NOT NULL,
 direction text NOT NULL CHECK(direction IN ('customer','supplier')),
 issuer_key text NOT NULL CHECK(issuer_key ~ '^[a-z0-9][a-z0-9._:-]{0,199}$'),
 invoice_reference text NOT NULL CHECK(length(invoice_reference) BETWEEN 1 AND 200 AND invoice_reference=btrim(invoice_reference)),
 source_integrity text NOT NULL CHECK(source_integrity IN ('client_declared','byte_verified')),
 reviewer_id uuid NOT NULL,
 evidence_reference text NOT NULL CHECK(length(btrim(evidence_reference)) BETWEEN 3 AND 500),
 reason text NOT NULL CHECK(length(btrim(reason)) BETWEEN 3 AND 2000),
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,raw_row_id),
 UNIQUE(tenant_id,direction,issuer_key,invoice_reference),
 FOREIGN KEY(tenant_id,raw_row_id) REFERENCES raw_import_rows(tenant_id,id),
 FOREIGN KEY(tenant_id,reviewer_id) REFERENCES tenant_memberships(tenant_id,user_id)
);
CREATE UNIQUE INDEX invoice_claim_review_alias_once ON invoice_identity_claims(tenant_id,direction,issuer_key,private.invoice_review_alias(invoice_reference));
ALTER TABLE invoice_identity_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoice_identity_claims FORCE ROW LEVEL SECURITY;
CREATE POLICY invoice_claim_tenant ON invoice_identity_claims USING(tenant_id=private.current_tenant_id()) WITH CHECK(tenant_id=private.current_tenant_id());
CREATE POLICY invoice_claim_reviewer ON invoice_identity_claims AS RESTRICTIVE FOR INSERT TO profitpilot_app
 WITH CHECK(reviewer_id=private.payroll_reviewer_id());
GRANT SELECT ON invoice_identity_claims TO profitpilot_app;
GRANT INSERT(tenant_id,raw_row_id,direction,issuer_key,invoice_reference,source_integrity,reviewer_id,evidence_reference,reason) ON invoice_identity_claims TO profitpilot_app;
CREATE FUNCTION private.guard_invoice_identity_claim() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,private AS $$
DECLARE src record;
BEGIN
 SELECT r.batch_id,r.payload,b.source_type,b.status INTO src FROM raw_import_rows r JOIN import_batches b ON b.tenant_id=r.tenant_id AND b.id=r.batch_id
 WHERE r.tenant_id=NEW.tenant_id AND r.id=NEW.raw_row_id;
 IF NOT FOUND OR src.status<>'review' OR src.source_type IS DISTINCT FROM NEW.direction||'_invoice'
 OR jsonb_typeof(src.payload->'invoice_id') IS DISTINCT FROM 'string'
 OR btrim(src.payload->>'invoice_id') IS DISTINCT FROM NEW.invoice_reference
 OR NOT EXISTS(SELECT 1 FROM mapping_decisions m WHERE m.tenant_id=NEW.tenant_id AND m.raw_row_id=NEW.raw_row_id AND m.method_version='invoice-validator-0.1.0' AND m.decision='candidate')
 THEN RAISE EXCEPTION 'Invoice claim requires matching reviewed source evidence' USING ERRCODE='23514'; END IF;
 IF NEW.source_integrity IS DISTINCT FROM (CASE WHEN EXISTS(SELECT 1 FROM import_source_receipts s WHERE s.tenant_id=NEW.tenant_id AND s.batch_id=src.batch_id) THEN 'byte_verified' ELSE 'client_declared' END)
 THEN RAISE EXCEPTION 'Invoice claim source integrity mismatch' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER invoice_identity_claim_guard BEFORE INSERT ON invoice_identity_claims FOR EACH ROW EXECUTE FUNCTION private.guard_invoice_identity_claim();
COMMIT;

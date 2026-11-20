-- Synthetic-only canonical invoice rehearsal. Never writes the financial invoices ledger.
BEGIN;
ALTER TABLE tenants ADD COLUMN invoice_rehearsal_enabled boolean NOT NULL DEFAULT false;
ALTER TABLE invoice_identity_claims ADD CONSTRAINT invoice_claim_tenant_id_unique UNIQUE(tenant_id,id);
CREATE TABLE invoice_confirmation_rehearsals (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id uuid NOT NULL,
 claim_id uuid NOT NULL,
 contract_id uuid NOT NULL,
 site_id uuid NOT NULL,
 contract_version_no integer NOT NULL,
 reviewer_id uuid NOT NULL,
 service_start date NOT NULL,
 service_end date NOT NULL,
 currency text NOT NULL CHECK(currency='AUD'),
 tax_basis text NOT NULL CHECK(tax_basis IN ('gst_inclusive','gst_exclusive','no_gst')),
 cost_kind text NOT NULL CHECK(cost_kind IN ('revenue','supplier','subcontractor')),
 evidence_reference text NOT NULL CHECK(evidence_reference ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{2,119}$'),
 direction text NOT NULL CHECK(direction IN ('customer','supplier')),
 issuer_key text NOT NULL,
 invoice_reference text NOT NULL,
 source_integrity text NOT NULL CHECK(source_integrity IN ('client_declared','byte_verified')),
 raw_row_id uuid NOT NULL,
 source_sha256 text CHECK(source_sha256 ~ '^[a-f0-9]{64}$'),
 invoice_date date NOT NULL,
 amount numeric(14,2) NOT NULL CHECK(amount>0 AND amount<='999999999999.99'::numeric),
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,claim_id),
 UNIQUE(tenant_id,raw_row_id),
 FOREIGN KEY(tenant_id,claim_id) REFERENCES invoice_identity_claims(tenant_id,id),
 FOREIGN KEY(tenant_id,raw_row_id) REFERENCES raw_import_rows(tenant_id,id),
 FOREIGN KEY(tenant_id,contract_id,contract_version_no) REFERENCES contract_versions(tenant_id,contract_id,version_no),
 FOREIGN KEY(tenant_id,site_id) REFERENCES sites(tenant_id,id),
 FOREIGN KEY(tenant_id,reviewer_id) REFERENCES tenant_memberships(tenant_id,user_id),
 CHECK(service_start<=service_end AND invoice_date BETWEEN service_start AND service_end),
 CHECK((direction='customer' AND cost_kind='revenue') OR (direction='supplier' AND cost_kind IN ('supplier','subcontractor')))
);
CREATE INDEX invoice_rehearsal_period ON invoice_confirmation_rehearsals(tenant_id,contract_id,site_id,service_start,service_end);
ALTER TABLE invoice_confirmation_rehearsals ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoice_confirmation_rehearsals FORCE ROW LEVEL SECURITY;
CREATE POLICY invoice_rehearsal_read ON invoice_confirmation_rehearsals FOR SELECT TO profitpilot_app
 USING(tenant_id=private.current_tenant_id());
CREATE POLICY invoice_rehearsal_insert ON invoice_confirmation_rehearsals FOR INSERT TO profitpilot_app
 WITH CHECK(tenant_id=private.current_tenant_id() AND reviewer_id=private.payroll_reviewer_id()
 AND EXISTS(SELECT 1 FROM tenants t WHERE t.id=tenant_id AND t.invoice_rehearsal_enabled));
GRANT SELECT ON invoice_confirmation_rehearsals TO profitpilot_app;
GRANT INSERT(tenant_id,claim_id,contract_id,site_id,reviewer_id,service_start,service_end,currency,tax_basis,cost_kind,evidence_reference) ON invoice_confirmation_rehearsals TO profitpilot_app;
CREATE FUNCTION private.guard_invoice_rehearsal() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,private AS $$
DECLARE src record; n integer; v integer;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM tenants WHERE id=NEW.tenant_id AND invoice_rehearsal_enabled AND status='active')
 THEN RAISE EXCEPTION 'Synthetic rehearsal not provisioned' USING ERRCODE='23514'; END IF;
 IF NOT EXISTS(SELECT 1 FROM tenant_memberships m JOIN users u ON u.id=m.user_id WHERE m.tenant_id=NEW.tenant_id AND m.user_id=NEW.reviewer_id AND m.status='active' AND m.role IN ('owner','admin','reviewer') AND u.status='active')
 THEN RAISE EXCEPTION 'Active reviewer required' USING ERRCODE='42501'; END IF;
 SELECT ic.*,r.payload,b.status AS batch_status,b.source_type,receipt.sha256 AS receipt_hash INTO src
 FROM invoice_identity_claims ic JOIN raw_import_rows r ON r.tenant_id=ic.tenant_id AND r.id=ic.raw_row_id
 JOIN import_batches b ON b.tenant_id=r.tenant_id AND b.id=r.batch_id
 LEFT JOIN import_source_receipts receipt ON receipt.tenant_id=b.tenant_id AND receipt.batch_id=b.id
 WHERE ic.tenant_id=NEW.tenant_id AND ic.id=NEW.claim_id;
 IF NOT FOUND OR src.batch_status<>'review' OR src.source_type IS DISTINCT FROM src.direction||'_invoice'
 OR src.invoice_reference IS DISTINCT FROM btrim(src.payload->>'invoice_id')
 OR src.source_integrity IS DISTINCT FROM (CASE WHEN src.receipt_hash IS NULL THEN 'client_declared' ELSE 'byte_verified' END)
 OR NOT EXISTS(SELECT 1 FROM mapping_decisions m WHERE m.tenant_id=NEW.tenant_id AND m.raw_row_id=src.raw_row_id AND m.method_version='invoice-validator-0.1.0' AND m.decision='candidate')
 OR jsonb_typeof(src.payload->'amount') IS DISTINCT FROM 'string'
 OR (src.payload->>'amount') !~ '^[0-9]{1,12}(\.[0-9]{1,2})?$'
 OR jsonb_typeof(src.payload->'date') IS DISTINCT FROM 'string'
 OR (src.payload->>'date') !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'
 THEN RAISE EXCEPTION 'Unsupported source or identity evidence' USING ERRCODE='23514'; END IF;
 -- No amounts, issuer, date or provenance supplied by the caller are authoritative.
 NEW.direction:=src.direction; NEW.issuer_key:=src.issuer_key; NEW.invoice_reference:=src.invoice_reference;
 NEW.source_integrity:=src.source_integrity; NEW.raw_row_id:=src.raw_row_id; NEW.source_sha256:=src.receipt_hash;
 NEW.invoice_date:=(src.payload->>'date')::date; NEW.amount:=(src.payload->>'amount')::numeric;
 IF NEW.amount<=0 OR NEW.invoice_date NOT BETWEEN NEW.service_start AND NEW.service_end
 THEN RAISE EXCEPTION 'Positive invoice and aligned service period required' USING ERRCODE='23514'; END IF;
 SELECT count(*),min(cv.version_no) INTO n,v FROM contract_versions cv
 JOIN contracts c ON c.tenant_id=cv.tenant_id AND c.id=cv.contract_id
 JOIN sites s ON s.tenant_id=c.tenant_id AND s.business_id=c.business_id AND s.id=NEW.site_id
 WHERE cv.tenant_id=NEW.tenant_id AND cv.contract_id=NEW.contract_id AND c.status='active' AND s.status='active'
 AND cv.approved_by IS NOT NULL AND cv.approved_at IS NOT NULL
 AND cv.effective_from<=NEW.service_end AND (cv.effective_to IS NULL OR cv.effective_to>=NEW.service_start);
 IF n<>1 OR NOT EXISTS(SELECT 1 FROM contract_versions cv WHERE cv.tenant_id=NEW.tenant_id AND cv.contract_id=NEW.contract_id AND cv.version_no=v
 AND cv.currency=NEW.currency AND cv.effective_from<=NEW.service_start AND (cv.effective_to IS NULL OR cv.effective_to>=NEW.service_end))
 THEN RAISE EXCEPTION 'Unique approved contract version and matching site/currency required' USING ERRCODE='23514'; END IF;
 NEW.contract_version_no:=v;
 RETURN NEW;
END $$;
CREATE TRIGGER invoice_rehearsal_guard BEFORE INSERT ON invoice_confirmation_rehearsals FOR EACH ROW EXECUTE FUNCTION private.guard_invoice_rehearsal();
CREATE FUNCTION private.audit_invoice_rehearsal() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public,private AS $$
BEGIN
 IF current_user='profitpilot_app' THEN
 INSERT INTO audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata)
 VALUES(NEW.tenant_id,NEW.reviewer_id,'invoice_confirmation_rehearsed','invoice_confirmation_rehearsal',NEW.id,'Synthetic invoice confirmation only',
 jsonb_build_object('claimId',NEW.claim_id,'costKind',NEW.cost_kind,'financialInclusionAuthorized',false));
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER invoice_rehearsal_audit AFTER INSERT ON invoice_confirmation_rehearsals FOR EACH ROW EXECUTE FUNCTION private.audit_invoice_rehearsal();
COMMIT;

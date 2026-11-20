-- Explicit whole-line, contract-specific payroll attribution for isolated synthetic rehearsals.
BEGIN;
ALTER TABLE allocation_lines ADD CONSTRAINT allocation_line_tenant_id_unique UNIQUE(tenant_id,id);
CREATE TABLE payroll_contract_rehearsals (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id uuid NOT NULL,
 allocation_line_id uuid NOT NULL,
 contract_id uuid NOT NULL,
 contract_version_no integer NOT NULL,
 site_id uuid NOT NULL,
 reviewer_id uuid NOT NULL,
 evidence_reference text NOT NULL CHECK(evidence_reference ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{2,119}$'),
 allocation_run_id uuid NOT NULL,
 payroll_pool_id uuid NOT NULL,
 source_record_id uuid NOT NULL,
 raw_row_id uuid NOT NULL,
 batch_id uuid NOT NULL,
 source_sha256 text CHECK(source_sha256 ~ '^[a-f0-9]{64}$'),
 service_start date NOT NULL,
 service_end date NOT NULL,
 currency text NOT NULL CHECK(currency='AUD'),
 bucket_type text NOT NULL CHECK(bucket_type IN ('direct','approved_allocated')),
 amount numeric(14,2) NOT NULL CHECK(amount>0),
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,allocation_line_id),
 FOREIGN KEY(tenant_id,allocation_line_id) REFERENCES allocation_lines(tenant_id,id),
 FOREIGN KEY(tenant_id,allocation_run_id) REFERENCES allocation_runs(tenant_id,id),
 FOREIGN KEY(tenant_id,payroll_pool_id) REFERENCES payroll_pools(tenant_id,id),
 FOREIGN KEY(tenant_id,source_record_id) REFERENCES payroll_source_records(tenant_id,id),
 FOREIGN KEY(tenant_id,raw_row_id) REFERENCES raw_import_rows(tenant_id,id),
 FOREIGN KEY(tenant_id,batch_id) REFERENCES import_batches(tenant_id,id),
 FOREIGN KEY(tenant_id,contract_id,contract_version_no) REFERENCES contract_versions(tenant_id,contract_id,version_no),
 FOREIGN KEY(tenant_id,site_id) REFERENCES sites(tenant_id,id),
 FOREIGN KEY(tenant_id,reviewer_id) REFERENCES tenant_memberships(tenant_id,user_id),
 CHECK(service_start<=service_end)
);
CREATE INDEX payroll_rehearsal_scope_idx ON payroll_contract_rehearsals(tenant_id,contract_id,site_id,service_start,service_end);
ALTER TABLE payroll_contract_rehearsals ENABLE ROW LEVEL SECURITY;
ALTER TABLE payroll_contract_rehearsals FORCE ROW LEVEL SECURITY;
CREATE POLICY payroll_rehearsal_read ON payroll_contract_rehearsals FOR SELECT TO profitpilot_app
 USING(tenant_id=private.current_tenant_id());
CREATE POLICY payroll_rehearsal_write ON payroll_contract_rehearsals FOR INSERT TO profitpilot_app
 WITH CHECK(tenant_id=private.current_tenant_id() AND reviewer_id=private.payroll_reviewer_id()
 AND EXISTS(SELECT 1 FROM tenants t WHERE t.id=tenant_id AND t.invoice_rehearsal_enabled));
GRANT SELECT ON payroll_contract_rehearsals TO profitpilot_app;
GRANT INSERT(tenant_id,allocation_line_id,contract_id,reviewer_id,evidence_reference)
 ON payroll_contract_rehearsals TO profitpilot_app;
CREATE FUNCTION private.guard_payroll_contract_rehearsal() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,private AS $$
DECLARE src record; n integer; v integer;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM tenants WHERE id=NEW.tenant_id AND status='active' AND invoice_rehearsal_enabled)
 THEN RAISE EXCEPTION 'Synthetic rehearsal not provisioned' USING ERRCODE='23514'; END IF;
 IF NOT EXISTS(SELECT 1 FROM tenant_memberships m JOIN users u ON u.id=m.user_id WHERE m.tenant_id=NEW.tenant_id AND m.user_id=NEW.reviewer_id AND m.status='active' AND m.role IN ('owner','admin','reviewer') AND u.status='active')
 THEN RAISE EXCEPTION 'Active reviewer required' USING ERRCODE='42501'; END IF;
 SELECT al.site_id,al.amount,al.bucket_type,al.allocation_run_id,al.source_record_id,ar.payroll_pool_id,
 pp.batch_id,pp.period_start,pp.period_end,pp.currency,ps.raw_row_id,receipt.sha256 AS receipt_hash
 INTO src FROM allocation_lines al
 JOIN allocation_runs ar ON ar.tenant_id=al.tenant_id AND ar.id=al.allocation_run_id
 JOIN payroll_pools pp ON pp.tenant_id=ar.tenant_id AND pp.id=ar.payroll_pool_id
 JOIN payroll_source_records ps ON ps.tenant_id=al.tenant_id AND ps.id=al.source_record_id AND ps.payroll_pool_id=pp.id
 JOIN raw_import_rows rr ON rr.tenant_id=ps.tenant_id AND rr.id=ps.raw_row_id AND rr.batch_id=pp.batch_id
 JOIN import_batches b ON b.tenant_id=pp.tenant_id AND b.id=pp.batch_id
 LEFT JOIN import_source_receipts receipt ON receipt.tenant_id=b.tenant_id AND receipt.batch_id=b.id
 WHERE al.tenant_id=NEW.tenant_id AND al.id=NEW.allocation_line_id
 AND ar.status='confirmed' AND ar.method_version='payroll-source-row-0.2.0' AND ar.reviewer_id IS NOT NULL
 AND b.source_type='payroll' AND b.status='accepted' AND al.bucket_type IN ('direct','approved_allocated')
 AND al.amount>0 AND pp.currency='AUD' AND al.site_id IS NOT NULL;
 IF NOT FOUND THEN RAISE EXCEPTION 'Confirmed source-linked site allocation required' USING ERRCODE='23514'; END IF;
 SELECT count(*),min(cv.version_no) INTO n,v FROM contract_versions cv
 JOIN contracts c ON c.tenant_id=cv.tenant_id AND c.id=cv.contract_id
 JOIN sites s ON s.tenant_id=c.tenant_id AND s.business_id=c.business_id AND s.id=src.site_id
 WHERE cv.tenant_id=NEW.tenant_id AND cv.contract_id=NEW.contract_id AND c.status='active' AND s.status='active'
 AND cv.approved_by IS NOT NULL AND cv.approved_at IS NOT NULL
 AND cv.effective_from<=src.period_end AND (cv.effective_to IS NULL OR cv.effective_to>=src.period_start);
 IF n<>1 OR NOT EXISTS(SELECT 1 FROM contract_versions cv WHERE cv.tenant_id=NEW.tenant_id AND cv.contract_id=NEW.contract_id AND cv.version_no=v
 AND cv.currency=src.currency AND cv.effective_from<=src.period_start AND (cv.effective_to IS NULL OR cv.effective_to>=src.period_end))
 THEN RAISE EXCEPTION 'Unique approved covering contract version and matching site required' USING ERRCODE='23514'; END IF;
 NEW.contract_version_no:=v; NEW.site_id:=src.site_id; NEW.amount:=src.amount;
 NEW.allocation_run_id:=src.allocation_run_id; NEW.payroll_pool_id:=src.payroll_pool_id; NEW.source_record_id:=src.source_record_id;
 NEW.raw_row_id:=src.raw_row_id; NEW.batch_id:=src.batch_id; NEW.source_sha256:=src.receipt_hash;
 NEW.service_start:=src.period_start; NEW.service_end:=src.period_end; NEW.currency:=src.currency; NEW.bucket_type:=src.bucket_type;
 RETURN NEW;
END $$;
CREATE TRIGGER payroll_rehearsal_guard BEFORE INSERT ON payroll_contract_rehearsals
 FOR EACH ROW EXECUTE FUNCTION private.guard_payroll_contract_rehearsal();
CREATE FUNCTION private.audit_payroll_contract_rehearsal() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,private AS $$
BEGIN
 IF current_user='profitpilot_app' THEN
  INSERT INTO audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata)
  VALUES(NEW.tenant_id,NEW.reviewer_id,'payroll_contract_rehearsed','payroll_contract_rehearsal',NEW.id,'Synthetic whole-line contract attribution',
  jsonb_build_object('allocationLineId',NEW.allocation_line_id,'contractId',NEW.contract_id,'financialInclusionAuthorized',false));
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER payroll_rehearsal_audit AFTER INSERT ON payroll_contract_rehearsals
 FOR EACH ROW EXECUTE FUNCTION private.audit_payroll_contract_rehearsal();
COMMIT;

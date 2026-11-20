-- F5: persisted synthetic contribution snapshots, never a live financial ledger.
BEGIN;
CREATE TABLE unified_report_snapshots(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id uuid NOT NULL,
 client_request_id uuid NOT NULL,
 contract_id uuid NOT NULL,
 site_id uuid NOT NULL,
 period_start date NOT NULL,
 period_end date NOT NULL,
 created_by uuid NOT NULL,
 contribution jsonb NOT NULL CHECK(jsonb_typeof(contribution)='object' AND contribution->>'completeness'='incomplete'),
 evidence jsonb NOT NULL CHECK(jsonb_typeof(evidence)='object' AND evidence->>'method'='unified-rehearsal-0.1.0'),
 evidence_sha256 text NOT NULL CHECK(evidence_sha256 ~ '^[a-f0-9]{64}$'),
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,client_request_id),
 UNIQUE(tenant_id,contract_id,site_id,period_start,period_end,evidence_sha256),
 FOREIGN KEY(tenant_id,contract_id) REFERENCES contracts(tenant_id,id),
 FOREIGN KEY(tenant_id,site_id) REFERENCES sites(tenant_id,id),
 FOREIGN KEY(tenant_id,created_by) REFERENCES tenant_memberships(tenant_id,user_id),
 CHECK(period_start<=period_end)
);
CREATE INDEX unified_reports_scope_idx ON unified_report_snapshots(tenant_id,contract_id,site_id,period_start,period_end,created_at DESC);
ALTER TABLE unified_report_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE unified_report_snapshots FORCE ROW LEVEL SECURITY;
CREATE POLICY unified_report_read ON unified_report_snapshots FOR SELECT TO profitpilot_app USING(
 tenant_id=private.current_tenant_id() AND private.actor_role() IN ('owner','admin','analyst','reviewer'));
CREATE POLICY unified_report_write ON unified_report_snapshots FOR INSERT TO profitpilot_app WITH CHECK(
 tenant_id=private.current_tenant_id() AND created_by=private.actor_id()
 AND private.actor_role() IN ('owner','admin','reviewer')
 AND EXISTS(SELECT 1 FROM tenants t WHERE t.id=tenant_id AND t.status='active' AND t.invoice_rehearsal_enabled));
GRANT SELECT ON unified_report_snapshots TO profitpilot_app;
GRANT INSERT(tenant_id,client_request_id,contract_id,site_id,period_start,period_end,created_by,contribution,evidence,evidence_sha256)
 ON unified_report_snapshots TO profitpilot_app;
CREATE FUNCTION private.guard_unified_report() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,private AS $$
DECLARE inv_count integer; pay_count integer; valid_inv integer; valid_pay integer;
 revenue numeric(18,2); supplier numeric(18,2); subcontractor numeric(18,2);
 direct_labour numeric(18,2); allocated_labour numeric(18,2); cost numeric(18,2); contribution numeric(18,2);
BEGIN
 IF NOT EXISTS(SELECT 1 FROM tenants t WHERE t.id=NEW.tenant_id AND t.status='active' AND t.invoice_rehearsal_enabled)
 OR NOT EXISTS(SELECT 1 FROM tenant_memberships m JOIN users u ON u.id=m.user_id
 WHERE m.tenant_id=NEW.tenant_id AND m.user_id=NEW.created_by AND m.status='active'
 AND m.role IN ('owner','admin','reviewer') AND u.status='active')
 THEN RAISE EXCEPTION 'Synthetic reporting access denied' USING ERRCODE='23514'; END IF;
 IF NEW.evidence->>'tenantId' IS DISTINCT FROM NEW.tenant_id::text
 OR NEW.evidence->>'contractId' IS DISTINCT FROM NEW.contract_id::text
 OR NEW.evidence->>'siteId' IS DISTINCT FROM NEW.site_id::text
 OR NEW.evidence->>'periodStart' IS DISTINCT FROM NEW.period_start::text
 OR NEW.evidence->>'periodEnd' IS DISTINCT FROM NEW.period_end::text
 OR jsonb_typeof(NEW.evidence->'invoiceLines')<>'array'
 OR jsonb_typeof(NEW.evidence->'payrollLines')<>'array'
 OR jsonb_typeof(NEW.evidence->'excludedLegacyPayroll')<>'array'
 OR NEW.contribution->>'currency'<>'AUD'
 OR octet_length(NEW.evidence::text)>4194304
 THEN RAISE EXCEPTION 'Invalid report evidence scope or size' USING ERRCODE='23514'; END IF;
 SELECT jsonb_array_length(NEW.evidence->'invoiceLines'),jsonb_array_length(NEW.evidence->'payrollLines')
 INTO inv_count,pay_count;
 IF inv_count<1 OR pay_count<1 OR inv_count>2000 OR pay_count>2000
 THEN RAISE EXCEPTION 'Evidence count outside safe bounds' USING ERRCODE='23514'; END IF;
 SELECT COUNT(DISTINCT i.id),COALESCE(SUM(i.amount) FILTER (WHERE i.cost_kind='revenue'),0),
 COALESCE(SUM(i.amount) FILTER (WHERE i.cost_kind='supplier'),0),
 COALESCE(SUM(i.amount) FILTER (WHERE i.cost_kind='subcontractor'),0)
 INTO valid_inv,revenue,supplier,subcontractor
 FROM jsonb_to_recordset(NEW.evidence->'invoiceLines') j(id uuid,amount text,cost_kind text,contract_version_no integer)
 JOIN invoice_confirmation_rehearsals i ON i.tenant_id=NEW.tenant_id AND i.id=j.id
 AND i.amount::text=j.amount AND i.cost_kind=j.cost_kind AND i.contract_version_no=j.contract_version_no
 AND i.contract_id=NEW.contract_id AND i.site_id=NEW.site_id
 AND i.service_start>=NEW.period_start AND i.service_end<=NEW.period_end;
 SELECT COUNT(DISTINCT p.id),COALESCE(SUM(p.amount) FILTER (WHERE p.bucket_type='direct'),0),
 COALESCE(SUM(p.amount) FILTER (WHERE p.bucket_type='approved_allocated'),0)
 INTO valid_pay,direct_labour,allocated_labour
 FROM jsonb_to_recordset(NEW.evidence->'payrollLines') j(id uuid,amount text,bucket_type text,contract_version_no integer)
 JOIN payroll_contract_rehearsals p ON p.tenant_id=NEW.tenant_id AND p.id=j.id
 AND p.amount::text=j.amount AND p.bucket_type=j.bucket_type AND p.contract_version_no=j.contract_version_no
 AND p.contract_id=NEW.contract_id AND p.site_id=NEW.site_id
 AND p.service_start>=NEW.period_start AND p.service_end<=NEW.period_end;
 IF valid_inv<>inv_count OR valid_pay<>pay_count OR revenue<=0
 THEN RAISE EXCEPTION 'Report references duplicate, invalid, missing or cross-tenant source evidence' USING ERRCODE='23514'; END IF;
 cost:=supplier+subcontractor+direct_labour+allocated_labour;
 contribution:=revenue-cost;
 IF NEW.contribution->>'revenue' IS DISTINCT FROM to_char(revenue,'FM9999999999999990.00')
 OR NEW.contribution->>'supplierCost' IS DISTINCT FROM to_char(supplier,'FM9999999999999990.00')
 OR NEW.contribution->>'subcontractorCost' IS DISTINCT FROM to_char(subcontractor,'FM9999999999999990.00')
 OR NEW.contribution->>'directLabour' IS DISTINCT FROM to_char(direct_labour,'FM9999999999999990.00')
 OR NEW.contribution->>'allocatedLabour' IS DISTINCT FROM to_char(allocated_labour,'FM9999999999999990.00')
 OR NEW.contribution->>'labourCost' IS DISTINCT FROM to_char(direct_labour+allocated_labour,'FM9999999999999990.00')
 OR NEW.contribution->>'deliveryCost' IS DISTINCT FROM to_char(cost,'FM9999999999999990.00')
 OR NEW.contribution->>'contribution' IS DISTINCT FROM to_char(contribution,'FM9999999999999990.00')
 OR NEW.contribution->>'marginPercent' IS DISTINCT FROM to_char(round(contribution*100/revenue,2),'FM9999999999999990.00')
 THEN RAISE EXCEPTION 'Persisted totals disagree with confirmed source evidence' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER unified_report_guard BEFORE INSERT ON unified_report_snapshots FOR EACH ROW EXECUTE FUNCTION private.guard_unified_report();
CREATE OR REPLACE FUNCTION private.guard_runtime_audit() RETURNS trigger
 LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public,private AS $$
BEGIN
 IF current_user <> 'profitpilot_app' THEN RETURN NEW; END IF;
 IF NEW.actor_user_id IS DISTINCT FROM private.actor_id() THEN
  RAISE EXCEPTION 'Audit actor does not match verified tenant identity' USING ERRCODE='42501';
 END IF;
 IF NEW.object_id IS NULL OR jsonb_typeof(NEW.metadata) <> 'object'
 OR octet_length(NEW.metadata::text) > 262144
 OR (NEW.reason IS NOT NULL AND (length(NEW.reason)>2000 OR NEW.reason ~ '[[:cntrl:]]'))
 OR NOT (
  (NEW.action='source_file_verified' AND NEW.object_type='import_batch'
    AND EXISTS(SELECT 1 FROM import_source_receipts r WHERE r.tenant_id=NEW.tenant_id AND r.batch_id=NEW.object_id))
  OR (NEW.action='invoice_identity_reserved' AND NEW.object_type='invoice_identity_claim'
    AND EXISTS(SELECT 1 FROM invoice_identity_claims r WHERE r.tenant_id=NEW.tenant_id AND r.id=NEW.object_id))
  OR (NEW.action='payroll_reconciled' AND NEW.object_type='allocation_run'
    AND EXISTS(SELECT 1 FROM allocation_runs r WHERE r.tenant_id=NEW.tenant_id AND r.id=NEW.object_id AND r.status='confirmed'))
  OR (NEW.action='invoice_match_decision' AND NEW.object_type='match_review'
    AND EXISTS(SELECT 1 FROM match_reviews r WHERE r.tenant_id=NEW.tenant_id AND r.id=NEW.object_id AND r.decision IN ('confirmed','held','rejected')))
  OR (NEW.action='calculation_created' AND NEW.object_type='calculation_run'
    AND EXISTS(SELECT 1 FROM calculation_runs r WHERE r.tenant_id=NEW.tenant_id AND r.id=NEW.object_id))
  OR (NEW.action='privacy_request_review' AND NEW.object_type='privacy_request'
    AND EXISTS(SELECT 1 FROM privacy_requests r WHERE r.tenant_id=NEW.tenant_id AND r.id=NEW.object_id))
  OR (NEW.action='invoice_confirmation_rehearsed' AND NEW.object_type='invoice_confirmation_rehearsal'
    AND EXISTS(SELECT 1 FROM invoice_confirmation_rehearsals r WHERE r.tenant_id=NEW.tenant_id AND r.id=NEW.object_id))
  OR (NEW.action='payroll_contract_rehearsed' AND NEW.object_type='payroll_contract_rehearsal'
    AND EXISTS(SELECT 1 FROM payroll_contract_rehearsals r WHERE r.tenant_id=NEW.tenant_id AND r.id=NEW.object_id))
  OR (NEW.action='unified_report_saved' AND NEW.object_type='unified_report_snapshot'
    AND EXISTS(SELECT 1 FROM unified_report_snapshots s WHERE s.tenant_id=NEW.tenant_id AND s.id=NEW.object_id))
  OR (NEW.action='calculation_restated' AND NEW.object_type='calculation_restatement'
    AND EXISTS(SELECT 1 FROM calculation_restatements r WHERE r.tenant_id=NEW.tenant_id AND r.id=NEW.object_id))
 )
 THEN RAISE EXCEPTION 'Invalid audited event or source evidence' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;


CREATE FUNCTION private.audit_unified_report() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,private AS $$
BEGIN
 IF current_user='profitpilot_app' THEN
  INSERT INTO audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata)
  VALUES(NEW.tenant_id,NEW.created_by,'unified_report_saved','unified_report_snapshot',NEW.id,
   'Incomplete synthetic source-linked financial contribution report',
   jsonb_build_object('contractId',NEW.contract_id,'siteId',NEW.site_id,
    'evidenceSha256',NEW.evidence_sha256,'financialInclusionAuthorized',false));
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER unified_report_audit AFTER INSERT ON unified_report_snapshots
 FOR EACH ROW EXECUTE FUNCTION private.audit_unified_report();
COMMIT;

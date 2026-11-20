-- F4: synthetic-only independent approval and immutable restatement lineage.
BEGIN;
ALTER TABLE calculation_runs ADD CONSTRAINT calculation_runs_tenant_id_id_unique UNIQUE(tenant_id,id);
CREATE TABLE calculation_restatements (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id uuid NOT NULL,
 prior_run_id uuid NOT NULL,
 next_run_id uuid NOT NULL,
 reviewed_by uuid NOT NULL,
 reason_code text NOT NULL CHECK(reason_code ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{2,119}$'),
 evidence_reference text NOT NULL CHECK(evidence_reference ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{2,119}$'),
 prior_evidence_sha256 text NOT NULL CHECK(prior_evidence_sha256 ~ '^[a-f0-9]{64}$'),
 next_evidence_sha256 text NOT NULL CHECK(next_evidence_sha256 ~ '^[a-f0-9]{64}$'),
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,prior_run_id),
 UNIQUE(tenant_id,next_run_id),
 FOREIGN KEY(tenant_id,prior_run_id) REFERENCES calculation_runs(tenant_id,id),
 FOREIGN KEY(tenant_id,next_run_id) REFERENCES calculation_runs(tenant_id,id),
 FOREIGN KEY(tenant_id,reviewed_by) REFERENCES tenant_memberships(tenant_id,user_id),
 CHECK(prior_run_id<>next_run_id AND prior_evidence_sha256<>next_evidence_sha256)
);
CREATE INDEX calculation_rest_scope ON calculation_restatements(tenant_id,created_at DESC,id DESC);
ALTER TABLE calculation_restatements ENABLE ROW LEVEL SECURITY;
ALTER TABLE calculation_restatements FORCE ROW LEVEL SECURITY;
CREATE POLICY calculation_rest_read ON calculation_restatements FOR SELECT TO profitpilot_app
 USING(tenant_id=private.current_tenant_id() AND private.actor_role() IN ('owner','admin','analyst','reviewer'));
CREATE POLICY calculation_rest_insert ON calculation_restatements FOR INSERT TO profitpilot_app
 WITH CHECK(tenant_id=private.current_tenant_id() AND reviewed_by=private.actor_id()
 AND private.actor_role() IN ('owner','admin','reviewer')
 AND EXISTS(SELECT 1 FROM tenants t WHERE t.id=tenant_id AND t.invoice_rehearsal_enabled AND t.status='active'));
GRANT SELECT ON calculation_restatements TO profitpilot_app;
GRANT INSERT(tenant_id,prior_run_id,next_run_id,reviewed_by,reason_code,evidence_reference)
 ON calculation_restatements TO profitpilot_app;
CREATE FUNCTION private.guard_calculation_restatement() RETURNS trigger
 LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public,private AS $$
DECLARE p calculation_runs%ROWTYPE; n calculation_runs%ROWTYPE;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM tenants t WHERE t.id=NEW.tenant_id AND t.invoice_rehearsal_enabled AND t.status='active')
 THEN RAISE EXCEPTION 'Synthetic restatement tenant not provisioned' USING ERRCODE='23514'; END IF;
 IF NOT EXISTS(SELECT 1 FROM tenant_memberships m JOIN users u ON u.id=m.user_id
   WHERE m.tenant_id=NEW.tenant_id AND m.user_id=NEW.reviewed_by AND m.status='active'
   AND m.role IN ('owner','admin','reviewer') AND u.status='active')
 THEN RAISE EXCEPTION 'Active independent reviewer required' USING ERRCODE='42501'; END IF;
 SELECT * INTO p FROM calculation_runs WHERE tenant_id=NEW.tenant_id AND id=NEW.prior_run_id;
 SELECT * INTO n FROM calculation_runs WHERE tenant_id=NEW.tenant_id AND id=NEW.next_run_id;
 IF p.id IS NULL OR n.id IS NULL OR p.contract_id<>n.contract_id OR p.site_id<>n.site_id
 OR p.period_start<>n.period_start OR p.period_end<>n.period_end
 OR p.completeness<>'incomplete' OR n.completeness<>'incomplete'
 OR p.formula_version<>'0.2.0' OR n.formula_version<>'0.2.0'
 OR n.created_at<p.created_at
 OR NEW.reviewed_by IN (p.created_by,n.created_by)
 THEN RAISE EXCEPTION 'Restatement requires same scope, supported formula and independent reviewer' USING ERRCODE='23514'; END IF;
 IF p.outputs->>'evidenceSha256' IS NULL OR n.outputs->>'evidenceSha256' IS NULL
 OR p.inputs->>'evidenceSha256' IS DISTINCT FROM p.outputs->>'evidenceSha256'
 OR n.inputs->>'evidenceSha256' IS DISTINCT FROM n.outputs->>'evidenceSha256'
 OR p.outputs->>'evidenceSha256' = n.outputs->>'evidenceSha256'
 OR (p.outputs->>'evidenceSha256') !~ '^[a-f0-9]{64}$'
 OR (n.outputs->>'evidenceSha256') !~ '^[a-f0-9]{64}$'
 THEN RAISE EXCEPTION 'Distinct source-backed calculation evidence required' USING ERRCODE='23514'; END IF;
 NEW.prior_evidence_sha256:=p.outputs->>'evidenceSha256';
 NEW.next_evidence_sha256:=n.outputs->>'evidenceSha256';
 RETURN NEW;
END $$;
CREATE TRIGGER calculation_rest_guard BEFORE INSERT ON calculation_restatements
 FOR EACH ROW EXECUTE FUNCTION private.guard_calculation_restatement();
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
  OR (NEW.action='calculation_restated' AND NEW.object_type='calculation_restatement'
    AND EXISTS(SELECT 1 FROM calculation_restatements r WHERE r.tenant_id=NEW.tenant_id AND r.id=NEW.object_id))
 )
 THEN RAISE EXCEPTION 'Invalid audited event or source evidence' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;

CREATE FUNCTION private.audit_calculation_restatement() RETURNS trigger
 LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public,private AS $$
BEGIN
 IF current_user='profitpilot_app' THEN
  INSERT INTO audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata)
  VALUES(NEW.tenant_id,NEW.reviewed_by,'calculation_restated','calculation_restatement',NEW.id,
   'Independently reviewed synthetic calculation restatement',
   jsonb_build_object('priorRunId',NEW.prior_run_id,'nextRunId',NEW.next_run_id,
    'reasonCode',NEW.reason_code,'evidenceReference',NEW.evidence_reference,
    'priorDigest',NEW.prior_evidence_sha256,'nextDigest',NEW.next_evidence_sha256,
    'financialInclusionAuthorized',false));
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER calculation_rest_audit AFTER INSERT ON calculation_restatements
 FOR EACH ROW EXECUTE FUNCTION private.audit_calculation_restatement();
COMMIT;

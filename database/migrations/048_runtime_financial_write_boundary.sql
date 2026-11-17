-- Least privilege: no direct runtime deletes or unimplemented provisioning writes.
BEGIN;
REVOKE INSERT,UPDATE,DELETE,TRUNCATE ON public.businesses,public.sites,public.contracts,public.contract_versions,public.variations FROM PUBLIC,profitpilot_app;
REVOKE DELETE,TRUNCATE ON public.mapping_decisions,public.allocation_runs,public.invoices,public.invoice_lines,public.match_reviews,public.calculation_runs FROM PUBLIC,profitpilot_app;
REVOKE UPDATE ON public.invoices,public.invoice_lines,public.calculation_runs FROM PUBLIC,profitpilot_app;
REVOKE UPDATE ON public.mapping_decisions,public.allocation_runs,public.match_reviews FROM PUBLIC,profitpilot_app;
GRANT UPDATE(decision,reason,reviewer_id,reviewed_at) ON public.mapping_decisions TO profitpilot_app;
GRANT UPDATE(status,reviewer_id,approved_at,approval_reason) ON public.allocation_runs TO profitpilot_app;
GRANT UPDATE(decision,reviewer_id,reviewed_at,evidence) ON public.match_reviews TO profitpilot_app;
-- PostgreSQL requires an UPDATE column privilege for row locks. Permit locks
-- without permitting any actual row modification on these immutable records.
GRANT UPDATE(id) ON public.sites,public.contracts,public.invoices,public.invoice_lines TO profitpilot_app;
CREATE POLICY runtime_update_authority ON public.sites AS RESTRICTIVE FOR UPDATE TO profitpilot_app
 USING (tenant_id=private.current_tenant_id() AND (true))
 WITH CHECK (tenant_id=private.current_tenant_id() AND (false));
CREATE POLICY runtime_update_authority ON public.contracts AS RESTRICTIVE FOR UPDATE TO profitpilot_app
 USING (tenant_id=private.current_tenant_id() AND (true))
 WITH CHECK (tenant_id=private.current_tenant_id() AND (false));
CREATE POLICY runtime_update_authority ON public.invoices AS RESTRICTIVE FOR UPDATE TO profitpilot_app
 USING (tenant_id=private.current_tenant_id() AND (true))
 WITH CHECK (tenant_id=private.current_tenant_id() AND (false));
CREATE POLICY runtime_update_authority ON public.invoice_lines AS RESTRICTIVE FOR UPDATE TO profitpilot_app
 USING (tenant_id=private.current_tenant_id() AND (true))
 WITH CHECK (tenant_id=private.current_tenant_id() AND (false));

-- Restrictive policies add authority gates to existing forced tenant isolation.
CREATE POLICY runtime_insert_authority ON public.import_batches AS RESTRICTIVE FOR INSERT TO profitpilot_app
 WITH CHECK (tenant_id=private.current_tenant_id() AND (private.has_scoped_permission(tenant_id,'imports.create') IS TRUE AND created_by=private.current_user_id() AND status='uploaded'));
CREATE POLICY runtime_update_authority ON public.import_batches AS RESTRICTIVE FOR UPDATE TO profitpilot_app
 USING (tenant_id=private.current_tenant_id() AND ((private.has_scoped_permission(tenant_id,'imports.rows.write') IS TRUE OR private.has_scoped_permission(tenant_id,'imports.validate') IS TRUE OR private.has_scoped_permission(tenant_id,'payroll.rows.decide') IS TRUE OR private.has_scoped_permission(tenant_id,'payroll.pools.reconcile') IS TRUE OR private.has_scoped_permission(tenant_id,'payroll.allocations.draft') IS TRUE OR private.has_scoped_permission(tenant_id,'matching.decide') IS TRUE)))
 WITH CHECK (tenant_id=private.current_tenant_id() AND ((status='review' AND (private.has_scoped_permission(tenant_id,'imports.rows.write') IS TRUE OR private.has_scoped_permission(tenant_id,'imports.validate') IS TRUE)) OR (status='accepted' AND (private.has_scoped_permission(tenant_id,'payroll.pools.reconcile') IS TRUE OR private.has_scoped_permission(tenant_id,'matching.decide') IS TRUE))));
CREATE POLICY runtime_insert_authority ON public.raw_import_rows AS RESTRICTIVE FOR INSERT TO profitpilot_app
 WITH CHECK (tenant_id=private.current_tenant_id() AND (private.has_scoped_permission(tenant_id,'imports.rows.write') IS TRUE AND EXISTS(SELECT 1 FROM public.import_batches b WHERE b.tenant_id=raw_import_rows.tenant_id AND b.id=raw_import_rows.batch_id AND b.created_by=private.current_user_id() AND b.status IN ('uploaded','review'))));
CREATE POLICY runtime_insert_authority ON public.mapping_decisions AS RESTRICTIVE FOR INSERT TO profitpilot_app
 WITH CHECK (tenant_id=private.current_tenant_id() AND ((decision IN ('candidate','held') AND private.has_scoped_permission(tenant_id,'imports.validate') IS TRUE) OR (decision='accepted' AND reviewer_id=private.current_user_id() AND private.has_scoped_permission(tenant_id,'matching.decide') IS TRUE)));
CREATE POLICY runtime_update_authority ON public.mapping_decisions AS RESTRICTIVE FOR UPDATE TO profitpilot_app
 USING (tenant_id=private.current_tenant_id() AND (decision IN ('candidate','held') AND (private.has_scoped_permission(tenant_id,'imports.validate') IS TRUE OR private.has_scoped_permission(tenant_id,'payroll.rows.decide') IS TRUE)))
 WITH CHECK (tenant_id=private.current_tenant_id() AND ((decision IN ('candidate','held') AND private.has_scoped_permission(tenant_id,'imports.validate') IS TRUE) OR (decision IN ('accepted','rejected','held') AND reviewer_id=private.current_user_id() AND private.has_scoped_permission(tenant_id,'payroll.rows.decide') IS TRUE)));
CREATE POLICY runtime_insert_authority ON public.invoices AS RESTRICTIVE FOR INSERT TO profitpilot_app
 WITH CHECK (tenant_id=private.current_tenant_id() AND (private.has_scoped_permission(tenant_id,'matching.decide') IS TRUE));
CREATE POLICY runtime_insert_authority ON public.invoice_lines AS RESTRICTIVE FOR INSERT TO profitpilot_app
 WITH CHECK (tenant_id=private.current_tenant_id() AND (private.has_scoped_permission(tenant_id,'matching.decide') IS TRUE));
CREATE POLICY runtime_insert_authority ON public.match_reviews AS RESTRICTIVE FOR INSERT TO profitpilot_app
 WITH CHECK (tenant_id=private.current_tenant_id() AND (private.has_scoped_permission(tenant_id,'matching.decide') IS TRUE AND decision='candidate'));
CREATE POLICY runtime_update_authority ON public.match_reviews AS RESTRICTIVE FOR UPDATE TO profitpilot_app
 USING (tenant_id=private.current_tenant_id() AND (private.has_scoped_permission(tenant_id,'matching.decide') IS TRUE AND decision IN ('candidate','held')))
 WITH CHECK (tenant_id=private.current_tenant_id() AND (private.has_scoped_permission(tenant_id,'matching.decide') IS TRUE));
CREATE POLICY runtime_insert_authority ON public.payroll_pools AS RESTRICTIVE FOR INSERT TO profitpilot_app
 WITH CHECK (tenant_id=private.current_tenant_id() AND (private.has_scoped_permission(tenant_id,'payroll.pools.reconcile') IS TRUE));
CREATE POLICY runtime_insert_authority ON public.allocation_runs AS RESTRICTIVE FOR INSERT TO profitpilot_app
 WITH CHECK (tenant_id=private.current_tenant_id() AND (private.has_scoped_permission(tenant_id,'payroll.allocations.draft') IS TRUE AND created_by=private.current_user_id() AND status='review' AND reviewer_id IS NULL));
CREATE POLICY runtime_update_authority ON public.allocation_runs AS RESTRICTIVE FOR UPDATE TO profitpilot_app
 USING (tenant_id=private.current_tenant_id() AND ((private.has_scoped_permission(tenant_id,'payroll.allocations.draft') IS TRUE OR private.has_scoped_permission(tenant_id,'payroll.allocations.confirm') IS TRUE)))
 WITH CHECK (tenant_id=private.current_tenant_id() AND (private.has_scoped_permission(tenant_id,'payroll.allocations.confirm') IS TRUE AND status='confirmed' AND reviewer_id=private.current_user_id() AND created_by<>reviewer_id AND approved_at IS NOT NULL));
CREATE POLICY runtime_insert_authority ON public.allocation_lines AS RESTRICTIVE FOR INSERT TO profitpilot_app
 WITH CHECK (tenant_id=private.current_tenant_id() AND (private.has_scoped_permission(tenant_id,'payroll.allocations.draft') IS TRUE AND EXISTS(SELECT 1 FROM public.allocation_runs r WHERE r.tenant_id=allocation_lines.tenant_id AND r.id=allocation_lines.allocation_run_id AND r.created_by=private.current_user_id() AND r.status='review')));
CREATE POLICY runtime_insert_authority ON public.calculation_runs AS RESTRICTIVE FOR INSERT TO profitpilot_app
 WITH CHECK (tenant_id=private.current_tenant_id() AND (private.has_scoped_permission(tenant_id,'calculations.create') IS TRUE AND created_by=private.current_user_id()));
CREATE POLICY runtime_insert_authority ON public.privacy_requests AS RESTRICTIVE FOR INSERT TO profitpilot_app
 WITH CHECK (tenant_id=private.current_tenant_id() AND (private.has_scoped_permission(tenant_id,'privacy.requests.submit') IS TRUE));
COMMIT;

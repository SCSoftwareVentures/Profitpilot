-- Narrow same-tenant reads to the actual financial capability. No direct access to
-- unused source references, unused contract-version narratives or unimplemented variations.
BEGIN;
CREATE POLICY runtime_select_authority ON public.tenant_memberships AS RESTRICTIVE FOR SELECT TO profitpilot_app
 USING (tenant_id=private.current_tenant_id() AND user_id=private.current_user_id());
REVOKE SELECT ON public.contract_versions,public.payroll_pools,public.allocation_lines,public.allocation_runs,public.variations FROM PUBLIC,profitpilot_app;
GRANT SELECT(id,tenant_id,contract_id,version_no,effective_from,effective_to,currency,approved_by,approved_at) ON public.contract_versions TO profitpilot_app;
GRANT SELECT(id,tenant_id,batch_id,period_start,period_end,total_amount,currency) ON public.payroll_pools TO profitpilot_app;
GRANT SELECT(id,tenant_id,allocation_run_id,site_id,bucket_type,amount,created_at) ON public.allocation_lines TO profitpilot_app;
GRANT SELECT(id,tenant_id,payroll_pool_id,method_version,status,direct_amount,allocated_amount,non_site_amount,excluded_amount,residual_amount,reviewer_id,created_at,created_by,approved_at) ON public.allocation_runs TO profitpilot_app;

CREATE POLICY runtime_select_authority ON public.businesses AS RESTRICTIVE FOR SELECT TO profitpilot_app
 USING (tenant_id=private.current_tenant_id() AND (private.has_scoped_permission(tenant_id,'contracts.read') IS TRUE OR private.has_scoped_permission(tenant_id,'matching.decide') IS TRUE OR private.has_scoped_permission(tenant_id,'calculations.create') IS TRUE OR private.has_scoped_permission(tenant_id,'payroll.allocations.draft') IS TRUE));
CREATE POLICY runtime_select_authority ON public.sites AS RESTRICTIVE FOR SELECT TO profitpilot_app
 USING (tenant_id=private.current_tenant_id() AND (private.has_scoped_permission(tenant_id,'contracts.read') IS TRUE OR private.has_scoped_permission(tenant_id,'matching.decide') IS TRUE OR private.has_scoped_permission(tenant_id,'calculations.create') IS TRUE OR private.has_scoped_permission(tenant_id,'payroll.allocations.draft') IS TRUE));
CREATE POLICY runtime_select_authority ON public.contracts AS RESTRICTIVE FOR SELECT TO profitpilot_app
 USING (tenant_id=private.current_tenant_id() AND (private.has_scoped_permission(tenant_id,'contracts.read') IS TRUE OR private.has_scoped_permission(tenant_id,'matching.decide') IS TRUE OR private.has_scoped_permission(tenant_id,'calculations.create') IS TRUE));
CREATE POLICY runtime_select_authority ON public.contract_versions AS RESTRICTIVE FOR SELECT TO profitpilot_app
 USING (tenant_id=private.current_tenant_id() AND (private.has_scoped_permission(tenant_id,'calculations.create') IS TRUE));
CREATE POLICY runtime_select_authority ON public.import_batches AS RESTRICTIVE FOR SELECT TO profitpilot_app
 USING (tenant_id=private.current_tenant_id() AND (private.has_scoped_permission(tenant_id,'imports.create') IS TRUE OR private.has_scoped_permission(tenant_id,'imports.rows.write') IS TRUE OR private.has_scoped_permission(tenant_id,'imports.validate') IS TRUE OR private.has_scoped_permission(tenant_id,'payroll.rows.decide') IS TRUE OR private.has_scoped_permission(tenant_id,'payroll.pools.reconcile') IS TRUE OR private.has_scoped_permission(tenant_id,'payroll.allocations.draft') IS TRUE OR private.has_scoped_permission(tenant_id,'matching.decide') IS TRUE));
CREATE POLICY runtime_select_authority ON public.raw_import_rows AS RESTRICTIVE FOR SELECT TO profitpilot_app
 USING (tenant_id=private.current_tenant_id() AND (private.has_scoped_permission(tenant_id,'imports.rows.write') IS TRUE OR private.has_scoped_permission(tenant_id,'imports.validate') IS TRUE OR private.has_scoped_permission(tenant_id,'payroll.rows.decide') IS TRUE OR private.has_scoped_permission(tenant_id,'payroll.pools.reconcile') IS TRUE OR private.has_scoped_permission(tenant_id,'matching.decide') IS TRUE));
CREATE POLICY runtime_select_authority ON public.mapping_decisions AS RESTRICTIVE FOR SELECT TO profitpilot_app
 USING (tenant_id=private.current_tenant_id() AND (private.has_scoped_permission(tenant_id,'imports.rows.write') IS TRUE OR private.has_scoped_permission(tenant_id,'imports.validate') IS TRUE OR private.has_scoped_permission(tenant_id,'payroll.rows.decide') IS TRUE OR private.has_scoped_permission(tenant_id,'payroll.pools.reconcile') IS TRUE OR private.has_scoped_permission(tenant_id,'matching.decide') IS TRUE));
CREATE POLICY runtime_select_authority ON public.payroll_pools AS RESTRICTIVE FOR SELECT TO profitpilot_app
 USING (tenant_id=private.current_tenant_id() AND (private.has_scoped_permission(tenant_id,'payroll.pools.reconcile') IS TRUE OR private.has_scoped_permission(tenant_id,'payroll.allocations.draft') IS TRUE OR private.has_scoped_permission(tenant_id,'payroll.allocations.confirm') IS TRUE OR private.has_scoped_permission(tenant_id,'payroll.allocations.read') IS TRUE OR private.has_scoped_permission(tenant_id,'calculations.create') IS TRUE OR private.has_scoped_permission(tenant_id,'matching.decide') IS TRUE));
CREATE POLICY runtime_select_authority ON public.allocation_runs AS RESTRICTIVE FOR SELECT TO profitpilot_app
 USING (tenant_id=private.current_tenant_id() AND (private.has_scoped_permission(tenant_id,'payroll.pools.reconcile') IS TRUE OR private.has_scoped_permission(tenant_id,'payroll.allocations.draft') IS TRUE OR private.has_scoped_permission(tenant_id,'payroll.allocations.confirm') IS TRUE OR private.has_scoped_permission(tenant_id,'payroll.allocations.read') IS TRUE OR private.has_scoped_permission(tenant_id,'calculations.create') IS TRUE OR private.has_scoped_permission(tenant_id,'matching.decide') IS TRUE));
CREATE POLICY runtime_select_authority ON public.allocation_lines AS RESTRICTIVE FOR SELECT TO profitpilot_app
 USING (tenant_id=private.current_tenant_id() AND (private.has_scoped_permission(tenant_id,'payroll.pools.reconcile') IS TRUE OR private.has_scoped_permission(tenant_id,'payroll.allocations.draft') IS TRUE OR private.has_scoped_permission(tenant_id,'payroll.allocations.confirm') IS TRUE OR private.has_scoped_permission(tenant_id,'payroll.allocations.read') IS TRUE OR private.has_scoped_permission(tenant_id,'calculations.create') IS TRUE OR private.has_scoped_permission(tenant_id,'matching.decide') IS TRUE));
CREATE POLICY runtime_select_authority ON public.invoices AS RESTRICTIVE FOR SELECT TO profitpilot_app
 USING (tenant_id=private.current_tenant_id() AND (private.has_scoped_permission(tenant_id,'matching.decide') IS TRUE OR private.has_scoped_permission(tenant_id,'calculations.create') IS TRUE));
CREATE POLICY runtime_select_authority ON public.invoice_lines AS RESTRICTIVE FOR SELECT TO profitpilot_app
 USING (tenant_id=private.current_tenant_id() AND (private.has_scoped_permission(tenant_id,'matching.decide') IS TRUE OR private.has_scoped_permission(tenant_id,'calculations.create') IS TRUE));
CREATE POLICY runtime_select_authority ON public.match_reviews AS RESTRICTIVE FOR SELECT TO profitpilot_app
 USING (tenant_id=private.current_tenant_id() AND (private.has_scoped_permission(tenant_id,'matching.decide') IS TRUE OR private.has_scoped_permission(tenant_id,'calculations.create') IS TRUE));
CREATE POLICY runtime_select_authority ON public.calculation_runs AS RESTRICTIVE FOR SELECT TO profitpilot_app
 USING (tenant_id=private.current_tenant_id() AND (private.has_scoped_permission(tenant_id,'calculations.read') IS TRUE OR private.has_scoped_permission(tenant_id,'calculations.create') IS TRUE));
COMMIT;

-- ProfitPilot migration 005: prevent duplicate confirmed matches and allocation runs.
BEGIN;
CREATE UNIQUE INDEX one_confirmed_match_per_invoice_line ON match_reviews(tenant_id,invoice_line_id) WHERE decision='confirmed';
CREATE UNIQUE INDEX one_confirmed_allocation_run_per_payroll_pool ON allocation_runs(tenant_id,payroll_pool_id) WHERE status='confirmed';
COMMIT;

-- ProfitPilot migration 008: least-privilege runtime writes.
-- Provisioning, membership administration and reference evidence remain migration/admin-only.
BEGIN;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
 ON ALL TABLES IN SCHEMA public FROM profitpilot_app;
-- Remove the legacy automatic grants on future tables created by this migration owner.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
 REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM profitpilot_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
 REVOKE USAGE, SELECT ON SEQUENCES FROM profitpilot_app;

-- Existing tenant-scoped SELECT grants remain subject to forced RLS.
-- Only columns required by current HTTP handlers can be modified.
GRANT INSERT ON import_batches, raw_import_rows, mapping_decisions, calculation_runs, audit_events TO profitpilot_app;
GRANT UPDATE (status) ON import_batches TO profitpilot_app;
GRANT UPDATE (decision,reason) ON mapping_decisions TO profitpilot_app;
GRANT UPDATE (decision,reviewer_id,reviewed_at) ON match_reviews TO profitpilot_app;
-- No runtime UPDATE/DELETE of raw imports, calculations or audit events.
-- This is runtime-role append-only, not protection against privileged DB administrators.
COMMIT;

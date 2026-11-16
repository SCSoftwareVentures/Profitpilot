-- ProfitPilot migration 008: least-privilege runtime table grants.
-- The runtime API must never be able to grant or modify tenant membership/identity.
BEGIN;
REVOKE INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public FROM profitpilot_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE INSERT,UPDATE,DELETE ON TABLES FROM profitpilot_app;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO profitpilot_app;

-- Explicit writes used by implemented API routes only.
GRANT INSERT,UPDATE ON import_batches TO profitpilot_app;
GRANT INSERT ON raw_import_rows TO profitpilot_app;
GRANT INSERT,UPDATE ON mapping_decisions TO profitpilot_app;
GRANT UPDATE ON match_reviews TO profitpilot_app;
GRANT INSERT ON calculation_runs TO profitpilot_app;
GRANT INSERT ON audit_events TO profitpilot_app;

-- No delete route exists. Tenant provisioning, membership/role changes and
-- identity lifecycle remain privileged administrative operations.
REVOKE INSERT,UPDATE,DELETE ON tenants,users,tenant_memberships FROM profitpilot_app;
COMMIT;

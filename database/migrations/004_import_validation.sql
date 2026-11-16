-- ProfitPilot migration 004: idempotent import validation results.
BEGIN;
ALTER TABLE mapping_decisions
 ADD CONSTRAINT mapping_decisions_row_method_unique UNIQUE(tenant_id,raw_row_id,method_version);
GRANT SELECT,INSERT,UPDATE,DELETE ON mapping_decisions TO profitpilot_app;
COMMIT;

-- Remove implicit PUBLIC execution from internal helper/trigger functions.
-- Explicit approved runtime and worker grants survive. This migration does
-- not change extension function privileges or grant new capabilities.
BEGIN;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA private FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC,profitpilot_app,profitpilot_scanner,profitpilot_identity_operator,profitpilot_audit_reader;
REVOKE CREATE ON SCHEMA private FROM PUBLIC,profitpilot_app,profitpilot_scanner,profitpilot_identity_operator,profitpilot_audit_reader;
-- PostgreSQL grants EXECUTE to PUBLIC by default. The global default must
-- be changed; a per-schema REVOKE cannot override the global default.
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
COMMIT;

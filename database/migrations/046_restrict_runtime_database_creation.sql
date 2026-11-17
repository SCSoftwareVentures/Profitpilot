-- Disallow runtime object creation and PostgreSQL temporary-schema shadowing.
BEGIN;
DO $fn$
BEGIN
 EXECUTE format('REVOKE CREATE, TEMPORARY ON DATABASE %I FROM PUBLIC, profitpilot_app',current_database());
END
$fn$;
REVOKE CREATE ON SCHEMA public FROM PUBLIC,profitpilot_app;
REVOKE CREATE ON SCHEMA private FROM PUBLIC,profitpilot_app;
COMMIT;

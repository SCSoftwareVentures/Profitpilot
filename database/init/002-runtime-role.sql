-- Bootstrap a non-superuser runtime role from an environment-provided random hex password.
-- The password is supplied to psql as POSTGRES_APP_PASSWORD; never store it in source control.
\getenv app_password POSTGRES_APP_PASSWORD
SELECT CASE WHEN :'app_password' ~ '^[0-9a-fA-F]{64,}$' AND length(:'app_password') % 2 = 0 THEN 1 ELSE 0 END AS valid_password \gset
\if :valid_password
SELECT format('CREATE ROLE profitpilot_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='profitpilot_app') \gexec
ALTER ROLE profitpilot_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD :'app_password';
GRANT CONNECT ON DATABASE profitpilot TO profitpilot_app;
GRANT USAGE ON SCHEMA public TO profitpilot_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO profitpilot_app;
GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO profitpilot_app;
-- New tables and sequences require explicit grants in their migrations.
\else
\echo 'POSTGRES_APP_PASSWORD must be at least 32 bytes of hexadecimal data'
\quit 3
\endif

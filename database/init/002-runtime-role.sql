-- Local development only: restricted runtime role.
-- Change this password before any shared environment. Never reuse it in production.
CREATE ROLE profitpilot_app LOGIN PASSWORD 'local-dev-only-change-this'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION;
GRANT CONNECT ON DATABASE profitpilot TO profitpilot_app;
GRANT USAGE ON SCHEMA public TO profitpilot_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO profitpilot_app;
GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO profitpilot_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT,INSERT,UPDATE,DELETE ON TABLES TO profitpilot_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT USAGE,SELECT ON SEQUENCES TO profitpilot_app;

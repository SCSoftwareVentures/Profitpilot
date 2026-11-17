-- Migration 025: fail-closed runtime privileges for identity and authorization records.
-- The initial bootstrap granted DML to future public tables by default. Revoke
-- that standing grant: every future application table must be reviewed and granted
-- explicitly. This does not affect explicitly approved privileges on existing tables.
BEGIN;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  REVOKE SELECT,INSERT,UPDATE,DELETE ON TABLES FROM profitpilot_app;

-- These records are managed by controlled operator/SECURITY DEFINER workflows,
-- never by direct writes from the runtime database role.
REVOKE INSERT,UPDATE,DELETE,TRUNCATE ON
  public.tenants,
  public.tenant_memberships,
  public.permission_catalog,
  public.role_permissions,
  public.tenant_membership_permission_overrides
FROM profitpilot_app;

-- The requester may submit via column-limited INSERT; reviewers modify requests
-- only through audited functions. A broad DELETE grant was unnecessary.
REVOKE DELETE,TRUNCATE ON public.privacy_requests FROM profitpilot_app;

-- Access checks legitimately read the catalogue and tenant-scoped overrides.
GRANT SELECT ON public.permission_catalog,
  public.role_permissions,
  public.tenant_membership_permission_overrides TO profitpilot_app;
COMMIT;

-- ProfitPilot migration 007: restrict global identity rows to the signed subject.
-- Users are global identities, not tenant-owned rows; the runtime may read only itself.
BEGIN;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
CREATE POLICY users_signed_subject_only ON users
 USING (
  auth_subject = nullif(current_setting('app.tenant_subject',true),'')
  AND private.current_tenant_id() IS NOT NULL
 )
 WITH CHECK (false);
REVOKE INSERT,UPDATE,DELETE ON users FROM profitpilot_app;
GRANT SELECT ON users TO profitpilot_app;
COMMIT;

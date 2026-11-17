-- ProfitPilot migration 008: permission catalogue, role grants and member overrides.
-- Apply with the migration administrator, never the runtime application role.
BEGIN;

CREATE TABLE permission_catalog (
  permission_key text PRIMARY KEY,
  description text NOT NULL,
  sensitive boolean NOT NULL DEFAULT false
);

CREATE TABLE role_permissions (
  role text NOT NULL CHECK (role IN ('owner','admin','analyst','reviewer','read_only')),
  permission_key text NOT NULL REFERENCES permission_catalog(permission_key) ON DELETE RESTRICT,
  PRIMARY KEY (role, permission_key)
);

CREATE TABLE tenant_membership_permission_overrides (
  tenant_id uuid NOT NULL,
  user_id uuid NOT NULL,
  permission_key text NOT NULL REFERENCES permission_catalog(permission_key) ON DELETE RESTRICT,
  effect text NOT NULL CHECK (effect IN ('grant','deny')),
  reason text NOT NULL CHECK (length(btrim(reason)) BETWEEN 3 AND 1000),
  granted_by uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,user_id,permission_key),
  FOREIGN KEY (tenant_id,user_id) REFERENCES tenant_memberships(tenant_id,user_id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id,granted_by) REFERENCES tenant_memberships(tenant_id,user_id) ON DELETE RESTRICT
);

INSERT INTO permission_catalog(permission_key,description,sensitive) VALUES
 ('contracts.read','Read tenant contract records',false),
 ('imports.create','Create source import batches',true),
 ('imports.rows.write','Ingest source import rows',true),
 ('imports.validate','Validate imported source rows',true),
 ('matching.decide','Confirm, reject or hold financial matching decisions',true),
 ('calculations.create','Create management calculations',true),
 ('calculations.read','Read management calculations',false),
 ('security.permissions.manage','Manage tenant member permission overrides',true),
 ('security.sessions.manage','Revoke tenant member sessions',true),
 ('privacy.requests.manage','Process tenant privacy requests',true);

INSERT INTO role_permissions(role,permission_key)
SELECT r.role,p.permission_key
FROM (VALUES
 ('owner','contracts.read'),('admin','contracts.read'),('analyst','contracts.read'),('reviewer','contracts.read'),('read_only','contracts.read'),
 ('owner','imports.create'),('admin','imports.create'),('analyst','imports.create'),
 ('owner','imports.rows.write'),('admin','imports.rows.write'),('analyst','imports.rows.write'),
 ('owner','imports.validate'),('admin','imports.validate'),('analyst','imports.validate'),('reviewer','imports.validate'),
 ('owner','matching.decide'),('admin','matching.decide'),('reviewer','matching.decide'),
 ('owner','calculations.create'),('admin','calculations.create'),('analyst','calculations.create'),('reviewer','calculations.create'),
 ('owner','calculations.read'),('admin','calculations.read'),('analyst','calculations.read'),('reviewer','calculations.read'),('read_only','calculations.read'),
 ('owner','security.permissions.manage'),('owner','security.sessions.manage'),('owner','privacy.requests.manage'),
 ('admin','security.sessions.manage'),('admin','privacy.requests.manage')
) AS r(role,permission_key)
JOIN permission_catalog p ON p.permission_key=r.permission_key;

CREATE INDEX tenant_permission_overrides_user_idx
 ON tenant_membership_permission_overrides(tenant_id,user_id,permission_key);

ALTER TABLE tenant_membership_permission_overrides ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_membership_permission_overrides FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant_membership_permission_overrides
 USING (tenant_id=private.current_tenant_id())
 WITH CHECK (tenant_id=private.current_tenant_id());

GRANT SELECT ON permission_catalog,role_permissions,tenant_membership_permission_overrides TO profitpilot_app;
COMMIT;

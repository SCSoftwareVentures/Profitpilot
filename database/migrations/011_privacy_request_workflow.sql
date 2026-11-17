-- ProfitPilot migration 011: tenant-scoped privacy request workflow.
BEGIN;
CREATE TABLE public.privacy_requests (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id uuid NOT NULL,
 subject_user_id uuid NOT NULL,
 submitted_by uuid NOT NULL,
 request_type text NOT NULL CHECK (request_type IN ('access','correction','export','deletion','restriction')),
 details text NOT NULL CHECK (length(btrim(details)) BETWEEN 3 AND 2000),
 status text NOT NULL DEFAULT 'requested' CHECK (status IN ('requested','identity_verification','under_review','legal_hold','fulfilled','rejected','withdrawn')),
 assigned_to uuid,
 resolution_summary text,
 legal_hold_reason text,
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 resolved_at timestamptz,
 FOREIGN KEY (tenant_id,subject_user_id) REFERENCES tenant_memberships(tenant_id,user_id) ON DELETE RESTRICT,
 FOREIGN KEY (tenant_id,submitted_by) REFERENCES tenant_memberships(tenant_id,user_id) ON DELETE RESTRICT,
 FOREIGN KEY (tenant_id,assigned_to) REFERENCES tenant_memberships(tenant_id,user_id) ON DELETE RESTRICT,
 CHECK ((status='legal_hold' AND length(btrim(coalesce(legal_hold_reason,'')))>=3) OR status<>'legal_hold'),
 CHECK ((status IN ('fulfilled','rejected') AND resolved_at IS NOT NULL) OR status NOT IN ('fulfilled','rejected'))
);
ALTER TABLE public.privacy_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.privacy_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON public.privacy_requests USING (tenant_id=private.current_tenant_id()) WITH CHECK (tenant_id=private.current_tenant_id());
CREATE INDEX privacy_requests_tenant_status_idx ON public.privacy_requests(tenant_id,status,created_at DESC);
CREATE INDEX privacy_requests_subject_idx ON public.privacy_requests(tenant_id,subject_user_id,created_at DESC);
GRANT SELECT,INSERT,UPDATE ON public.privacy_requests TO profitpilot_app;
INSERT INTO permission_catalog(permission_key,description,sensitive) VALUES
 ('privacy.requests.submit','Submit privacy requests for the authenticated tenant member',true),
 ('privacy.requests.read','Read privacy requests submitted by the authenticated tenant member',true)
ON CONFLICT(permission_key) DO NOTHING;
INSERT INTO role_permissions(role,permission_key)
SELECT roles.role,permissions.permission_key
FROM (VALUES ('owner'),('admin'),('analyst'),('reviewer'),('read_only')) AS roles(role)
CROSS JOIN (VALUES ('privacy.requests.submit'),('privacy.requests.read')) AS permissions(permission_key)
ON CONFLICT DO NOTHING;
COMMIT;

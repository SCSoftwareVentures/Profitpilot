-- Draft only; not wired into production migrations.
-- This table holds opaque short-lived proofs, never customer PINs.
CREATE TABLE IF NOT EXISTS securepay_release_proofs (
 proof_ref text PRIMARY KEY,
 tenant_id uuid NOT NULL,
 milestone_id uuid NOT NULL,
 customer_id uuid NOT NULL,
 amount_cents bigint NOT NULL CHECK(amount_cents>0),
 expires_at timestamptz NOT NULL,
 consumed_at timestamptz,
 consumed_request_id uuid,
 created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(tenant_id,milestone_id) REFERENCES securepay_milestones(tenant_id,id),
 CHECK ((consumed_at IS NULL AND consumed_request_id IS NULL) OR
        (consumed_at IS NOT NULL AND consumed_request_id IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS securepay_proof_scope
 ON securepay_release_proofs(tenant_id,milestone_id,customer_id,expires_at);
ALTER TABLE securepay_release_proofs ENABLE ROW LEVEL SECURITY;
ALTER TABLE securepay_release_proofs FORCE ROW LEVEL SECURITY;
-- Intentionally no permissive policy until signed tenant context and
-- customer identity are verified through the application auth layer.

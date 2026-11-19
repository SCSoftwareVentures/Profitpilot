-- SecurePay milestone persistence draft; apply only after database review.
-- Payment execution remains disabled. This schema records intent, not custody.
CREATE TABLE IF NOT EXISTS securepay_milestones (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  job_id uuid NOT NULL,
  amount_cents bigint NOT NULL CHECK (amount_cents > 0),
  is_final boolean NOT NULL DEFAULT false,
  status text NOT NULL CHECK (status IN
    ('planned','submitted','disputed','approved','release_pending','released')),
  version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
  provider_transaction_ref text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id,id)
);
CREATE TABLE IF NOT EXISTS securepay_release_requests (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  milestone_id uuid NOT NULL,
  idempotency_key text NOT NULL,
  amount_cents bigint NOT NULL CHECK(amount_cents > 0),
  authorization_ref text NOT NULL,
  status text NOT NULL CHECK(status IN ('pending','submitted','confirmed','failed')),
  provider_transaction_ref text,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(tenant_id,idempotency_key),
  FOREIGN KEY(tenant_id,milestone_id) REFERENCES securepay_milestones(tenant_id,id)
);
CREATE UNIQUE INDEX IF NOT EXISTS securepay_unique_provider_txn
 ON securepay_release_requests(provider_transaction_ref)
 WHERE provider_transaction_ref IS NOT NULL;
ALTER TABLE securepay_milestones ENABLE ROW LEVEL SECURITY;
ALTER TABLE securepay_milestones FORCE ROW LEVEL SECURITY;
ALTER TABLE securepay_release_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE securepay_release_requests FORCE ROW LEVEL SECURITY;
-- Deliberately NO permissive RLS policies: default deny until integrated
-- with the application's signed tenant-context mechanism.
-- All releases require one database transaction: lock milestone FOR UPDATE,
-- validate state/version, atomically consume PIN authorization, insert request
-- with unique idempotency key, then dispatch through an outbox after commit.

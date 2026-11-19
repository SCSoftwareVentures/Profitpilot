-- Draft: no production migration, runtime grants or permissive RLS.
-- Provision payer identities only via a separately reviewed invitation flow.
CREATE TABLE securepay_payer_identities(
 tenant_id uuid NOT NULL,
 customer_id uuid NOT NULL,
 auth_subject text NOT NULL CHECK(length(auth_subject) BETWEEN 1 AND 512),
 active boolean NOT NULL DEFAULT true,
 PRIMARY KEY(tenant_id,customer_id), UNIQUE(tenant_id,auth_subject)
);
CREATE TABLE securepay_pin_change_grants(
 grant_ref uuid PRIMARY KEY,
 tenant_id uuid NOT NULL,
 customer_id uuid NOT NULL,
 purpose text NOT NULL CHECK(purpose IN ('enroll','recover')),
 expires_at timestamptz NOT NULL,
 consumed_at timestamptz,
 FOREIGN KEY(tenant_id,customer_id) REFERENCES securepay_payer_identities(tenant_id,customer_id)
);
ALTER TABLE securepay_payer_identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE securepay_payer_identities FORCE ROW LEVEL SECURITY;
ALTER TABLE securepay_pin_change_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE securepay_pin_change_grants FORCE ROW LEVEL SECURITY;
-- Grant issuance is intentionally absent until identity-provider step-up
-- verification, invitation security and recovery notifications are integrated.

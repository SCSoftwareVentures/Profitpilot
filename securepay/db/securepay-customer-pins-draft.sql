-- Isolated draft. No production migration or permissive policies.
-- Bind the specific paying customer to each milestone; legacy fixtures may remain NULL.
ALTER TABLE securepay_milestones ADD COLUMN IF NOT EXISTS payer_customer_id uuid;
CREATE TABLE IF NOT EXISTS securepay_customer_pins (
 tenant_id uuid NOT NULL,
 customer_id uuid NOT NULL,
 salt text NOT NULL CHECK(salt ~ '^[0-9a-f]{32}$'),
 pin_hash text NOT NULL CHECK(pin_hash ~ '^[0-9a-f]{64}$'),
 failed_attempts integer NOT NULL DEFAULT 0 CHECK(failed_attempts BETWEEN 0 AND 5),
 locked_until timestamptz,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,customer_id)
);
ALTER TABLE securepay_customer_pins ENABLE ROW LEVEL SECURITY;
ALTER TABLE securepay_customer_pins FORCE ROW LEVEL SECURITY;
-- No permissive policies until signed customer/tenant identity and enrollment/reset
-- authorization have been reviewed. Never expose this table through a client API.

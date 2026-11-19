# SecurePay sandbox API boundary

The routes are disabled by default and cannot be enabled with NODE_ENV=production.
No external provider call, money custody or settlement runs in this implementation.

## Sandbox routes
- POST /v1/securepay/tenants/:tenantId/pin/grant — exact body: purpose (enroll or recover), stepUpToken. Optional and disabled unless the recovery authority is configured. Requires a separately validated short-lived, purpose- and tenant-bound step-up JWT with a unique jti. The resulting grant expires in at most two minutes and cannot be used twice.
- POST /v1/securepay/tenants/:tenantId/pin — exact body: pin, purpose (enroll or recover), grantRef.
- POST /v1/securepay/tenants/:tenantId/milestones/:milestoneId/reserve — exact body: pin, expectedAmountCents, idempotencyKey.
- The customer JWT must have the configured issuer, dedicated audience, recent auth_time, configured MFA assurance claim, and valid expiration.
- Responses never include PINs, reusable approval proofs or underlying database errors. A 202 reservation is not a transfer; moneyMoved is false.

## Session recovery
Successful PIN recovery sets a database-backed revocation timestamp and atomically writes a pending notification event. Customer API operations require a verified auth_time strictly newer than this timestamp; the payer identity is locked while checking and using that authentication. Recovery assertions must also be newer. This revokes older sessions at the SecurePay API, not at the external identity provider. The notification outbox stores identifiers and event type only; no delivery worker, contact details or external sends are provisioned. Failed transactions cannot queue a notification or revoke the session.

## Release blockers
- The 500-run qualification covers the original 52-test snapshot at commit 86b38751f79c4eabe58ecb94011e653ab2f2a313, not subsequent hardening. Requalify the updated test inventory before release.
- Payer invitation/provisioning and a real identity provider's purpose-bound step-up token issuance remain unimplemented. The sandbox verifies and consumes such assertions, uses an independent recovery signing key, and persists a replay ledger. The recovery key and verifier share the application process; separate deployment and external identity-provider session revocation remain required.
- The restricted payer runtime cannot directly mutate PINs, grant consumption, proof records, release requests or milestone states after applying the command-boundary draft. The narrow database functions recheck payer, state, version, amount, credential and scope; release and PIN change require exact, short-lived HMAC commands. Provision the domain-separated key derived from the PIN pepper into securepay_private.command_key via a trusted administrator, never the pepper itself. The service remains trusted to verify the PIN; full service or command-key compromise is not covered. A runtime with a valid signed payer context can still increment failure counters (denial of service within that payer's scope). Independent authority isolation, command-key rotation, and production deployment review remain outstanding.
- Audit events for grant issuance/consumption, PIN changes/failures and release reservation are transactional and protected from the payer runtime. Audit export, external immutable retention, independent anchoring, full denied-request telemetry, notification delivery and external identity-provider session revocation, key rotation and distributed rate limits remain outstanding.
- Implement provider-confirmed funding/dispute holds, payment reconciliation, retry semantics and dispute settlement.
- Validate Australian legal and provider requirements independently. No claim of production readiness.

# SecurePay sandbox API boundary

The routes are disabled by default and cannot be enabled with NODE_ENV=production.
No external provider call, money custody or settlement runs in this implementation.

## Sandbox routes
- POST /v1/securepay/tenants/:tenantId/pin — exact body: pin, purpose (enroll or recover), grantRef.
- POST /v1/securepay/tenants/:tenantId/milestones/:milestoneId/reserve — exact body: pin, expectedAmountCents, idempotencyKey.
- The customer JWT must have the configured issuer, dedicated audience, recent auth_time, configured MFA assurance claim, and valid expiration.
- Responses never include PINs, reusable approval proofs or underlying database errors. A 202 reservation is not a transfer; moneyMoved is false.

## Release blockers
- Provisioning payer identity and issuance of PIN enrollment/recovery grants from a verified identity-provider step-up event are not implemented. CI uses explicitly provisioned synthetic grants.
- The restricted payer database runtime is a trusted service credential, not a customer login. Current RLS scopes access but does not independently verify the PIN inside PostgreSQL: a compromised service or arbitrary SQL execution under the runtime could manufacture a proof or change an eligible milestone state. Before live use, eliminate direct financial/credential mutations, enforce independently authenticated, one-use authorization at a narrow database operation boundary, and test direct SQL bypass attempts.
- Add persistent audit events, secure recovery notification and session revocation, key rotation and rate-limiting across distributed instances.
- Implement provider-confirmed funding/dispute holds, payment reconciliation, retry semantics and dispute settlement.
- Validate Australian legal and provider requirements independently. No claim of production readiness.

# SecurePay sandbox API boundary

The routes are disabled by default and cannot be enabled with NODE_ENV=production.
No external provider call, money custody or settlement runs in this implementation.

## Sandbox routes
- POST /v1/securepay/tenants/:tenantId/pin — exact body: pin, purpose (enroll or recover), grantRef.
- POST /v1/securepay/tenants/:tenantId/milestones/:milestoneId/reserve — exact body: pin, expectedAmountCents, idempotencyKey.
- The customer JWT must have the configured issuer, dedicated audience, recent auth_time, configured MFA assurance claim, and valid expiration.
- Responses never include PINs, reusable approval proofs or underlying database errors. A 202 reservation is not a transfer; moneyMoved is false.

## Release blockers
- The 500-run qualification covers the original 52-test snapshot at commit 86b38751f79c4eabe58ecb94011e653ab2f2a313, not subsequent hardening. Requalify the updated test inventory before release.
- Provisioning payer identity and issuance of PIN enrollment/recovery grants from a verified identity-provider step-up event are not implemented. CI uses explicitly provisioned synthetic grants.
- The restricted payer runtime cannot directly mutate PINs, grant consumption, proof records, release requests or milestone states after applying the command-boundary draft. The narrow database functions recheck payer, state, version, amount, credential and scope; release and PIN change require exact, short-lived HMAC commands. Provision the domain-separated key derived from the PIN pepper into securepay_private.command_key via a trusted administrator, never the pepper itself. The service remains trusted to verify the PIN; full service or command-key compromise is not covered. A runtime with a valid signed payer context can still increment failure counters (denial of service within that payer's scope). Independent authority isolation, command-key rotation, and production deployment review remain outstanding.
- Add persistent audit events, secure recovery notification and session revocation, key rotation and rate-limiting across distributed instances.
- Implement provider-confirmed funding/dispute holds, payment reconciliation, retry semantics and dispute settlement.
- Validate Australian legal and provider requirements independently. No claim of production readiness.

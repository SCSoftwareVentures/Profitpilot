# SecurePay SP-S7 — terminal operator revocations and trusted-issuer boundary

## Verifiable behavior

S7 adds **append-only, single-use** withdrawal of an S6 synthetic signed-claim record. The authenticated tenant operator who originally recorded the claim, or the tenant owner/admin, may record a revocation under an exact request schema. The backend derives the current actor from its signed JWT-bound PostgreSQL tenant context. Tenant operators cannot modify or delete the revocation; direct runtime-role SQL cannot revoke a claim belonging to a different tenant or case. Concurrent requests cannot create two terminal revocations for one claim (database unique constraint). Same-actor, same-request exact replay returns 200; changed fields or another revocation attempt return 409.

POST/GET: `/v1/tenants/:tenantId/prototype/securepay-cases/:caseId/evidence/:evidenceId/signed-party-claims/:claimId/revoke`

POST requires exactly:
- `clientRequestId`: UUID
- `reasonCode`: `operator_withdrawal`, `suspected_key_compromise`, `provenance_disputed`, or `administrative_hold`
- `revocationReference`: bounded opaque reference; do not include personal information.

The S6 GET `verify-signature` endpoint now reports two separate realities: `cryptographicSignatureValid` (may remain true after withdrawal), and `revoked`, `status` and `operationallyUsable=false`. The S6 list endpoint includes revocation state for each returned claim. Revocation never alters the historical Ed25519 signature, whose original statement is still auditable.

GET `/v1/tenants/:tenantId/prototype/securepay-party-job-trust/:caseId` counts customer/tradesperson claims and revoked claims. Every result **always** blocks production authorization; a count of signatures is never a verified identity. This is a fail-closed integration boundary, not an identity provider integration.

## Limitations and remaining next priority

These revocations reflect **operator administrative action**, not authenticated legal withdrawal or consent by a real customer/tradesperson. S6 self-supplied keys are not backed by a trusted issuer. No authenticated external party-to-job membership, consent evidence, actual file bytes or byte-hash custody, real payment flow, adjudicator appointment, or Australian compliance sign-off exists. The protected deployment profile blocks the entire synthetic namespace.

The next integration must establish an independently configured identity issuer and verified, revocable user-to-job role grants, with controlled key rotation, actual content hashing and protected object storage, anti-malware processing, source authentication and retention policy. Real funds and binding dispute outcomes remain forbidden.

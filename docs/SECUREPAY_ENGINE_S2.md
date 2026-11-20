# SecurePay SP-S2 — synthetic operator evidence register

SP-S2 stores synthetic disputes and opaque evidence references in append-only, tenant-isolated PostgreSQL tables. It is NOT a live SecurePay dispute settlement service, an escrow facility, an authenticated customer/business portal, or a payment ledger.

## Authenticated prototype endpoints

Only active tenant owners, admins and reviewers with valid JWTs and database tenant context may use:
- POST /v1/tenants/:tenantId/prototype/securepay-cases
- GET /v1/tenants/:tenantId/prototype/securepay-cases/:caseId
- POST /v1/tenants/:tenantId/prototype/securepay-cases/:caseId/evidence
- GET /v1/tenants/:tenantId/prototype/securepay-cases/:caseId/evidence (optional cursor, 100 items/page)

Case input must contain exactly: synthetic=true, clientRequestId (UUID), jobReference and claimReference (opaque tokens).
Evidence input must contain exactly: clientRequestId (UUID), evidenceType and evidenceReference (opaque token).

This is a restricted operator register, not an assertion that the named customer or tradesperson personally submitted anything. Evidence categories are reported claims or notes, not verified origin or trusted document custody. Direct money movement is impossible through these endpoints. The protected deployment profile denies the entire prototype namespace.

## Safeguards

- PostgreSQL forced RLS, signed transaction-scoped tenant context and verified actor membership
- Owner/admin/reviewer-only read and insert privileges, matching creator attribution
- Composite tenant foreign keys, idempotent exact repeats, conflicting replay rejection
- Immutable rows, no runtime UPDATE/DELETE, fail-closed status and verification flags
- No user-supplied payment amount, destination, decision, funds-moved flag or authenticated party assertion
- Authenticated HTTP and database negative tests, encrypted backup/restore count comparison

No real case data or payment details are authorised for this synthetic environment. Opaque evidence references are not independently anchored, and the records could still be altered by a sufficiently privileged database administrator outside this runtime guard.

## Next engineering gates

Tie the isolated SP-S1 decision-state machine to authoritative case events only after independently verified customer/business identity, reviewer conflict checks, evidence provenance and governance, atomic concurrency, calendars, lifecycle tests, user interface and Australian regulatory/provider review. Keep real funds disabled throughout development.

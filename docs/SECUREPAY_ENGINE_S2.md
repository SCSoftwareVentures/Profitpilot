# SecurePay SP-S2 — synthetic operator evidence register

SP-S2 stores synthetic disputes and opaque evidence references in append-only, tenant-isolated PostgreSQL tables. It is NOT a live SecurePay dispute settlement service, an escrow facility, an authenticated customer/business portal, or a payment ledger.

## Authenticated prototype endpoints

Only active tenant owners, admins and reviewers with valid JWTs and database tenant context may use:
- POST /v1/tenants/:tenantId/prototype/securepay-cases
- GET /v1/tenants/:tenantId/prototype/securepay-cases (optional tenant-scoped cursor, 100 cases/page)
- GET /v1/tenants/:tenantId/prototype/securepay-cases/:caseId
- GET /v1/tenants/:tenantId/prototype/securepay-cases/:caseId/decision-preflight (read-only, always blocked)
- POST /v1/tenants/:tenantId/prototype/securepay-cases/:caseId/evidence
- GET /v1/tenants/:tenantId/prototype/securepay-cases/:caseId/evidence (optional cursor, 100 items/page)

Case input must contain exactly: synthetic=true, clientRequestId (UUID), jobReference and claimReference (opaque tokens).
Evidence input must contain exactly: clientRequestId (UUID), evidenceType and evidenceReference (opaque token).

This is a restricted operator register, not an assertion that the named customer or tradesperson personally submitted anything. Evidence categories are reported claims or notes, not verified origin or trusted document custody. Direct money movement is impossible through these endpoints. The protected deployment profile denies the entire prototype namespace.

The case-list cursor must exist in the same tenant, returns no cross-tenant rows, and does not assert verified party identity. Pagination uses descending creation timestamp and UUID ordering; it does not provide a tamper-proof evidence export.

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

## SP-S2 decision preflight (safe engineering bridge)

The read-only preflight uses one repeatable-read tenant transaction to inspect the recorded case and count matching operator-reported claim references, business response reports and review notes. It identifies missing operator reports and whether the requester also opened the case; this does **not** establish reviewer independence, party identity, evidence provenance, consent, legal authority or a permitted payment. An unrelated claim reference cannot satisfy the claim-match signal. Even when all three operator-report categories exist, `decisionReadiness` remains `blocked`, `decisionAuthority` and `paymentAuthority` remain false, and the unverifiable gates are explicitly returned. No SP-S1 event is advanced, no status is mutated, and no funds are moved. Complete authoritative identity and governance integration before exposing a real decision workflow.

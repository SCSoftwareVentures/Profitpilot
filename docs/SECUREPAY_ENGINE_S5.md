# SecurePay SP-S5 — synthetic reported provenance register

## Actual guarantee, not an implied one

S5 records **who in the authenticated tenant operator workspace reported provenance metadata for an existing evidence item**. The operator may report an origin, but the person who allegedly supplied the document, their identity, their authority for the underlying job, the contents, and the custody history have **not** been independently authenticated. All items remain synthetic rehearsal data.

## API

- POST/GET `/v1/tenants/:tenantId/prototype/securepay-cases/:caseId/evidence/:evidenceId/provenance`
- GET `/v1/tenants/:tenantId/prototype/securepay-cases/:caseId/provenance-preflight`

Authenticated, active tenant owner/admin/reviewer only. POST must have **exactly** `clientRequestId` UUID, `reportedOrigin` from `reported_customer`, `reported_business`, `reported_third_party`, `operator_observed`, `unknown`; `acquisitionMethod` from `operator_relay`, `document_reference_only`, `unknown`; and an opaque bounded `sourceReference`. The backend determines actor ID from the signed database context. It reads the case/job/evidence scope from PostgreSQL, never from caller-supplied IDs or a claimed identity.

Database composite FK prevents attaching an evidence item to the wrong tenant or case. Signed actor attribution, forced tenant RLS, append-only triggers, exact idempotency replay rejection and restricted columns prevent asserting a verified origin, job authority, content authenticity or payment authority. The server computes a reproducible SHA-256 checksum of **reported metadata only**. This is not a checksum of the source document, not externally anchored, and not a proof that any actual customer or business sent the material. No source file bytes or personally identifying evidence is accepted. Sources are opaque references; callers must not put personal data into them.

The read-only provenance preflight reports counts of evidence with any metadata receipt and separately counts **reported** customer origins on claim evidence and **reported** business origins on response evidence. It **always** returns `decisionReadiness=blocked`, `paymentAuthority=false`, and `partyToJobVerified=false`, even with every reported category filled.

## Limitations and next gate

S5 does not bind a verified human customer or tradesperson to an independently validated job, authenticate source upload bytes, verify a document signature, provide a WORM audit store, prove source custody, or integrate with a payment provider. Real evidence ingestion needs explicit permission, privacy basis, malware scanning, content hashing and protected object storage; real-party binding needs a trusted authentication provider and independently established role-to-job authority. No regulatory or payment-provider approval is presumed. S5 is a draft prototype and does not enable payments, settlement or adjudication.

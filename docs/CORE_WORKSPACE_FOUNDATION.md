# Core workspace foundation — implementation scope

Date: 18 November 2026. Base: verified security release branch source head
ae8cdd65147ff41e82ff13cd7416b0d1746ef637, CI #1838. The security
candidate and buyer handover remain unchanged. This is a separate development
branch; no production authorization follows from this work.

## Implemented journey
- An authenticated tenant owner/admin creates one new business, one site,
  one contract and its first draft contract version in a single database
  transaction. An active tenant member can retrieve that setup by its UUID.
- Client-generated UUIDv4 setupId gives safe retry semantics scoped to the
  creating actor and the exact canonical input. Different inputs or actor
  conflict; a failed insert rolls back all linked records. Setup IDs are
  unique only within each tenant; server-generated contract IDs prevent a
  cross-tenant identifier-existence oracle.
- Explicit AUD, monthly billing, tax-basis enum (unknown permitted only
  as draft), effective date 2000–2099 and canonical nonnegative two-decimal
  price within NUMERIC(14,2). Names follow a deliberately narrow bounded
  ASCII label profile. No free-form source reference or arbitrary nested JSON.
- New contract versions have no approver or approval timestamp. They cannot
  qualify as the approved effective baseline for a calculation. No automatic
  approval, payment, profit claim, document intake or payroll processing.
- Migration 045 adds one bounded security-definer capability and a unique
  audit-receipt index; no direct writes granted to the API runtime. Actor
  authority, emergency containment and tenant-bound identity are enforced
  at the database boundary, and the reviewed security catalogue is advanced.
- New endpoints reject production requests before body parsing; the
  restriction cannot be disabled with an environment toggle.

## Verification
Unit tests cover strict money/date/field schemas and closed production gate.
Dedicated authenticated integration tests cover unauthorized and wrong-
tenant requests, direct unsigned/reader SQL attempts, concurrent identical
retries, changed-payload conflicts, independent cross-tenant identifier reuse, exact
decimal persistence, draft status, chained audit event and emergency
containment. Full existing security CI remains mandatory. Record actual
exact-head status in the branch CI; this document does not assert test success.

## Next core work
1. Workspace discovery/selection, business and site management, contract
   version draft editing via new immutable versions, explicit recent-MFA
   owner/reviewer approval and overlapping effective-period safeguards.
2. Evidence-backed synthetic payroll ingestion and source reconciliation:
   do not open generic real payroll intake or collect employee identifiers.
3. Invoice source-to-line mapping and human decision workflows with
   completeness checks, supplier cost classification, variation authority.
4. Versioned management contribution, exceptions and reporting; keep
   definitive profit/margin withheld until material inputs and policy prove
   completeness.
5. iPhone-first integrated buyer demonstration, navigation, retry handling
   and workflow acceptance. The current browser business prototype is not
   yet integrated with this API.

Existing customer, finance, privacy, legal and production acceptance gates
remain in force; no main merge, external spend or deployment.

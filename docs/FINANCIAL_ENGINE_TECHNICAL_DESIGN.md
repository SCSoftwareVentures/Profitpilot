# Financial Engine Technical Design

**Status:** proposed technical design for review; not an implemented schema or API contract.
**Reviewed ref:** product/six-differentiators-blueprint, commit 43910081652db83bb2b9e5e0e3c2f98c0596b915.
**Execution status:** design only. No code, migrations, dependencies or tests changed or executed.
**Build authority:** implementation remains blocked pending G5 signed GO and named owners.

## 1. Executive decision

Retain a modular monolith and PostgreSQL, but separate the financial calculation domain from HTTP handlers and source-import parsing.

The calculation engine must be a deterministic, pure domain layer. It accepts validated, versioned inputs and returns typed results with provenance references. Persistence orchestration creates immutable calculation runs in one database transaction. HTTP routes authenticate, authorise, validate and invoke application services; they must not perform financial arithmetic.

Authoritative money must be parsed from source text into exact decimal values. JavaScript Number is prohibited in the authoritative money path, including API serialization, aggregation, persistence conversion and test oracles.

This design does not select a decimal package, monetary precision/scale, GST policy, rounding policy, revenue recognition basis or materiality threshold. Those decisions require named technical and finance/accounting approval.

## 2. Baseline findings and integration dependency

The reviewed source currently exposes money, validateInvoiceRows, allocatePayroll, matchInvoice, summariseContracts and aggregateMetrics from src/engine.js. These functions use JavaScript numeric coercion/arithmetic. server/index.js also calculates contribution using Number and toFixed inside a route handler.

The current module has no exact decimal abstraction, immutable financial input contract, source-row allocation ledger or complete calculation provenance.

### Critical branch dependency

The database/API security scaffold is in separate open draft PR #25, branch security/exhaustive-hardening, not part of PR #26's base branch. PR #25 is not merged. Its migrations, schema and API contract must not be assumed to exist on main or on this documentation branch.

Before implementation, the technical owner must reconcile the intended base commit and PR #25 disposition. Do not copy schema assumptions across branches or merge either PR as an incidental part of this work.

## 3. Target module boundaries

Proposed source layout:

    src/financial/
      decimal/decimal-adapter.js
      decimal/decimal-policy.js
      parsing/amount-parser.js
      parsing/locale-profiles.js
      contracts/money.js
      contracts/source-reference.js
      contracts/result-status.js
      payroll/payroll-pool.js
      payroll/allocation.js
      payroll/allocation-validation.js
      invoices/invoice-normalisation.js
      invoices/match-evidence.js
      invoices/match-coverage.js
      contribution/contribution-input.js
      contribution/contribution-calculation.js
      runs/calculation-input.js
      runs/calculation-result.js
      runs/provenance.js
      index.js
    server/services/
      import-service.js
      allocation-service.js
      match-review-service.js
      calculation-service.js
    server/repositories/
      financial-repository.js
      import-repository.js
    server/routes/
      imports.js
      allocations.js
      matches.js
      calculations.js
    tests/financial/
      decimal/
      parsing/
      payroll/
      invoices/
      contribution/
      properties/
      integration/

The decimal adapter isolates the selected third-party package. Domain modules must use this adapter rather than import the package directly. Pure calculation modules must not import Express, PostgreSQL clients, environment variables, clocks, random generators or network clients. All required values, including effective dates and policy versions, are explicit inputs.

## 4. Canonical domain contracts

The following TypeScript-like declarations are conceptual interface notation, not current source code or a commitment to TypeScript adoption.

### 4.1 Money

    type CurrencyCode = string; // validated ISO 4217 code
    type TaxBasis =
      | "GST_INCLUSIVE" | "GST_EXCLUSIVE" | "NO_GST"
      | "OTHER" | "UNKNOWN";

    type MoneyValue = {
      amount: string;             // canonical decimal string, never JS number
      currency: CurrencyCode;
      taxBasis: TaxBasis;
      sourcePrecision: number | null;
      sourceReferenceId: string;
      parserVersion: string;
      status: "VALID" | "HELD" | "UNKNOWN" | "REJECTED";
    };

Runtime schemas must validate decimal grammar, supported scale, bounds, currency code, tax basis and source-reference existence. Type declarations alone are not validation.

### 4.2 Source reference

    type SourceReference = {
      tenantId: string;
      sourceSystemId: string;
      importBatchId: string;
      sourceFileId: string;
      sourceRowId: string;
      sourceRowNumber: number;
      sourceChecksum: string;
    };

Raw payloads remain in restricted storage. Calculation outputs reference source IDs rather than duplicating sensitive payroll or invoice payloads.

### 4.3 Typed calculation result

    type FinancialResult<T> =
      | { status: "VALID"; value: T; warnings: string[] }
      | { status: "INCOMPLETE"; value: T | null; missingInputs: string[]; warnings: string[] }
      | { status: "HELD"; value: null; exceptions: string[] }
      | { status: "REJECTED"; value: null; errors: string[] };

Do not overload null or zero. A known zero is a valid amount. An unavailable amount is unknown or incomplete.

### 4.4 Policy references

Every calculation input carries immutable IDs/versions for parser and source mapping; payroll eligibility and allocation method; invoice denominator and match-evidence policy; tax treatment; rounding registry; contribution inclusion and revenue basis; calculation formula; and engine build/commit.

No default policy may be silently selected in production.

## 5. Calculation interfaces

### 5.1 Amount parsing

Input: raw source string, declared source profile/locale, currency mapping, tax-basis mapping, source reference and parser version.

Output: FinancialResult of MoneyValue.

Rules:
- No implicit locale detection for ambiguous values.
- No permissive Number() or parseFloat() financial parsing.
- Retain raw input separately.
- Malformed, ambiguous or unsupported values are held.
- Zero and missing remain distinct.
- Credits and negative values retain their sign.
- Parser/profile changes create new versions.

### 5.2 Payroll allocation

Input includes authoritative payroll pool and source control total; eligible source rows with exact amounts and cost basis; proposed direct/approved/non-site/unallocated/excluded classifications; allocation method/version and reviewer decisions; currency/tax basis and pay-period identity.

Output includes per-source-row allocation ledger, exact bucket totals, residual, reconciliation difference, exceptions and provenance.

Invariants:
1. For each source row, sum of allocations cannot exceed eligible amount.
2. A source row cannot be counted twice in overlapping confirmed runs.
3. Direct, approved allocated, non-site, residual and excluded buckets reconcile to the authoritative pool under the approved policy.
4. Pending or rejected decisions are not approved site costs.
5. A new allocation decision creates a new run; it never rewrites history.

### 5.3 Invoice evidence and match coverage

Candidate evidence dimensions remain separately inspectable: customer identity; contract and contract-version identity; site identity; service-period fit; service/line description; amount and currency; GST/tax basis; duplicate/conflict state; source lineage.

Output states distinguish candidate, held, confirmed and rejected. Candidate confidence does not equal authorisation. Only authorised human confirmation enters the confirmed match-coverage numerator.

Coverage input includes a versioned eligible-denominator policy, line eligibility decisions, credits, cancellations and duplicates. The calculation returns numerator, denominator, exact ratio, display ratio, included line IDs and exclusions.

### 5.4 Contribution

Input includes revenue basis and eligible revenue source lines; direct-coded labour; approved allocated labour; supplier/subcontractor costs; other included delivery costs; non-site and unallocated amounts; currency and tax basis; service-period completeness; policy versions and source references.

Output is labelled management contribution and exposes included/excluded categories and coverage. If material inputs are unknown, incompatible or incomplete, return HELD/INCOMPLETE and suppress definitive margin.

### 5.5 Calculation run

A calculation run is immutable and captures tenant, contract, contract version, site, service period; all included source row IDs and excluded/held IDs; import batch/file checksums; mapping, allocation, match and financial policy versions; engine commit and decimal adapter version; exact input snapshot/hash; exact decimal output snapshot; status, warnings and exceptions; creator, timestamp/timezone and correlation ID; prior run and restatement reason, where applicable.

A replay with the same canonical inputs and policy versions reproduces the same exact outputs. A changed input, policy or engine version creates a new run with explicit lineage.

## 6. Persistence model — logical, not migration-ready

Proposed logical relationships:

    Tenant
      └─ ImportBatch
          └─ SourceFileManifest
              └─ RawImportRow
                  └─ MappingDecision (versioned)

    Tenant
      └─ PayrollPool
          └─ PayrollSourceRow
              └─ AllocationLine
                  └─ AllocationRun

    Tenant
      └─ Invoice
          └─ InvoiceLine
              └─ MatchCandidate
                  └─ MatchReviewDecision (append-only)

    Tenant
      └─ CalculationRun
          ├─ CalculationRunSource (included/held/excluded)
          ├─ CalculationRunPolicy
          ├─ CalculationOutput
          └─ RestatementLink

### Database requirements

- Use PostgreSQL NUMERIC(p,s) only after supported maximum amount, precision and scale have been validated. These are open decisions.
- Currency and tax basis are mandatory on monetary records.
- Use foreign keys and tenant-scoped uniqueness for source references and decision identities.
- Source snapshots, review decisions, calculation outputs and audit events are append-only; corrections append new versions.
- Add uniqueness constraints for idempotency keys and source-row identity within a source file/import scope.
- Apply row-level security and tenant-scoped repository access consistently with the separately reviewed security architecture.
- Use database transactions for state transitions and calculation-run creation.
- Never store authoritative money as SQL REAL, FLOAT or DOUBLE PRECISION.
- Do not use JSON numeric values for authoritative money snapshots; decimal strings may be retained in immutable snapshots, with queryable canonical values in typed columns.
- Add indexes only after query plans and expected volumes are measured.

### Concurrency rules

- Approval and match-confirmation updates are conditional state transitions, not blind overwrites.
- Use row locks or compare-and-set version checks to prevent concurrent finalisation.
- Use unique idempotency keys for import creation and externally retried commands.
- Persist decision and audit event in the same transaction.
- Calculation-run creation snapshots a consistent set of source/decision versions; reject if those versions change during the transaction.

## 7. API contract — proposed versioned shape

Routes below are illustrative, not implemented.

### Parse/preview import

    POST /v1/tenants/{tenantId}/imports/{batchId}/preview

Request identifies mapping profile version and preview options. It does not accept client-supplied authoritative totals or calculated values.

Response contains accepted/held/rejected row counts; source versus parsed row counts; exact decimal control totals as strings with currency/tax basis; exceptions and source row references; mapping version and preview ID.

### Submit allocation proposal

    POST /v1/tenants/{tenantId}/payroll-pools/{poolId}/allocation-runs

Request includes source row IDs, destination bucket/site, exact decimal allocation strings, method version and evidence references. Server revalidates eligibility and row-level caps. Proposal is not confirmed until authorised review.

### Review allocation decision

    POST /v1/tenants/{tenantId}/allocation-runs/{runId}/decisions

Request contains decision, reason and expected version. Server enforces role, state transition and source-row invariants. Client identity/role is never trusted from request body.

### Review invoice match

    POST /v1/tenants/{tenantId}/match-candidates/{candidateId}/decisions

Request contains confirm/reject/hold, reason and expected version. Human authority, evidence state and conflict status are checked server-side.

### Create calculation run

    POST /v1/tenants/{tenantId}/calculation-runs

Request contains contract, site, service period and selected policy versions. It does not contain client-calculated revenue, cost, contribution or margin.

Response includes run ID and status; exact monetary strings; currency and tax basis; coverage/completeness; included and excluded source references; policy and engine versions; warnings and limitations.

### Retrieve immutable run

    GET /v1/tenants/{tenantId}/calculation-runs/{runId}

The endpoint is tenant-scoped and read-only. Restatement creates a new run; it does not update the old response.

All endpoints require authentication, tenant membership, least-privilege role checks, server-side schema validation, audit events and rate limits. API errors must not leak raw payroll/invoice payloads or database details.

## 8. Application service and transaction pattern

1. Authenticate caller and resolve active tenant membership.
2. Validate request schema and idempotency key.
3. Begin tenant-scoped database transaction.
4. Lock/read source and policy versions for a consistent snapshot.
5. Load only authorised, eligible source references.
6. Call pure domain calculation function with explicit inputs.
7. Validate output invariants again at service boundary.
8. Persist immutable run, input references, outputs and audit event atomically.
9. Commit and return exact decimal strings.
10. On failure, roll back all writes and return a stable error code/reference.

Pure calculation code is testable without a database. Persistence integration tests separately prove tenant isolation, concurrency and transaction rollback.

## 9. Decimal library selection protocol

Do not add a dependency until the technical owner records a comparison covering active maintenance/release history; licence and transitive dependencies; known security advisories; Node.js 22 compatibility; parsing from strings; precision and scale controls; required rounding modes and negative tie behaviour; deterministic serialisation; performance on synthetic batches; interoperability; lockfile, SBOM and upgrade policy.

The selected package is isolated behind decimal-adapter.js. No source file should create monetary decimals from JavaScript numeric literals. Tests use strings.

## 10. Migration and rollout strategy

### Stage 0 — design approval
- Reconcile PR #25 security scaffold disposition and base branch.
- Resolve policy owners and package choice.
- Review schema compatibility and migration order.
- Freeze synthetic golden fixtures and expected outputs.
- Obtain G5 signed GO before implementation.

### Stage 1 — non-production vertical slice
- Add decimal adapter and source parser.
- Implement one synthetic payroll fixture end-to-end.
- Persist exact source references and a calculation run.
- Verify deterministic replay and tenant isolation.
- No live customer data.

### Stage 2 — payroll and invoice domain
- Implement row-level payroll allocations and human decision history.
- Implement invoice evidence candidates and confirmed coverage.
- Run integration, concurrency and property suites.

### Stage 3 — contribution and restatement
- Implement only after revenue/cost/tax/rounding policies are approved.
- Add completeness suppression and immutable restatements.
- Independently review every golden expected result.

### Stage 4 — controlled pilot gate
- Separately satisfy privacy/legal, storage, malware scanning, identity/MFA, backup/restore, monitoring, incident response and penetration-test requirements.
- Use minimised, specifically authorised data in a controlled environment only after approval.
- Unit tests alone do not authorise deployment or customer onboarding.

### Migration safety
- Every schema migration has forward migration, rollback/recovery plan, data compatibility review and tenant isolation test.
- Never convert existing floating-point values into canonical exact amounts without retaining raw source values and documenting that exact historical source precision may be unrecoverable.
- Mark reconstructed historical values as estimated/reconstructed, not source-exact.
- Do not backfill currency or tax basis by guessing AUD or GST treatment.

## 11. Observability and audit requirements

Capture structured events for import accepted/held/rejected; mapping proposed/confirmed/rejected; allocation proposed/confirmed/rejected/restated; invoice match proposed/confirmed/rejected; calculation run created/blocked/restated; policy version changed; export generated; permission denied and suspicious cross-tenant access.

Each event includes tenant, actor/service identity, action, target ID, timestamp, correlation ID, policy/version references and reason where appropriate. Do not log raw personal, payroll or invoice content. Security logs are protected against modification and access-controlled.

Operational metrics include processing duration, held-row rate, reconciliation differences, failed calculations, duplicate import rate, restatement rate, tenant isolation denials and export activity. Metrics must not expose individual worker data.

## 12. Security, privacy and failure analysis

| Threat/failure | Required control |
|---|---|
| Cross-tenant record access | Tenant-scoped authorization, RLS and adversarial integration tests |
| Reviewer self-escalation | Server-side role checks and audited role grants |
| Double allocation | Per-row cap, uniqueness and transactional locking |
| Duplicate import/retry | Checksum/idempotency key and unique constraints |
| Concurrent approval | Conditional state transition/version check |
| Calculation input changes mid-run | Consistent transaction snapshot and version capture |
| Decimal overflow/scale abuse | Explicit parser bounds and decimal library limits |
| Malformed locale | Hold ambiguous source values; no guess |
| Missing tax/currency | Block incompatible aggregation |
| Stale mapping/policy | Version pinning and new calculation run |
| Log/data leakage | Redaction, least privilege, restricted raw source storage |
| Data correction | Append-only restatement and audit trail |
| Public repository exposure | Synthetic fixtures only; secrets and real records prohibited |

Private object storage, malware scanning, retention/deletion, production key management, identity/MFA, independent penetration testing and backup restore remain separate release blockers.

## 13. Design acceptance checklist

The design is ready for implementation estimation only when accountable owners approve:
- [ ] Technical owner confirms base commit and PR #25 dependency/disposition.
- [ ] Finance/accounting reviewer approves payroll cost basis, revenue basis, GST handling and rounding boundaries.
- [ ] Decimal package and version are selected with security/licence review.
- [ ] Monetary precision/scale and maximum bounds are approved.
- [ ] Source profiles/locales and parser error semantics are specified.
- [ ] Canonical contracts and runtime validation schemas are reviewed.
- [ ] Logical schema and tenant uniqueness/RLS design are reviewed.
- [ ] API request/response schemas are reviewed and versioned.
- [ ] Concurrency, idempotency and immutable restatement rules are accepted.
- [ ] Golden fixture expected values have independent review.
- [ ] Privacy, retention and access classifications are approved.
- [ ] G5 explicit signed GO, named technical owner, delivery capacity, legal/privacy plan and approved budget exist.

**Current outcome: NOT READY FOR IMPLEMENTATION.** This is a technical design baseline for review, not build authorisation.

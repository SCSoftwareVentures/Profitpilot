# Financial Engine Remediation Backlog and Traceability

**Status:** engineering analysis and proposed backlog; documentation only.
**Reviewed ref:** `product/six-differentiators-blueprint`
**Reviewed source commit:** `4693fbb7d2269852cf9a93cb80d8ef844c0b814f`
**Reviewed source files:** `src/engine.js`, `tests/engine.test.js`, `package.json`, Core Calculation Spec, Financial Data Contract, Synthetic Financial Test Oracle and Executable Acceptance Test Plan.
**Execution status:** no code changed, no package installed, no tests executed by this review.

## 1. Executive engineering assessment

The current engine is a small deterministic demo module, not a financial calculation engine suitable for customer data. Its principal risk is not simply floating-point rounding: the current public functions accept weakly typed inputs and discard much of the evidence required to establish what a number means.

The first remediation should therefore establish typed source facts and exact arithmetic before adding more financial features. Payroll row-level allocation and invoice evidence/authority follow. Contribution aggregation must remain blocked until currency, tax basis, period completeness and revenue/cost policies are explicit.

**Do not implement this backlog before the project's existing build authorisation gate (G5).** This document is a proposed implementation sequence, not approval to start feature coding.

## 2. Current source-to-requirement traceability

| Area | Current implementation | Gap against contract | Priority | Acceptance references |
|---|---|---|---|---|
| Money primitive | `money()` uses `Number`, `Math.round`, `Number.EPSILON` | Binary float; no declared precision, rounding boundary, negative tie policy or overflow contract | Critical | DEC-001–012 |
| Source parsing | Invoice `amount` uses `Number(r.amount)` | No locale, currency, tax basis, source precision, raw/parsed status or ambiguity handling | Critical | DEC-001–005, DEC-010–011 |
| Invoice validation | Requires invoice_id/site/date/positive amount | No contract identity, currency/tax checks, credit semantics, duplicate identity, line-level provenance | High | INV-001, INV-004, INV-007, TAX-004–006 |
| Payroll | Aggregate direct/approved/non-site/excluded totals; computes residual | No source-row identity, per-row eligibility/cap, duplicate allocation, reviewer/evidence lineage or currency/tax compatibility | Critical | PAY-001–009, PROP-001–002 |
| Invoice matching | Site/date/positive amount; labels MEDIUM | Evidence model incomplete; no contract/customer identity, tax/currency checks, conflict detection or persisted human decision state | High | INV-001–009 |
| Contribution | Sums revenue/cost and computes margin | No declared revenue basis, currency/tax/period/completeness metadata, cost classification or missing-input state | Critical | CON-001–005 |
| Import | CSV parser returns row objects | No import batch/checksum, mapping version, idempotency or source control totals in this module | High | IMP-001–007 |
| Restatement | No calculation-run model in engine | Cannot reproduce historical result or preserve old/new runs in current module | High | DEC-012, PAY-009, PROP-010 |
| Test suite | Basic example tests | No financial golden oracle execution, negative midpoint, locale, GST, currency, provenance, idempotency, property or adversarial coverage | Critical | all suites |

## 3. Proposed work packages

### FE-01 — typed money and decimal foundation
**Priority:** Critical. **Dependency:** finance/accounting policy owner and technical owner.

Deliverables:
- Select and pin a maintained decimal arithmetic package only after licence, maintenance, security and runtime review.
- Define canonical money value and parser result types.
- Implement source-specific parsing from strings; reject ambiguous or malformed formats.
- Preserve raw value, currency, tax basis, source precision, parser version and source reference.
- Replace all authoritative `Number` arithmetic with decimal operations.
- Define rounding policy registry and keep unresolved business rounding policies configurable/blocked, not guessed.
- Serialise money as decimal strings.

Acceptance: DEC-001–012, TAX-006, PROP-003, PROP-008, PROP-012–013. No float conversion in authoritative path.

### FE-02 — payroll source-row allocation ledger
**Priority:** Critical. **Dependency:** FE-01 and approved payroll cost/eligibility definitions.

Deliverables:
- Source payroll row identity and eligible amount.
- Mutually exclusive direct, approved allocated, non-site, unallocated and excluded classifications.
- Per-row allocation cap and duplicate/overlap detection.
- Approval record with role, method version, evidence, timestamp and reason.
- Exact pool reconciliation and source control totals.
- Immutable allocation runs and restatement links.

Acceptance: PAY-001–009, PROP-001–002, PROP-010, PROP-011, PROP-014.

### FE-03 — invoice evidence and human decision model
**Priority:** High. **Dependency:** FE-01 and contract/site/service-period identity model.

Deliverables:
- Separate evidence candidate from authorised confirmation.
- Evidence dimensions for customer, contract, site, service period, service description, amount, currency, tax basis, duplicates and conflicts.
- Explicit eligible denominator policy for coverage.
- Human decision record with reviewer authority, evidence and timestamp.
- Credits, cancellations and duplicate candidates preserved as distinct states.

Acceptance: INV-001–009, PROP-006, PROP-011.

### FE-04 — contribution completeness and policy
**Priority:** Critical. **Dependency:** FE-01, FE-02, FE-03 and finance review.

Deliverables:
- Explicit revenue basis and cost inclusion policy.
- Currency/tax/period compatibility checks.
- Required-input and materiality completeness rules.
- Distinct direct, approved allocation, supplier, other delivery, non-site and residual values.
- Management contribution label and limitations.
- Suppress definitive margin when material inputs are unknown/incomplete.

Acceptance: CON-001–005, PROP-005, PROP-008–009, PROP-011.

### FE-05 — import integrity and source lineage
**Priority:** High. **Dependency:** source-specific mapping contracts.

Deliverables:
- Import batch, checksum, tenant, source system and mapping/parser version.
- Stable source row IDs and row counts.
- Idempotency key and duplicate replay handling.
- Source/parsed/accepted/held/excluded control totals.
- Unknown mapping and timezone exceptions held visibly.
- Safe export encoding.

Acceptance: IMP-001–007, PROP-003–004, PROP-014.

### FE-06 — immutable calculation run and restatement
**Priority:** High. **Dependency:** FE-01 through FE-05; data model design review.

Deliverables:
- Calculation run ID, immutable input/version references, engine commit, policies and generated timestamp.
- Output snapshot and provenance closure.
- New run for corrected source, mapping, approval or policy.
- Old run retained and marked superseded/restated; reason and reviewer recorded.
- Deterministic reproduction.

Acceptance: DEC-012, PAY-009, PROP-010–012.

### FE-07 — cross-cutting security and test assurance
**Priority:** Critical for any customer-data pilot. **Dependency:** identity/tenant architecture and environment.

Deliverables:
- Tenant isolation on every read/write and calculation lookup.
- Role checks for approvals and reviewer decisions.
- Concurrent decision/idempotency protection.
- Property-based suite with recorded seeds and shrinking.
- CI evidence tied to exact commit, runtime and fixtures.
- Independent expected-result review and accounting sign-off.

Acceptance: all security cases in the verification plan; all property invariants; exit criteria in the Executable Acceptance Test Plan.

## 4. Dependency order

```text
G5 build authorisation
        |
        v
FE-01 typed parsing + decimal foundation
        |
        +-------------------+
        |                   |
        v                   v
FE-02 payroll ledger    FE-05 import lineage
        |                   |
        +---------+---------+
                  |
                  v
          FE-03 invoice evidence
                  |
                  v
          FE-04 contribution policy
                  |
                  v
          FE-06 immutable calculation runs
                  |
                  v
          FE-07 integrated assurance
                  |
                  v
          separately approved pilot gate
```

Some work can be designed in parallel, but implementation dependencies must not be bypassed. In particular, contribution must not be made authoritative before the source money contract, payroll provenance and invoice evidence models exist.

## 5. Existing tests versus required coverage

Current `tests/engine.test.js` includes basic money precision, date validation, CSV parsing, invoice required fields, payroll aggregate reconciliation, amount-only unmatched, human-confirmation flag and basic contribution metrics.

It does **not** currently prove:
- negative half-cent rounding behaviour;
- locale-safe decimal parsing;
- GST or currency compatibility;
- line-versus-total rounding policy;
- zero versus unknown semantics;
- row-level payroll allocation caps and duplicate protection;
- invoice evidence completeness and decision authority;
- contribution completeness and tax/currency comparability;
- import checksum idempotency;
- restatement immutability;
- property-based invariants or tenant isolation.

No conclusion about passing these missing cases can be drawn from the existing test suite.

## 6. Explicit design decisions still required

These must be resolved by named accountable owners, not selected by the implementation agent:
1. Decimal library, licence and pinned version.
2. Supported currency set and precision/scale bounds.
3. Source-specific locale/number formats.
4. Rounding mode and boundary for each financial operation.
5. GST source and transaction-specific treatment.
6. Historical FX rate source/method.
7. Payroll pool inclusions and eligibility rules.
8. Contract revenue basis and eligible invoice denominator.
9. Cost categories and materiality thresholds.
10. Raw employee/invoice record access, retention and deletion policy.

## 7. Implementation safeguards

- Do not add a decimal dependency until technical review is recorded.
- Do not change existing engine semantics in place without a migration/compatibility plan.
- Keep demo fixtures synthetic and clearly labelled.
- Do not use live customer payroll, invoices or employee records in public repository fixtures, CI logs or issue comments.
- Do not claim accounting, tax, statutory or audit compliance.
- Do not expose individual worker rankings or sensitive small-group data.
- Do not build payment custody, escrow or funds movement into these work packages.
- No merge, deployment or production use is authorised by this backlog.

## 8. Definition of backlog readiness

This backlog is ready for estimation only after:
- a named technical owner validates architecture and dependencies;
- a qualified finance/accounting reviewer resolves relevant policy decisions;
- legal/privacy review defines permitted data and retention;
- test fixtures and expected results receive independent sign-off;
- G5 explicit signed GO is recorded.

Until then, status remains **proposed / blocked pending authorisation**.

# Financial Engine Executable Acceptance Test Plan

**Status:** proposed test plan and synthetic test vectors. Documentation only; no executable tests were added or run by this document.
**Applies to:** future authorised financial calculation engine for the initial contract × site × service-period workflow.
**Test data:** synthetic only.
**Release status:** all cases below are NOT RUN unless an execution record is separately attached to a named commit and environment.

## 1. Purpose and test philosophy

This plan converts the Financial Data Contract, Core Calculation Specification and Synthetic Financial Test Oracle into an executable acceptance suite. It defines what must be tested, how to avoid false positives, and what evidence constitutes a pass.

A passing unit test is necessary but not sufficient. Financial acceptance also requires independent expected-result review, source reconciliation, tenant/role controls, reproducibility, and qualified review of the underlying accounting/tax assumptions.

### Required test layers

| Layer | Purpose | Minimum evidence |
|---|---|---|
| Parser unit tests | Validate source text into typed values | Exact input/output and held reasons |
| Decimal unit tests | Validate exact arithmetic and rounding | Exact decimal strings |
| Domain unit tests | Payroll, matching, variation and contribution rules | Expected outputs and state transitions |
| Property tests | Validate invariants across generated inputs | Seed, generator version, failing case |
| Integration tests | Persistence, API, tenant and role boundaries | Named DB/runtime and request/response evidence |
| Regression tests | Preserve prior approved outcomes | Baseline fixture version and diff |
| Independent review | Challenge expected values and policy | Reviewer sign-off and issue log |

## 2. Test fixture envelope

Every executable fixture must include:
- fixture_id and fixture_version;
- synthetic tenant_id, source_system_id, contract_id, contract_version_id, site_id and service_period_id;
- source file checksum, row count and source control totals;
- raw source amount strings and declared locale;
- currency, tax basis, source precision and date/timezone;
- expected parsed values and held exceptions;
- method, mapping, tax and rounding policy versions;
- expected exact decimal outputs as strings;
- expected status and audit events;
- expected source lineage for each output;
- independent reviewer and review date.

No fixture should depend on implicit defaults. Every omitted/unknown value must be intentional and asserted.

## 3. Decimal parsing and arithmetic suite

### DEC-001 — canonical decimal parsing
Input: `"1234.50"`, declared dot-decimal format, AUD.
Expected: valid decimal string `"1234.50"`, scale 2, AUD retained.

### DEC-002 — thousands separator
Input: `"1,234.50"`, declared en-AU format.
Expected: valid canonical `"1234.50"`. Same text without declared locale/format must be held as ambiguous.

### DEC-003 — ambiguous separator
Input: `"1.234"`, no declared source locale.
Expected: HELD; no numeric value is emitted for authoritative calculations.

### DEC-004 — malformed numeric
Inputs: `"1,2x.00"`, `"--5.00"`, `"NaN"`, `"Infinity"`.
Expected: HELD or REJECTED according to parser contract; never coerced to zero.

### DEC-005 — zero versus null
Inputs: literal `"0.00"` and missing amount.
Expected: first is VALID zero; second is UNKNOWN/null.

### DEC-006 — positive half-cent policy vector
Inputs: `"1.004"`, `"1.005"`, `"1.006"`.
Expected: under an explicitly selected HALF_UP-to-2-decimals test policy: `"1.00"`, `"1.01"`, `"1.01"`.

### DEC-007 — negative half-cent policy vector
Input: `"-1.005"`.
Expected: under the same HALF_UP policy: `"-1.01"`. This test must specifically catch asymmetric language-native rounding.

### DEC-008 — line versus total rounding
Input: two synthetic exact line amounts `"0.005"` and `"0.005"`.
Expected: fixture must declare whether rounding occurs per line or after aggregation. Under HALF_UP at line level the total of rounded lines is `"0.02"`; under aggregate-then-round the total is `"0.01"`. Both are mathematically distinct policies; only the approved workflow policy may be used.

### DEC-009 — negative credit
Input: `"-110.00"` linked to a credit note.
Expected: sign preserved; no absolute-value conversion.

### DEC-010 — precision and bounds
Test maximum supported amount, maximum source scale, excess scale, overflow, underflow and exponent notation.
Expected: accepted values are exact; out-of-contract values are held/rejected with explicit reason.

### DEC-011 — no binary float boundary
Run every arithmetic test using canonical decimal strings from parser through persistence, API and export.
Expected: no conversion to JS Number for authoritative money at any boundary.

### DEC-012 — deterministic serialization
Repeat same operation with different source row ordering.
Expected: exact same decimal output string and same logical lineage set.

## 4. GST and currency suite

### TAX-001 — declared GST-exclusive
Input 100.00, AUD, GST_EXCLUSIVE, declared 10% fixture rate.
Expected: ex-GST 100.00, GST 10.00, inc-GST 110.00.

### TAX-002 — declared GST-inclusive
Input 110.00, AUD, GST_INCLUSIVE, declared 10% fixture rate.
Expected: ex-GST 100.00, GST 10.00, inc-GST 110.00.

### TAX-003 — no GST
Input 100.00, AUD, NO_GST.
Expected: tax 0.00 and total 100.00, only where no-GST classification is supported by source/policy.

### TAX-004 — unknown tax basis
Input 100.00, tax basis UNKNOWN.
Expected: retained as source value but excluded/held from tax-sensitive aggregation; no assumed conversion.

### TAX-005 — unlike tax basis
Aggregate one GST-inclusive and one GST-exclusive amount.
Expected: block aggregation until a reviewed, versioned conversion is applied.

### TAX-006 — unlike currency
Aggregate AUD 100.00 and NZD 100.00.
Expected: block aggregation. No implied parity conversion.

### TAX-007 — FX conversion provenance
Input with explicit synthetic rate, rate source, base/quote, direction, effective timestamp, retrieval timestamp, method and reviewer.
Expected: conversion output traces all metadata and retains original amounts. Missing any mandatory rate metadata blocks conversion.

## 5. Payroll allocation suite

### PAY-001 — full reconciliation
Pool AUD 10,000.00; direct 5,000.00; approved allocation 2,000.00; non-site 1,000.00; residual 2,000.00; excluded 0.00.
Expected: exact reconciliation; each bucket distinct.

### PAY-002 — over-allocation
Pool 100.00; source row eligible 50.00; two allocations 30.00 and 20.01 against that row.
Expected: hold allocation run; identify source row and 0.01 excess.

### PAY-003 — duplicate source-row assignment
Same source row appears twice with allocations that double-count its eligible amount.
Expected: block or hold; no double counting.

### PAY-004 — pending allocation
Allocation suggestion exists but has no authorised reviewer decision.
Expected: candidate not included in approved site allocation.

### PAY-005 — invalid approver role
User without required reviewer role attempts approval.
Expected: deny server-side; audit event recorded without disclosing sensitive row payload.

### PAY-006 — residual preservation
Pool 1,000.00, supported buckets total 870.00.
Expected: residual 130.00, not spread across sites.

### PAY-007 — source control total mismatch
Parsed payroll rows do not reconcile to authoritative export total.
Expected: run status unreconciled/held; report expected, parsed, accepted, held and excluded totals.

### PAY-008 — incomplete period
Missing final payroll export for pay period.
Expected: INCOMPLETE; no definitive complete-period comparison.

### PAY-009 — allocation restatement
Previously confirmed run corrected by a new mapping.
Expected: new immutable run, prior run retained, actor/reason/time and changed values linked.

## 6. Invoice matching suite

### INV-001 — amount-only
Same amount but missing customer/contract/site/period identity.
Expected: no high-confidence or confirmed match.

### INV-002 — full evidence candidate
Customer, contract, site, service period, amount, currency and tax basis align.
Expected: candidate with evidence references; human confirmation still required.

### INV-003 — competing contracts
Same invoice line plausibly maps to two active contracts.
Expected: conflict state; no automatic confirmation.

### INV-004 — duplicate invoice
Same invoice reference/source row replayed.
Expected: duplicate detected and preserved; not silently counted twice.

### INV-005 — partial match
Only some invoice lines have sufficient evidence.
Expected: confirmed coverage numerator includes only eligible human-confirmed lines with medium/high evidence.

### INV-006 — credit note linkage
Invoice and credit retained as separate linked source records.
Expected: gross, credit and net are separately traceable.

### INV-007 — service period mismatch
Invoice date falls outside the contract service period.
Expected: period conflict visible; no automatic high-confidence result.

### INV-008 — permission boundary
Unauthorised role attempts to confirm match.
Expected: deny server-side; append audit event.

### INV-009 — denominator policy
Test eligible invoice denominator with exclusions, credit notes, duplicate candidates and cancelled lines.
Expected: denominator matches the versioned eligibility policy; every exclusion has a reason and source reference.

## 7. Contribution and variation suite

### CON-001 — complete contribution
Revenue 18,000.00 ex-GST; included site delivery costs 9,000.00 ex-GST.
Expected: management contribution 9,000.00 and ratio 50.00%, with non-site and residual separately disclosed.

### CON-002 — missing revenue
Revenue source missing.
Expected: contribution unavailable, not zero.

### CON-003 — missing material cost category
A material supplier-cost source is missing.
Expected: incomplete status and visible coverage; no definitive contribution/margin claim.

### CON-004 — mixed currency or tax basis
Expected: block aggregate absent approved conversion.

### CON-005 — unallocated residual
Expected: separately disclosed; no silent site allocation.

### VAR-001 — requested variation
No authorised approval.
Expected: candidate only; zero approved variation value.

### VAR-002 — observed extra work
Evidence exists but no approval.
Expected: preserve observation; not billable solely because work occurred.

### VAR-003 — approval
Authorised approver, approved scope and price, effective date and evidence all present.
Expected: approved value enters the applicable versioned view.

### VAR-004 — retrospective approval
Expected: retain event time and approval time separately; never rewrite history.

### VAR-005 — rejected variation
Expected: retained with reason and excluded from approved value.

## 8. Import, idempotency and provenance suite

### IMP-001 — exact replay
Same file checksum, tenant and import scope replayed.
Expected: idempotent; no duplicate facts or cost.

### IMP-002 — same filename, changed checksum
Expected: new source version and reconciliation requirement; filename not identity.

### IMP-003 — row-count control
Source row count differs from accepted + held + explicitly excluded rows.
Expected: import not marked reconciled.

### IMP-004 — monetary control
Source total differs from parsed/accepted/held/excluded totals.
Expected: explicit unreconciled difference; no silent acceptance.

### IMP-005 — unknown site alias
Expected: unresolved mapping; no fuzzy auto-merge.

### IMP-006 — timezone boundary
Source timestamp and service period cross UTC/local date boundary.
Expected: local service period semantics preserved; no unnoticed period reassignment.

### IMP-007 — formula injection export
Text begins with spreadsheet formula control characters.
Expected: safe export encoding while raw source remains protected.

## 9. Property-based invariants

Property-based tests should generate deterministic synthetic datasets with recorded seeds. They must not use customer data.

| ID | Invariant | Expected property |
|---|---|---|
| PROP-001 | Payroll reconciliation | Sum of all mutually exclusive buckets equals authoritative pool exactly |
| PROP-002 | Source row cap | Sum of allocations per source row never exceeds eligible row amount |
| PROP-003 | Determinism | Permuting input rows leaves output values unchanged |
| PROP-004 | Idempotency | Replaying an identical import leaves logical totals unchanged |
| PROP-005 | Null preservation | Unknown inputs never become zero |
| PROP-006 | Candidate isolation | Adding unconfirmed candidates does not change confirmed totals |
| PROP-007 | Variation authority | Unapproved variation never increases approved/billable value |
| PROP-008 | Currency safety | Mixed currency aggregation is rejected absent explicit conversion |
| PROP-009 | Tax-basis safety | Unlike/unknown tax basis is never silently combined |
| PROP-010 | Restatement immutability | New run does not mutate prior output |
| PROP-011 | Provenance closure | Every output amount can be traced to included source records and policy versions |
| PROP-012 | Rounding determinism | Same exact decimal inputs and policy always produce same exact output |
| PROP-013 | Sign preservation | Credits/refunds retain their sign through all transformations |
| PROP-014 | Exclusion accounting | Every excluded source amount remains accounted for in control totals |

For every property failure, retain seed, minimal failing input, expected invariant, actual result, runtime, engine commit and issue ID.

## 10. Metamorphic and adversarial tests

- Permute input row order and verify identical totals.
- Split one source line into two equivalent lines where the business policy says aggregation should be invariant; explicitly document cases where per-line rounding makes it non-invariant.
- Add an unrelated tenant's records and prove no output or lookup changes for the first tenant.
- Add a duplicate import and prove no duplicate contribution.
- Change only tax basis and prove incompatible aggregation becomes blocked.
- Change only approval state from pending to confirmed and verify only the authorised transition changes confirmed totals.
- Remove one required source file and verify incomplete state, not a zero-filled result.
- Change parser/mapping version and verify a new calculation run/restatement.
- Fuzz malformed numeric text, oversized amounts, negative values and date/time boundaries.
- Test concurrent confirmation attempts to prevent double approval or duplicate posting.

## 11. Exit criteria

Financial calculation acceptance is blocked until all of the following are true:

1. All mandatory deterministic cases pass on a named commit.
2. Property-based suite passes with retained seeds and a documented run count.
3. No unresolved Critical or High severity financial calculation defects remain.
4. Payroll and invoice control totals reconcile exactly under the approved policy.
5. All expected results receive independent reviewer approval.
6. Currency, tax basis, rounding, parsing and contribution policies have named approvers.
7. Tenant isolation and role-authority integration tests pass.
8. Restatement and audit history tests pass.
9. CI evidence identifies commit SHA, runtime, environment and full job result.
10. Qualified finance/accounting review signs off the scope and limitations.
11. Privacy/security/legal and pilot gates are separately satisfied before any real customer data or production use.

A green unit-test suite alone does not pass these exit criteria.

## 12. Execution evidence template

| Field | Required value |
|---|---|
| Test run ID | Unique opaque ID |
| Engine commit SHA | Exact commit |
| Fixture bundle version | Version/hash |
| Runtime/dependencies | Exact versions |
| Environment | CI/test environment identifier |
| Test count | Executed count |
| Passed/failed/skipped | Counts |
| Failed case IDs | Exact IDs |
| Property seeds | All seeds |
| Source reconciliation | Expected/actual totals |
| Reviewer | Named reviewer |
| Date/time | Timestamp and timezone |
| Defect references | Issue IDs |
| Result | PASS / FAIL / BLOCKED / NOT RUN |

Do not populate this template with assumed results. Only the test runner and reviewer can provide execution evidence.

 
## 13. Targeted automated execution evidence — 17 November 2026

The hardening branch adds a deterministic property subset and exact-money regression tests. CI run **#43982827602** on exact implementation head `ead10a236e33684c25c5c7613d1c5a2fbeb883fd` passed:
- Node.js 22: 59 total, 56 passed, 0 failed, 3 skipped. The skips include the PostgreSQL-dependent API and TLS integration tests in the standalone Node job; those execute in the PostgreSQL job.
- PostgreSQL 16: migrations through 013, tenant/FK catalogue audit across 20 protected/root tables, restricted-role RLS checks, authenticated API integration, production image build, real TLS trust/invalid-CA tests and production-mode API health check all passed.
- Property subset: 500 seeded payroll bucket reconciliation cases (seed `0x5eed1234`), aggregation row-order invariance, null/sign preservation and mixed currency/tax-basis blocking passed.

This is a targeted subset only. The complete DEC/TAX/PAY/PAYLED/INV/CON/VAR/IMP and property-based acceptance plan remains **NOT COMPLETE**. Locale parsing, approved rounding, GST/FX, full payroll restatement, invoice denominator/credit handling, variation lifecycle, source control totals, timezone and export injection cases remain unimplemented or not fully tested. Independent expected-value review and qualified accounting/payroll/tax approval are still required.

 
### Follow-up CI run #43983962328 — migration 014 and reviewer decision integrity

CI run **#43983962328** passed on exact hardening head `6b98299006d9aa620f494ec4fe52d095e82947c4`:
- Node.js 22: 59 tests, 56 passed, 0 failed, 3 skipped. The three skipped tests are database-dependent API/TLS integration tests in the standalone Node job; they ran in the PostgreSQL job.
- PostgreSQL 16: migrations through 014; 20-table tenant/FK catalogue audit; restricted-role RLS; authenticated API integration; production image build; trusted-CA TLS success; untrusted-CA rejection; production-mode API database health success.
- Reviewer decision tests now prove signed actor binding, immutable evidence, final-state immutability, mandatory audit reason and same-transaction audit-event creation for both direct SQL and the API.

The complete deterministic/property acceptance plan remains NOT COMPLETE and still requires the policy-dependent and domain cases enumerated above, independent expected-value review and qualified finance/payroll/tax approval.

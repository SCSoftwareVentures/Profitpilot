# ProfitPilot — API Calculation Path Static Audit

**Review date:** 16 November 2026  
**Reviewed ref:** PR #25 security branch, head 17178768002b978d6f5bd76f0192b2bbff7a4355  
**Files inspected:** server/index.js, src/engine.js, database/schema.sql, tests/tenant-isolation.catalog.sql and the financial-engine specifications  
**Method:** static source review through repository files; no code was modified and no new test was executed  
**Status:** findings require engineering confirmation and remediation after G5

## 1. Executive conclusion

The current calculation endpoint is not ready to provide an authoritative financial result. It includes useful defensive checks—confirmed invoice matches, confirmed site allocations, period-overlap rejection, currency/tax-basis checks, a management-contribution disclaimer and an incomplete marker—but those controls do not cure the structural defects below.

**Release recommendation: do not expose the calculation route as a dependable financial result until the critical issues are closed.**

## 2. Findings

### API-CALC-01 — Referenced allocation_lines table is absent from reviewed schema

**Severity: Critical**

The calculation route in server/index.js joins allocation_lines for confirmed payroll allocation and site amount selection. The reviewed database/schema.sql defines allocation_runs but does not define allocation_lines, and the PR #25 changed-file list does not include a migration creating the row-level ledger.

**Impact:** the calculation path has an unresolved schema dependency. Green CI does not prove this route works if the test suite does not execute it against a schema containing that table.

**Closure:** define the complete source-row allocation ledger from PAYLED design; add migration, tenant-scoped keys, indexes, row caps, RLS, runtime grants, immutable decision history and authenticated route tests. Do not add a superficial table just to satisfy the SQL join.

### API-CALC-02 — Money crosses the JavaScript Number boundary

**Severity: Critical**

The endpoint reads numeric database aggregates and converts revenue and cost to JavaScript Number before subtraction. The result is passed through the money helper and returned in the output. This is an authoritative API path and conflicts with the exact-decimal requirement.

The engine utility uses BigInt to derive integer cents in some paths, but converts cents back to Number for outward values. Invoice validation parses raw amount text with Number. Those boundaries must be reviewed as part of the same remediation; adding a decimal helper is not enough if routes, parsers or serializers convert back to binary floating point.

**Impact:** exactness, scale, rounding, negative midpoint behaviour and deterministic serialization cannot be guaranteed end to end.

**Closure:** adopt an approved decimal abstraction; retain source decimal text; serialize monetary results as canonical decimal strings; use NUMERIC with owner-approved precision/scale; prohibit Number conversion for authoritative monetary data; test parser-to-database-to-domain-to-API-to-export.

### API-CALC-03 — Contribution is emitted while calculation is marked incomplete

**Severity: Critical**

The route saves a calculation with completeness set to incomplete, but the output object still contains contribution and margin values. The endpoint requires at least one confirmed invoice line and one confirmed allocation line, then builds an arithmetic result. The presence of one or more rows is not proof that all material revenue and cost categories are complete.

The output's limitations correctly state that other delivery costs, non-site costs and unallocated payroll may be excluded. However, returning a contribution and margin alongside incomplete status creates a presentation risk if a consumer uses the amount without enforcing the status.

**Closure:** implement a versioned completeness policy with required sources, categories, period coverage, eligibility and materiality rules. When material inputs are missing, return an unavailable/incomplete value state and explicit coverage; do not provide a definitive contribution/margin scalar. If a partial diagnostic amount is retained for internal review, name and label it as partial, suppress headline presentation, and test that every client/export respects this rule.

### API-CALC-04 — Invoice issue date is used as service-period selection

**Severity: High**

The current revenue query filters customer invoice rows using invoices.invoice_date between the requested period dates. The match-review data model has service-period fields, but the query does not use those fields to establish period attribution.

**Impact:** invoice issue date and service delivery period are not interchangeable. A late-issued invoice, advance invoice, credit note or invoice covering multiple service periods can be attributed to the wrong reporting period if invoice date is used as a proxy.

**Closure:** define the revenue-period policy with a finance/domain owner. Prefer confirmed service-period mapping to select contract/site economics; model invoice issue date, invoice service period, payment date and accounting period separately. Handle multi-period invoices and credit allocation explicitly. Add tests for late, advance, multi-period and backdated invoices.

### API-CALC-05 — Contract baseline tax-basis compatibility is not fully represented

**Severity: High**

The reviewed contract_versions schema records price and currency but does not carry the full explicit tax-basis metadata required by the financial data contract. The calculation route checks that the selected invoice rows have one currency/tax basis and compares invoice currency to contract currency, but the reviewed baseline does not provide a tax-basis value to compare against.

**Impact:** a uniform invoice tax basis is not necessarily compatible with the commercial baseline. A cardinality count of one does not prove the underlying amounts share an approved GST treatment.

**Closure:** add explicit, versioned tax basis and applicable tax policy to the contract baseline; distinguish source tax basis from reporting/comparison basis; block incompatible aggregation without a reviewed conversion and provenance.

### API-CALC-06 — Current row existence checks are not completeness checks

**Severity: High**

The endpoint requires a non-zero count of confirmed invoice lines and allocation lines. This validates that some data exists, not that the requested service period is covered by every material source or that the selected records are the complete eligible set.

**Impact:** partial but non-empty datasets may appear calculated. Period overlap rejection is a useful safeguard but does not prove completeness across payroll runs, invoice sources, supplier costs, non-site costs or adjustments.

**Closure:** create a source-coverage contract with expected period boundaries, source manifests, row counts, missing-category rules, reconciliation status and explicit exclusions. The result's completeness state must be derived from those controls, not from row count alone.

### API-CALC-07 — Match evidence is narrower than the product contract

**Severity: High**

The engine's current match helper uses site identity, a date within the contract period and amount validity as evidence dimensions. It does require human confirmation, which is correct, but the evidence model does not establish customer identity, contract identity, service-period linkage, currency, GST basis, duplicate/invoice-line conflicts or source lineage.

**Impact:** the confidence label can overstate what is actually evidenced and the match record may not support the denominator and traceability rules.

**Closure:** use the multi-dimensional evidence model in INV-001–009. Separate raw candidate evidence, confidence policy and final human decision. Require an eligible-denominator policy before reporting coverage.

### API-CALC-08 — Prototype allocation helper is aggregate-oriented

**Severity: Critical for payroll attribution**

The helper validates aggregate direct, approved, non-site and excluded values and derives a residual. It does not itself implement the proposed per-source-row ledger, row-level caps, source-row identity, reviewer evidence, duplicate line controls, concurrency or immutable decision events.

**Impact:** a pool total may reconcile while the underlying source rows are duplicated, misattributed or over-allocated.

**Closure:** implement the row-level PAYLED domain model and acceptance suite only after named payroll/finance policy owners approve included components, exclusions, negative values and allocation methods.

## 3. Positive controls observed

These controls are useful foundations and should be preserved during remediation:

- The route selects a contract version and blocks overlapping/ambiguous versions.
- It only sums invoice lines associated with confirmed match decisions.
- It only sums confirmed site allocation records.
- It rejects confirmed payroll periods that overlap only part of the requested service period rather than silently prorating.
- It checks invoice currency against the selected contract currency and blocks unknown or mixed invoice tax/currency values.
- It stores a calculation run and an audit event.
- The output explicitly says management contribution is not statutory or audited profit.
- The identity/tenant security branch contains a catalog-driven RLS and tenant-FK audit, plus authenticated API and container CI.

These positive controls do not mean the full workflow is accepted. Every check must be exercised on a combined candidate and tied to source-complete financial fixtures.

## 4. Required route acceptance tests

| Test ID | Scenario | Expected result |
|---|---|---|
| API-CALC-T01 | Calculation invoked on freshly migrated schema | All referenced tables and columns exist; no undefined allocation_lines |
| API-CALC-T02 | Revenue and cost with decimal fractions and negative credits | Exact decimal strings; no Number conversion |
| API-CALC-T03 | A period has one confirmed invoice but is missing the final invoice source | INCOMPLETE; no definitive contribution/margin |
| API-CALC-T04 | Invoice issue date differs from confirmed service period | Assigned using approved service-period policy, not invoice date shortcut |
| API-CALC-T05 | Invoice tax basis differs from contract version basis | Held until explicit approved conversion |
| API-CALC-T06 | Late, advance and multi-period invoice lines | Correct service-period assignment and traceable split policy |
| API-CALC-T07 | A source payroll period partially overlaps target service period | Blocked or handled by an approved, versioned policy; never silently prorated |
| API-CALC-T08 | Payroll row is allocated twice or beyond eligible amount | Confirmation denied and source row identified |
| API-CALC-T09 | Non-site and unallocated payroll categories are missing | Result completeness reflects missing material inputs |
| API-CALC-T10 | Duplicate request/retry and concurrent calculation creation | Idempotent output or explicit conflict; no duplicate financial events |
| API-CALC-T11 | Calculation restated after source/mapping/policy correction | New immutable run; previous output retained |
| API-CALC-T12 | Tenant A requests Tenant B contract/site/source/run identifiers | Deny without data leakage; audit denial safely |
| API-CALC-T13 | User without reviewer role attempts match/allocation confirmation | Server-side denial and safe audit event |
| API-CALC-T14 | Currency mismatch, unknown tax basis or missing source manifest | Held/unavailable result; no implicit default |

Every test above is **PROPOSED / NOT RUN**. The current CI result must not be described as passing this suite.

## 5. Remediation dependency order

1. Obtain G5 signed GO and name technical, financial/payroll, privacy/legal and security owners.
2. Resolve source-period, revenue basis, payroll inclusions, GST, currency, precision and rounding policies.
3. Approve source-row payroll ledger and invoice evidence/decision domain models.
4. Resolve schema/API mismatch and tenant-safe keys/grants/RLS.
5. Implement decimal-safe parsing and calculation end to end.
6. Implement source completeness and service-period matching.
7. Add the API calculation test suite above and the DEC/TAX/PAY/PAYLED/INV/CON/VAR/IMP tests.
8. Run on one combined, reviewed commit; obtain independent accounting and security review.

No application code, SQL, migrations, live data or production changes are authorised by this audit. Synthetic test data only.

## 6. Security-branch implementation update — 17 November 2026

The static findings above describe the earlier reviewed API/schema state. PR #25 has since advanced independently to head `ce66bcf6f9a705532313ce6e71892839a3b55344`, which passed CI run #43971209376. On that separate branch:

- Migration 010 now supplies a tenant-scoped immutable payroll source-row ledger and append-only source-linked allocation lines, with per-row over-allocation protection.
- Migration 011 enforces source/pool totals, currency, reviewer authority, per-row completeness, summary reconciliation, zero residual, source-linked line totals and immutable confirmed runs.
- Payroll source-row inserts are constrained to raw evidence from the same tenant's payroll import batch as the pool.
- The API intentionally blocks payroll row ingestion; the normalizer is a pure helper only. There is no complete privacy-safe payroll parser/import, allocation-review or reviewer-confirmation API.
- The calculation route now uses the migrated allocation ledger and cent-based decimal arithmetic for the calculation output, rejects partial confirmed payroll and invoice service-period overlaps, and stores the result as incomplete with contribution/margin withheld.

This is not closure of the proposed API-CALC suite. The contract tax-basis model, full source completeness and reconciliation, other cost categories, credits/reversals, restatement/idempotency, complete payroll workflow and the API-CALC-T01–T14 acceptance tests remain unproven or incomplete. The PR #25 and PR #26 branches have not been combined or merged. Do not treat the PR #25 CI pass as execution of the proposed financial acceptance suite.



## 7. Contract tax basis and aggregation follow-up — 17 November 2026

PR #25 now adds `contract_versions.tax_basis` (migration 012; legacy default `unknown`). The calculation route requires the confirmed invoice tax basis to be singular, known, in the contract currency and equal to the effective approved contract version's tax basis. Unknown or mismatched basis blocks the calculation. The pure prototype aggregation helper also refuses to combine records when currency, tax basis or reporting-period metadata is mixed or incomplete.

PR #25 head `ff354de4418b4d471ca0e8cd881af4f9acf5ef78` passed CI run #43973502209. This does not close the remaining financial acceptance gaps: full revenue/source completeness, credit notes and reversals, restatement, source manifests, customer/contract identity mapping from actual invoice imports, full payroll mapping/allocation/reviewer workflow, other cost categories, and API-CALC-T01–T14 remain unproven or incomplete. The PR #25/#26 combined candidate has not been tested.


## 8. Payroll currency alignment and negative API regression — 17 November 2026

The calculation route now checks payroll allocation currency as well as invoice currency against the effective contract version. It rejects mixed payroll currencies and any payroll currency that differs from the contract currency. A synthetic API integration fixture creates a valid source-row payroll pool and confirmed site allocation in USD against an AUD contract, then verifies the calculation is blocked. A separate complete synthetic fixture verifies invoice GST-basis mismatch is also blocked.

PR #25 head `ce168020eb49667616e5c36f1cc9b324f92c22b5` passed CI run #43974141222. These are targeted negative integration cases, not the complete calculation acceptance suite, accounting policy approval or independent audit.


## 9. Combined-candidate source review — PR #27, 17 November 2026

**Reviewed ref:** combined PR #27 head `47f0a5c3dc5a1e4f85b565b27195e5d217195c0a`.  
**Method:** static inspection of `server/index.js`, `src/engine.js`, database schema/migrations and the current integration/unit tests; CI job evidence checked separately. This is not independent accounting validation.

The earlier findings API-CALC-01 and API-CALC-02 are superseded for this combined candidate in the following limited sense:

- Migration 010 creates the tenant-scoped `payroll_source_rows` table and links append-only `allocation_lines` to source-row provenance. Migration 011 adds confirmation-time integrity checks. The calculation query now joins the migrated allocation ledger rather than relying on a nonexistent table.
- The calculation route parses database decimal text into integer BigInt cents and formats the difference back to canonical decimal text. Invoice validation uses strict decimal syntax. Cardinality fields are converted to Number only for row counts, not monetary arithmetic.
- The route does not emit a definitive contribution or margin while its model is incomplete: `contribution` and `marginPercent` are null; the separately named `indicativeContribution` is explicitly limited and accompanied by incompleteness/limitations metadata.
- Migration 012 supplies contract-version tax-basis metadata; calculation blocks unknown or mismatched invoice tax basis. Integration tests cover targeted tax-basis and payroll-currency mismatch negatives.

### Remaining calculation/payroll acceptance gaps

1. **Payroll normalization exactness:** `normalizePayrollRows` currently accepts a finite JavaScript-number `amount` as well as a string. Converting an already-rounded binary floating-point value to text cannot recover the original source decimal. Before enabling ingestion, accept only canonical source decimal strings and test rejection of numeric inputs, exponent notation, unsafe magnitudes and malformed values.
2. **Payroll workflow:** the normalizer is a pure helper. There is no complete privacy-safe payroll upload/parse/mapping/review/allocation/confirmation API. Payroll ingestion remains disabled.
3. **Completeness:** requiring at least one confirmed invoice line and one confirmed payroll allocation line is not a source manifest or proof that all eligible revenue and cost categories are present. The current output correctly labels itself incomplete and withholds headline contribution/margin, but a versioned source-coverage policy and explicit expected-source reconciliation are still needed.
4. **Accounting policy:** tax basis, GST treatment, rounding, credits/reversals, FX conversion, service-period attribution and payroll inclusion policy require named qualified approval. Migration metadata is not a substitute for that approval.
5. **Acceptance evidence:** targeted authenticated API regression cases and the configured Node/PostgreSQL CI pass do not execute the full API-CALC-T01–T14 set or the broader DEC/TAX/PAY/PAYLED/INV/CON/VAR/IMP and property-based suites. Those remain NOT RUN as a complete suite.

Do not represent the calculation output as audited profit, complete margin, tax advice or payroll processing. Keep payroll ingestion disabled and preserve the G5/release gate.

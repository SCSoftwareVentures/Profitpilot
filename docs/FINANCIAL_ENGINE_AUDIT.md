# Financial Engine Audit — Prototype Findings

**Audit target:** current `main` branch prototype at the time of review.
**Files reviewed:** `src/engine.js`, `tests/engine.test.js`, `docs/CORE_CALCULATION_SPEC.md`, and `docs/SYNTHETIC_FINANCIAL_TEST_ORACLE.md`.
**Status:** static code review only. No local execution, runtime test, production data test or independent accounting review was performed for this audit.
**Classification:** findings describe code paths and risks visible in the reviewed source; they are not claims of an observed production loss.

## Executive assessment

The current engine is explicitly labelled demo logic and says not to use real payroll/customer data. That warning is appropriate. It is not yet a reliable financial calculation engine.

The highest-priority issues are:
1. Money arithmetic uses JavaScript binary floating-point and `Math.round`, not decimal arithmetic or integer minor units.
2. Payroll allocation accepts unstructured numeric inputs and does not preserve source-row-level allocation provenance or enforce per-source-row allocation caps.
3. Invoice matching can label a candidate MEDIUM on site/date/positive-amount checks alone, without explicit contract identity or amount reconciliation evidence.
4. Current tests cover basic examples but do not cover the financial golden fixtures, rounding boundaries, currency/tax basis, null semantics, duplicate import idempotency, restatements or allocation provenance.

Do not use the current engine to produce customer-facing financial figures until these findings are resolved and independently tested.

## Findings

### FE-01 — Floating-point rounding is not a safe financial primitive

**Severity:** Critical for financial release; high implementation priority.

**Code:** `src/engine.js`, `money`.

Current implementation:
```js
export const money = value => Math.round((Number(value) + Number.EPSILON) * 100) / 100;
```

This converts values to binary floating-point, adds a fixed epsilon, and applies `Math.round`. This does not implement a documented decimal rounding policy such as decimal ROUND_HALF_UP for positive and negative values. A fixed epsilon is not a general correction for binary floating-point representation, and JavaScript `Math.round` has asymmetric tie behaviour for negative values.

**Reproduction by language semantics:** `Math.round(-1.5)` returns `-1`; therefore a negative half-cent case represented at the scaled value can round toward positive infinity rather than away from zero. The fixture's declared expected result for `-1.005` is `-1.01`, but the current implementation is not a valid general implementation of that rule.

**Required remediation:**
- Adopt a vetted decimal arithmetic library or integer minor-unit model with explicit handling of source precision and intermediate precision.
- Define rounding mode and exact rounding boundaries for line, tax, invoice and aggregate calculations.
- Reject malformed/non-finite values; do not silently coerce arbitrary inputs with `Number()`.
- Add positive and negative tie cases, very large values, tiny values, and cumulative line-vs-total cases.
- Keep original source amount and parsed decimal representation for audit traceability.

### FE-02 — Payroll allocation is aggregate-only and lacks source-row controls

**Severity:** High.

**Code:** `src/engine.js`, `allocatePayroll`.

The function accepts arrays of objects containing `site` and `amount`, sums their amounts, and checks the aggregate residual. It does not require stable source-row identifiers, verify that each source row is allocated at most once, enforce allocation fractions summing to no more than 100%, or prove that approved allocations have a reviewer/method/evidence record. It therefore cannot itself establish the source-row-level invariants required by the core specification.

The function also converts inputs with `Number()` and rounds bucket totals after summation. That means malformed, locale-ambiguous or high-precision source values are not reliably held with a traceable parse error.

**Required remediation:**
- Separate parsing/validation from allocation calculation.
- Require source batch, row ID, currency, tax basis, period and original amount.
- Require explicit allocation decision ID, method version, reviewer, evidence reference and approval timestamp for approved allocations.
- Enforce per-source-row allocation caps and detect duplicate source-row allocations.
- Keep non-site, excluded and unallocated buckets separate and reconcile exactly to the authoritative pool under the declared precision.
- Return held errors with source references instead of only a generic error list.

### FE-03 — Invoice match confidence can overstate available evidence

**Severity:** High.

**Code:** `src/engine.js`, `matchInvoice`.

The function checks only whether the row's site equals the contract's site, whether its date is inside the contract period, and whether the amount is positive. When all three are true it labels the candidate `MEDIUM`. It does not check explicit contract identity, service type/period mapping beyond date range, tax basis/currency compatibility, amount reconciliation against expected invoice/contract evidence, or conflicting candidate matches.

Human confirmation is required, which is correct, but a MEDIUM evidence label is still misleading if the required evidence dimensions are not present.

**Required remediation:**
- Return evidence dimensions individually and default to insufficient/low until the complete evidence model is satisfied.
- Require explicit contract identity and service-period mapping, not merely a date inside a broad contract period.
- Record currency and tax basis compatibility.
- Detect competing contract/site candidates and duplicate invoice references.
- Separate evidence quality from match status; a score must never be interpreted as probability unless calibrated.
- Ensure only a human-confirmed medium/high match enters the coverage numerator.

### FE-04 — Numeric coercion and amount parsing are too permissive

**Severity:** High.

**Code:** `src/engine.js`, `validateInvoiceRows`, `allocatePayroll`, `matchInvoice`.

JavaScript `Number()` accepts representations beyond a controlled financial input grammar (for example, hexadecimal strings). The engine has no declared locale, decimal separator, thousands separator, currency or tax-basis parser. It cannot reliably distinguish ambiguous values such as `1.234` across locales.

**Required remediation:**
- Define supported source formats per import mapping and require explicit locale/number format.
- Reject ambiguous and malformed values into a held state with the source row and reason.
- Preserve zero separately from missing/null and from malformed values.
- Never silently infer currency or GST treatment.

### FE-05 — Contribution aggregation lacks required financial basis metadata

**Severity:** High.

**Code:** `src/engine.js`, `summariseContracts`, `aggregateMetrics`.

The current functions sum numeric `revenue` and `cost` fields and calculate contribution/margin. They do not enforce common currency, GST basis, calculation period, revenue eligibility, completeness, cost inclusion policy or allocation version. A zero revenue value produces a null margin, but there is no completeness state or explanation for why the result is unavailable.

**Required remediation:**
- Accept only validated typed monetary values with currency, tax basis, period and source lineage.
- Block mixed-currency and unlike-tax-basis aggregation without an explicit reviewed transformation.
- Require explicit revenue/cost inclusion policy and calculation version.
- Return incomplete/unavailable states when material inputs are missing.
- Keep non-site and unallocated items separately disclosed; do not silently distribute them.
- Label output management contribution only, never net/statutory/audited profit.

### FE-06 — Current automated tests do not exercise the financial acceptance contract

**Severity:** High.

**Code:** `tests/engine.test.js`.

Existing tests cover basic rounding, CSV parsing, invoice row validation, aggregate payroll reconciliation, simple candidate matching and contribution aggregation. They do not yet execute the worked cases in the synthetic financial oracle.

Missing coverage includes:
- Positive and negative decimal half-cent boundaries.
- Exact GST-inclusive/exclusive/no-GST conversions and unknown tax basis.
- Different currencies and blocked aggregation.
- Per-row payroll over-allocation, duplicate allocation and source provenance.
- Null versus zero and malformed/locale-ambiguous numbers.
- Invoice credits, duplicate candidates and eligibility denominator rules.
- Contract identity conflicts and competing match candidates.
- Candidate/approved variation authority.
- Incomplete service periods.
- Historical restatement immutability.
- Determinism under row reordering and idempotent import replay.

**Required remediation:** turn every golden fixture and invariant into executable tests against the exact implementation commit. Record runtime, commit SHA, pass/fail output and reviewer.

## Release disposition

| Area | Static audit disposition |
|---|---|
| Cent-level money arithmetic | **Block** |
| Payroll allocation as financial evidence | **Block** |
| Invoice evidence confidence | **Block** |
| Import amount parsing | **Block** |
| Contribution reporting | **Block** |
| Basic CSV parser behaviour | Limited prototype coverage only |
| Current demo/test harness | Prototype only; not financial acceptance evidence |

## Required sequence

1. Approve a formal financial data contract: amount representation, currency, GST basis, source precision, rounding policy and calculation grain.
2. Replace the money primitive with a decimal-safe implementation.
3. Design source-row-level payroll allocation and approval provenance.
4. Rework invoice evidence dimensions and confidence/status separation.
5. Add typed, basis-aware contribution aggregation and completeness states.
6. Convert all synthetic golden fixtures and invariants into executable tests.
7. Run the full suite on a named commit in CI and have an independent reviewer verify expected results.
8. Keep all production use blocked until G0–G5 and the separate release/security controls are satisfied.

**No code was changed by this audit.** This document records static findings and remediation requirements; it does not represent a fix or passing test result.

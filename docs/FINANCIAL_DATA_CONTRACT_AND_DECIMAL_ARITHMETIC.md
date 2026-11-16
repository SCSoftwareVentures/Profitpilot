# Financial Data Contract and Decimal Arithmetic Decision

**Status:** proposed design decision for review. Documentation only; not an implemented engine, schema or accounting policy.
**Applies to:** initial Australian contract × site × service-period management-economics workflow.
**Decision owner:** requires named technical owner and qualified finance/accounting review before implementation.
**Scope exclusions:** statutory payroll calculation, tax return preparation, audited accounts, payment custody and legal determination of billability.

## 1. Decision summary

1. Monetary source values are parsed into exact decimal values from source text. They are never converted through JavaScript `Number` for authoritative arithmetic.
2. Currency, tax basis, source precision, period, source lineage and calculation method are mandatory typed attributes.
3. Unknown is represented explicitly and never coerced to zero.
4. Arithmetic uses a vetted decimal library with explicit precision and rounding configuration, or integer minor units only where the operation is provably limited to the currency's minor-unit precision. Rates, ratios, unit prices and intermediate calculations require decimal precision.
5. Rounding is a versioned policy applied at named boundaries. No universal line-vs-invoice rule or rounding mode is assumed by this document.
6. Every output is reproducible from immutable source versions, mapping decisions, allocation decisions, calculation policy version and engine version.
7. Calculations with incompatible currency/tax basis or incomplete material inputs are blocked or explicitly marked incomplete; they are not silently normalised.

## 2. Canonical monetary value

Every amount used in a calculation must have the following logical shape:

| Attribute | Requirement | Example |
|---|---|---|
| amount_raw | Original source text, retained securely | `"1,234.50"` |
| amount_decimal | Exact parsed decimal string; no exponent notation in canonical serialisation | `"1234.50"` |
| currency | ISO 4217 code | `"AUD"` |
| tax_basis | `GST_INCLUSIVE`, `GST_EXCLUSIVE`, `NO_GST`, `OTHER`, `UNKNOWN` | `"GST_EXCLUSIVE"` |
| source_precision | Decimal places supplied by source | `2` |
| source_reference | File, batch, row, source system and source record IDs | stable opaque IDs |
| parser_version | Version of source-specific parser/mapping | `"payroll-csv-v1"` |
| status | `VALID`, `HELD`, `UNKNOWN`, `REJECTED` | `"VALID"` |

The decimal string is the canonical interchange representation. Do not serialise authoritative monetary values as JSON floating-point numbers. API schemas should expose decimal strings and explicit currency/tax metadata.

### Parsing rules

- Parse from original text using a source-specific declared locale and number format.
- Reject ambiguous decimal/thousands separators, unsupported currency symbols, malformed signs, embedded formulas and non-finite values.
- Do not use permissive `parseFloat` or `Number` coercion as a financial parser.
- Do not strip minus signs, brackets, credit markers or currency codes without an explicit source mapping.
- Keep raw source value and parsed canonical value side by side.
- Empty/missing is `UNKNOWN`/null; literal zero is valid zero.
- Never infer AUD merely because the initial market is Australia.
- A parser change creates a new mapping/parser version and requires a restatement impact assessment.

## 3. Arithmetic model

### Preferred implementation

Use a maintained decimal arithmetic package compatible with the selected Node.js runtime. Before selection, the technical owner must review package maintenance, licence, security posture, precision model, rounding modes, parsing behaviour and reproducibility. Pin the dependency and lockfile.

The engine must:
- construct decimals directly from canonical decimal strings;
- prohibit implicit conversion to binary floating-point;
- define precision for intermediate calculations;
- define explicit rounding mode at each business boundary;
- serialise outputs as decimal strings;
- reject NaN, Infinity and overflow;
- make operations deterministic and independent of input row order.

Integer minor units can be used for amounts already quantised to the currency's minor unit, but must not be used as a shortcut for calculations involving fractional rates, prorations, allocations, unit prices or tax calculations without a mathematically reviewed precision strategy.

### Forbidden patterns for authoritative money

- `Math.round(Number(value) * 100) / 100`
- `parseFloat(rawAmount)` or `Number(rawAmount)` as financial parsing
- arithmetic over JSON numeric money fields
- silent fallback such as `amount || 0`
- rounding each intermediate value without an approved policy
- summing different currencies or GST bases directly

## 4. Rounding policy registry

Rounding is not a global formatting preference. It is part of the calculation method and must be versioned.

Each policy record must define:
- policy ID and version;
- operation (source line, allocation, tax component, invoice total, period aggregation, ratio/display);
- rounding mode;
- target scale;
- boundary (before/after aggregation, per line/per document);
- negative-value behaviour;
- source/legal/accounting rationale and reviewer;
- effective date and affected calculation types.

Candidate modes for controlled testing include HALF_UP, HALF_EVEN, DOWN, UP and FLOOR. Selecting a mode for a real workflow requires qualified review and evidence of the source system/customer accounting treatment. The golden fixture's ROUND_HALF_UP examples are test vectors only, not a universal policy.

Do not conflate:
- **calculation precision** — precision retained internally;
- **posting precision** — amount recorded by the source/business process;
- **display precision** — digits shown to the user;
- **tax rounding** — policy for tax components;
- **aggregation boundary** — when values are summed and rounded.

## 5. Currency and GST compatibility

An aggregate is valid only if all included values have compatible:
- currency;
- tax basis or approved conversion;
- service/pay period and timezone interpretation;
- inclusion/exclusion policy;
- calculation version and source status.

Currency conversion requires a separately approved rate source, rate value, base/quote currency, effective timestamp, retrieval timestamp, conversion direction, rounding policy and reviewer. Do not use a current spot rate to restate historical economics unless the method explicitly requires it and is approved.

GST conversion must retain original source amount and basis. GST rate and treatment must be sourced for the relevant transaction and date; 10% in synthetic fixtures is not a substitute for tax advice or validation of a real transaction. Unknown tax basis is held or visibly excluded from tax-sensitive aggregates.

## 6. Calculation grain and source lineage

Canonical calculation grain:

**tenant × contract × contract version × site × service period × currency × tax basis × calculation version**

A calculation run must retain:
- source batch IDs and checksums;
- included, excluded and held source-row IDs;
- source row counts and control totals;
- mapping version and human decisions;
- payroll allocation run/version and reviewer;
- invoice match decisions and reviewer;
- contract/scope version;
- tax and rounding policy versions;
- engine version/commit;
- generated timestamp and timezone;
- prior run/restatement link and reason, if applicable.

The same immutable inputs and versions must reproduce the same exact outputs. A corrected input or policy creates a new run; it does not mutate an old output.

## 7. Typed status model

Do not collapse data quality into a single confidence score.

- `VALID`: parsed and passed structural checks.
- `HELD`: unresolved exception prevents use in a confirmed calculation.
- `UNKNOWN`: source does not establish a required fact.
- `CANDIDATE`: suggested mapping/match/allocation awaiting authority.
- `CONFIRMED`: authorised human decision recorded with evidence.
- `EXCLUDED`: deliberately omitted under a documented policy and reason.
- `INCOMPLETE`: required source coverage is missing for the period or metric.
- `RESTATED`: superseded by a new version but retained as historical output.

A valid parsed row is not necessarily a valid accounting classification. A high evidence score is not approval. A candidate is not a confirmed financial fact.

## 8. Payroll allocation contract

Each allocation line must include:
- payroll source row ID and source amount;
- eligible amount and currency/tax/cost basis;
- destination site or one of non-site, unallocated, excluded buckets;
- allocation amount or fraction;
- method ID/version and rationale;
- evidence reference;
- reviewer identity, role, decision and timestamp for approved allocations;
- unique allocation decision ID and supersession link.

Enforce:
1. Total allocation against a source row cannot exceed its eligible amount.
2. A source row cannot be double-counted across overlapping runs.
3. All eligible pool value reconciles across direct, approved allocation, non-site, residual and excluded buckets.
4. No missing amount is treated as zero.
5. Rejected or pending allocation candidates do not enter approved site totals.
6. Allocation changes create a new run with full restatement lineage.

## 9. Invoice match contract

A match candidate must expose independent evidence dimensions:
- customer identity;
- contract identity;
- site identity;
- service-period fit;
- line/service description or service type;
- amount and currency compatibility;
- GST/tax-basis compatibility;
- duplicate/conflict checks;
- source references.

Evidence status and approval status remain separate. The candidate cannot enter confirmed match coverage until a permitted human reviewer confirms it. Amount similarity alone is insufficient. Conflicts and competing candidates must be visible.

## 10. Contribution contract

A contribution result must declare:
- eligible revenue basis and source;
- direct-coded labour;
- approved allocated labour;
- supplier/subcontractor cost;
- other included site delivery costs;
- separately disclosed non-site and unallocated values;
- currency and tax basis;
- period completeness and coverage;
- all exclusions, estimates and assumptions.

If a material component is unknown or period coverage is incomplete, return an explicit incomplete/unavailable state rather than a definitive margin. The output is a management contribution view, not net, statutory, tax or audited profit.

## 11. API and persistence requirements

- Persist canonical monetary decimal values as database `NUMERIC(p,s)` or an equivalently exact representation, with precision/scale selected from validated source ranges and migration review.
- Do not persist money as SQL `REAL`, `FLOAT` or `DOUBLE PRECISION`.
- API request/response money fields are decimal strings plus currency and tax basis.
- Validate decimal grammar, precision, scale and bounds server-side.
- Never trust client-calculated totals as authoritative.
- Persist calculation input/version references and immutable output snapshots.
- Enforce tenant scope and role permissions at the API and database layers.
- Export decimal strings with explicit currency/tax basis and safe spreadsheet text handling.

## 12. Acceptance gates for implementation

Before implementation is accepted:
1. Finance/accounting reviewer approves the scope, cost basis, GST treatment and rounding policies.
2. Technical owner approves decimal library, precision/scale, parser contracts and API representation.
3. Every golden fixture has independently reviewed expected outputs.
4. Positive/negative midpoint, high precision, large values, negative credits, null/zero, locale ambiguity, currency mismatch and tax-basis mismatch tests pass.
5. Payroll source-row allocation caps, duplicate allocation and restatement tests pass.
6. Invoice evidence dimensions and human authority tests pass.
7. Contribution completeness and label tests pass.
8. Property tests prove reconciliation, determinism and idempotency for generated synthetic cases.
9. CI results are tied to a named commit and runtime.
10. No real customer data is introduced until security/privacy/legal and pilot approvals are complete.

## 13. Open decisions — must not be guessed

- Decimal package and exact version.
- Maximum supported amount, precision and scale.
- Source-specific locale and parsing formats.
- Approved rounding mode and boundary for each calculation type.
- GST source-of-truth and transaction-specific tax handling.
- FX source and historical conversion method.
- Whether payroll pool includes each employment on-cost component.
- Contract revenue basis (invoiced, accrued, earned, or another explicitly chosen basis).
- Materiality thresholds for incomplete contribution views.
- Retention and access policy for raw employee/invoice source records.

These decisions require evidence, a named owner and approval. This document deliberately leaves them open rather than manufacturing a universal financial policy.

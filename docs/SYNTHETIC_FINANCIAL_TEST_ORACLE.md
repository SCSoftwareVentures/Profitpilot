# Synthetic Financial Test Oracle — Worked Examples

**Status:** proposed independent expected-results oracle. Synthetic data only. These examples are not statutory accounting, payroll, tax or audited-profit advice, and they do not prove that application code passes.
**Purpose:** give reviewers a hand-checkable baseline against which a future deterministic calculation engine and its automated tests can be compared.
**Currency:** AUD unless stated otherwise.
**Tax convention:** each case explicitly states GST basis. GST is shown at 10% solely as a declared fixture assumption.
**Rounding convention:** cases requiring cent rounding explicitly declare decimal ROUND_HALF_UP at the stated boundary. This is a test-fixture convention, not a universal accounting policy.

## 1. Fixture A — payroll pool reconciliation

### Inputs

One synthetic pay period has an authoritative payroll source total of **AUD 10,000.00**.

| Bucket | Evidence basis | Amount |
|---|---|---:|
| Site A direct-coded labour | Source row directly identifies Site A | 5,000.00 |
| Site B approved allocation | Approved method ALLOC-01, reviewer decision recorded | 2,000.00 |
| Non-site labour | Source identifies central/non-site work | 1,000.00 |
| Unallocated residual | Insufficient evidence to attribute | 2,000.00 |
| **Authoritative source pool** | Payroll export total | **10,000.00** |

### Expected results

- Reconciled buckets = 5,000 + 2,000 + 1,000 + 2,000 = **AUD 10,000.00**.
- Difference to authoritative pool = **AUD 0.00**.
- Site-attributed management allocation = **AUD 7,000.00**.
- Non-site remains **AUD 1,000.00**.
- Unallocated residual remains **AUD 2,000.00**.
- Attribution coverage, if the declared numerator is direct-coded plus approved allocation and denominator is the entire eligible pool, = 7,000 / 10,000 = **70.00%**.

The 70% is a management-attribution coverage measure, not proof that the remaining 30% is avoidable or a site loss.

### Negative variants

| Case | Change | Expected result |
|---|---|---|
| A-N1 | Approved allocation changed to 2,000.01 without changing pool | Block confirmation; 0.01 over-allocation |
| A-N2 | Remove evidence for Site B allocation | Reclassify 2,000.00 to unallocated pending review; preserve total |
| A-N3 | Same source row allocated to Site A and Site B | Detect double allocation; hold run |
| A-N4 | Payroll source total absent | Do not infer pool from bucket sum; mark unreconciled |
| A-N5 | Payroll period incomplete | Mark incomplete; do not compare as a complete service period |

## 2. Fixture B — contract contribution bridge

### Inputs

One synthetic contract/site/service period. All amounts below are GST-exclusive AUD and the fixture explicitly assumes they are comparable on that basis.

| Component | Amount |
|---|---:|
| Eligible customer invoice value for the period | 18,000.00 |
| Direct-coded site labour | 5,000.00 |
| Approved allocated site labour | 2,000.00 |
| Supplier/subcontractor delivery cost | 1,500.00 |
| Other included site delivery cost | 500.00 |
| Non-site payroll cost | 1,000.00 |
| Unallocated payroll residual | 2,000.00 |

### Expected results

Included site delivery costs = 5,000 + 2,000 + 1,500 + 500 = **AUD 9,000.00**.

Management contribution before separately disclosed non-site and unallocated items = 18,000 - 9,000 = **AUD 9,000.00**.

Contribution ratio on the declared eligible invoice value = 9,000 / 18,000 = **50.00%**.

Separate disclosure:
- Non-site payroll: **AUD 1,000.00**.
- Unallocated payroll residual: **AUD 2,000.00**.
- Combined separately disclosed amounts: **AUD 3,000.00**.

Do not subtract the separately disclosed amounts a second time from the stated site contribution. If a different fully loaded management view is requested, show it as a distinct calculation with an explicit allocation policy. The result must be labelled **management contribution**, not net profit, audited profit, statutory profit or tax profit.

### Negative variants

| Case | Change | Expected result |
|---|---|---|
| B-N1 | Eligible revenue missing | No contribution amount or margin; show unavailable |
| B-N2 | Supplier cost tax basis unknown | Hold from like-for-like aggregation or isolate visibly |
| B-N3 | Period only partially covered by payroll | Mark contribution incomplete; no definitive margin |
| B-N4 | Non-site amount silently spread across sites | Fail integrity review; no unapproved allocation |
| B-N5 | Candidate variation of 1,000.00 not approved | Exclude from approved revenue and billable value |

## 3. Fixture C — invoice match coverage

### Inputs

Eligible invoice value is declared as **AUD 12,000.00 GST-exclusive** after the documented exclusions policy.

| Invoice line | Eligible value | Evidence and decision | Counts in numerator? |
|---|---:|---|---|
| INV-01 | 4,000.00 | Contract, site, service period and amount align; human-confirmed | Yes |
| INV-02 | 3,000.00 | Contract, site, service period and amount align; human-confirmed | Yes |
| INV-03 | 2,000.00 | Amount aligns only; site/period conflict; pending | No |
| INV-04 | 1,500.00 | Site and period evidence incomplete; pending | No |
| INV-05 | 1,500.00 | Duplicate candidate; unresolved | No |
| **Total** | **12,000.00** | | |

### Expected results

Human-confirmed eligible value with medium/high evidence = 4,000 + 3,000 = **AUD 7,000.00**.

Invoice match coverage = 7,000 / 12,000 = **58.3333…%**, displayed as **58.33%** when rounded to two decimal places using the declared display rounding rule.

The amount-only candidate is not a confirmed match. The duplicate candidate remains visible and is not silently deleted. Coverage remains below the 80% G0 threshold.

## 4. Fixture D — GST basis conversion

Declared fixture rate: 10%. All values are synthetic and source tax basis is known.

| Source representation | Input | Expected ex-GST | Expected GST | Expected inc-GST |
|---|---:|---:|---:|---:|
| GST-exclusive | 100.00 | 100.00 | 10.00 | 110.00 |
| GST-inclusive | 110.00 | 100.00 | 10.00 | 110.00 |
| No GST | 100.00 | 100.00 | 0.00 | 100.00 |

For GST-inclusive 110.00: ex-GST = 110 / 1.10 = 100.00; GST = 10.00.

For unknown tax basis, expected result is **unknown/held**, not an assumed inclusive or exclusive amount.

## 5. Fixture E — decimal rounding boundaries

Declared test policy: decimal ROUND_HALF_UP to two places at the final line amount boundary.

| Exact input | Expected rounded output |
|---:|---:|
| 1.004 | 1.00 |
| 1.005 | 1.01 |
| 1.006 | 1.01 |
| 2.675 | 2.68 |
| -1.005 | -1.01 |

Run these cases in every supported runtime and compare exact decimal strings or integer cents. Binary floating-point approximations must not change the expected output.

A separate test must compare line-level rounding with invoice-total rounding. They are not interchangeable. The product must apply the declared policy consistently and retain source precision.

## 6. Fixture F — credits, duplicate imports and null semantics

| Case | Input | Expected result |
|---|---|---|
| F-01 | Invoice 1,100.00 inc-GST and linked credit 110.00 inc-GST | Preserve both source records; show gross 1,100.00, credit 110.00, net 990.00 inc-GST |
| F-02 | Same source file checksum imported twice for same tenant/scope | Idempotent replay; no duplicate cost or invoice rows |
| F-03 | Same filename, different checksum | Distinct source version; require reconciliation, filename alone is not identity |
| F-04 | Known amount 0.00 | Preserve numeric zero |
| F-05 | Missing amount | Preserve null/unknown; do not coerce to zero |
| F-06 | Malformed amount "1,2x.00" | Hold row with source reference and reason |
| F-07 | Ambiguous locale value "1.234" without source locale | Hold; do not guess decimal or thousands separator |

## 7. Fixture G — variation authority

| State | Evidence | Expected financial treatment |
|---|---|---|
| Requested | Customer asks for extra work; no approval | Candidate only; zero approved variation value |
| Observed | Worker records additional work; no approval | Evidence retained; not billable by itself |
| Approved | Authorised approver, scope and price evidence recorded | May enter approved variation value under effective date/version |
| Rejected | Authorised rejection and reason | Retain history; exclude from approved/billable value |
| Invoiced | Invoice line linked to approved variation | Show invoiced amount separately |
| Reconciled | Invoice/payment evidence reconciled under the applicable system | Show reconciliation state; do not infer bank settlement from invoice status |

## 8. Property and invariant tests

These should be automated when a calculation engine is authorised:

1. For every valid payroll fixture, allocation buckets reconcile exactly to the authoritative eligible pool at the declared precision.
2. No allocation run can allocate more than the eligible source pool or any individual source row.
3. Reordering source rows does not change deterministic totals.
4. Replaying the same import does not change totals.
5. Adding a held/unmatched row does not silently alter confirmed totals.
6. A candidate invoice match never changes confirmed coverage until an authorised human decision is appended.
7. An unapproved variation never increases approved contract value or billable variation value.
8. Unknown tax basis never enters a tax-sensitive aggregate without an explicit reviewed conversion.
9. A restatement creates a new version and never mutates prior outputs.
10. Null and zero remain distinct through import, calculation, API and export.
11. Currency mismatch blocks aggregation absent a sourced, time-stamped and approved conversion.
12. Every reported numerator and denominator can be traced to included source records and exclusions.

## 9. Independent verification procedure

For each case:
1. Two reviewers calculate expected results independently from the fixture inputs.
2. Resolve any disagreement before encoding expected values.
3. Record formula, tax basis, currency, precision and rounding boundary.
4. Freeze the fixture version and expected-result key.
5. Execute against the exact application commit and runtime.
6. Compare exact monetary outputs and status transitions.
7. Retain pass/fail evidence, logs with sensitive data redacted, reviewer and date.
8. Re-run after any calculation, parser, mapping or schema change.

A test is **not passed** because its expected result is written here. Only execution evidence on a named commit and environment supports a pass.

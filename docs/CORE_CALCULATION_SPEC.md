# ProfitPilot — Core Calculation Specification

**Status:** logical specification for the initial contract-economics wedge. Not a statutory accounting, payroll, tax or audited-profit methodology. Exact formulas require versioned implementation and approved test fixtures.

## 1. Calculation grain
Tenant × contract × site × service period × calculation version. Never combine different periods, sites, tax bases or currencies without an explicit documented transformation.

## 2. Payroll pool
Retain the authoritative payroll pool total for each pay period, with included cost components and exclusions documented. Do not infer superannuation, payroll tax, leave, workers compensation, award or other statutory obligations unless source data and scope explicitly include them and qualified review approves the treatment.

## 3. Allocation buckets
Represent each pool across distinct buckets:
- Direct-coded site cost
- Approved allocated site cost
- Non-site cost
- Unallocated residual
- Explicitly excluded cost, with reason

**Reconciliation invariant:** direct-coded + approved allocated + non-site + unallocated + explicitly excluded = authoritative source pool, subject only to documented rounding/tax treatment.

No allocation run may create cost beyond the eligible pool. Site-level allocation is a management allocation unless direct site-coded source evidence supports attribution.

## 4. Attribution coverage
Measure the proportion of payroll pool attributable using direct coding or an explicitly approved allocation basis. Document numerator, denominator, exclusions and method for each export set. Retain rationale, inputs, limitations and version.

## 5. Invoice match coverage
Define eligible invoice value before calculation, including treatment of credits, cancellations, duplicate candidates, tax basis and out-of-scope lines.

**Coverage = value of eligible invoice lines with medium/high evidence and human-confirmed contract/site/service-period mapping ÷ total eligible invoice value.**

Candidates are not confirmed matches. Confidence score alone does not confirm a match. G0 requires at least 80% of eligible invoice value matched with medium/high evidence, with denominator and exceptions recorded.

## 6. Contribution bridge
A management contribution view may be presented only when revenue and cost basis are explicit:
- Eligible contract revenue/invoice value
- Less direct-coded labour
- Less approved allocated labour
- Less attributable supplier/subcontractor costs
- Less other included delivery costs
- Equals contribution before separately identified non-site/unallocated items

Do not call this audited profit, net profit, statutory profit or tax profit. Display excluded, estimated and unallocated values. Do not present a definitive margin where material inputs are missing.

## 7. Tax, rounding and confidence
Every source amount carries GST-inclusive, GST-exclusive, no-GST/other or unknown status. Never silently compare unlike bases. Preserve source precision, define rounding boundaries, and use decimal arithmetic.

Confidence describes evidence quality, not probability of correctness unless calibrated. Record identity, amount, date/period evidence, conflicts, source references, method version and reviewer. Amount-only similarity cannot justify high confidence.

## 8. Variation and restatement
States distinguish requested, observed, candidate, approved, rejected, completed, invoiced and reconciled. Approval requires an authorised party and evidence of approved scope/price.

Corrections create a new calculation version and restatement linking old/new runs, reason, affected metrics, reviewer and date. Never silently rewrite prior outputs.

## 9. Presentation rules
- Mark incomplete periods.
- Display data coverage and unallocated residuals.
- Separate direct evidence, allocation and estimate.
- Show assumptions and exceptions beside headline values.
- Suppress small worker groups where fewer than three distinct workers contribute.
- No individual worker ranking or unsupported visit-quality score.
- No savings/revenue-recovery/verified-profit claim without measured evidence.

## 10. Automated invariants
1. Allocation buckets reconcile to eligible payroll pool.
2. Site allocations cannot exceed eligible pool.
3. Malformed amounts are held unless source meaning is supported.
4. Amount-only evidence cannot produce high-confidence match.
5. Candidate match is not confirmed.
6. Candidate variation is not approved/billable.
7. Unknown tax basis is not silently coerced.
8. Duplicate imports are idempotent and reviewable.
9. Restatement preserves prior run.
10. Incomplete periods remain distinguishable.

## Implementation 0.2.0 — conservative partial report

The API calculation run snapshots confirmed medium/high reviewed customer invoice matches by explicit service period and approved site payroll lines in one database statement. It requires one full-period approved AUD contract version and exactly one contract in the business (including inactive contracts, conservatively). Partial overlaps, unknown/mixed/GST-inclusive revenue bases, overlapping payroll pools and excessive evidence are rejected. Integer cents preserve precision. The snapshot includes opaque match, line, pool and allocation IDs, amounts and period bounds but no raw source references or personal payroll records. Returned contribution is revenue less included site labour only, always incomplete; definitive margin is null. Pool context is whole-source context, not additional contract costs. Supplier/other costs, explicit multi-contract attribution, coverage denominators, restatement linkage and external source verification remain future work. Never sum overlapping report runs.

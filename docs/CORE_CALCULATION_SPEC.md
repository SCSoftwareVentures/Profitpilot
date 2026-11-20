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

## 11. Implemented synthetic formula 0.2.0
The API uses integer minor units, exact decimal strings and two-decimal percentage rounding half away from zero. Nonpositive revenue has no margin; the numeric legacy projection is null if outside its supported range. Authoritative values are in outputs.exact. A maximum of 2,000 included invoice lines and 2,000 site allocation lines per calculation bounds storage; oversized or unrepresentable totals fail with 422. Revenue requires both invoice date and reviewed service period to align; overlapping/ambiguous cases are held, no allocation by pro-rata. Each successful run captures the approved contract version, included match/line IDs, source row and batch/receipt digests when available, included payroll allocation/run/source IDs, date/currency/basis and exact amounts, plus formula and period/rounding policy in a repeatable-read transaction. Deterministic key-sorted SHA-256 identifies the input snapshot; this is integrity evidence, not an issuer signature or independent audit. Existing runtime immutability controls remain. Site-level payroll can overlap multiple contracts and is not proven contract-specific; other costs and source coverage remain unresolved. All results remain incomplete. Prior runs retained unchanged. G0–G5 real-data approval unchanged.

## 12. Synthetic canonical confirmation and external invoice bridge
Migration 017 defaults all tenants to rehearsal disabled. An administrator may provision only an isolated synthetic tenant outside the API; runtime cannot change the flag. Separate immutable registry derives amounts, identity and invoice dates from reviewed raw evidence and claims; reviewer attests AUD, tax basis, classification and contract/site/service alignment with an opaque evidence reference. Scope requires exactly one approved covering contract version. Unique claim and raw row, tenant FKs, RLS and atomic audit prevent duplicates and cross-tenant writes. No issuer authentication, credits, multi-line normalization, promotion to invoices, actual calculation inclusion or live activation. The read-only invoice bridge sums exact revenue, supplier and subcontractor amounts separately; mixed tax/currency, version or partial periods fail closed. Payroll is explicitly not included; zero costs reflect included rehearsal evidence only, not completeness. Future validated source semantics and contract-specific labour attribution remain necessary before joining the ledger. No G0–G5 gate changed.

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

## Implementation 0.3.0 — reviewed delivery expenses

Confirmed supplier invoice matches now enter the same evidence snapshot as customer invoices and payroll. Fresh-MFA review must explicitly classify supplier, subcontractor or other direct delivery expense and attest duplicate expense and payroll-overlap checks. A positive supplier amount is a cost; a negative amount is a credit. No inferred cost categories or overhead allocations. All included invoice lines must share the same supported tax basis, reviewed evidence and contained period. Unclassified or incompatible confirmed expense evidence blocks the report. Exact cents and the rounded included-cost ratio are calculated server-side. A zero expense amount is not proof of no expense. Definitive margin remains null; actual source coverage, unmatched expenses, enterprise overhead, tax, source verification and accounting reconciliation remain open. The report retains the earlier single-contract constraint and prior versions. Supplier candidate preparation and canonical source ingestion remain development gaps.

## Canonical invoice preparation 0.1.0

An independent fresh-MFA reviewer can reconcile an open customer/supplier invoice batch into canonical invoices and source-linked match candidates. One complete batch of 1–200 persisted rows is supported. Each row requires invoice_id (uppercase ASCII canonical identifier), date, line_number (integer, contiguous per invoice), description, amount (signed decimal string with exactly two places), currency AUD, tax_basis (gst_exclusive or no_gst), contract_id, site_id, service_start and service_end (within batch). Request fields: manifest containing invoiceNumber, total and lineCount for every invoice; expectedRowCount; sourceReviewed=true; reason. No guessing, number coercion, partial materialization or automatic confirmation. Candidate confirmation requires a third actor distinct from importer and preparer. Repeated invoice numbers in the same direction are held, even when issued by different suppliers; source identifiers must be unique within tenant and direction. Review is human attestation, not external verification; full coverage, general-ledger feeds and production UI remain outstanding.

Only the batch creator can submit invoice source rows. Exact JSONB replay is allowed before sealing; changed content is rejected. Fresh-MFA reviewers can recover candidate IDs and limited financial evidence via the batch candidates endpoint without retrying preparation. Raw payloads and descriptions are excluded. The workflow currently requires three distinct accounts, a conservative development decision pending review of small-business approval models.

## Implementation 0.4.0 — observed coverage and attributable site overhead

Coverage is restricted to recorded invoice lines with a match in the requested contract/site/service-period scope. Count unique line IDs, include candidate, held and rejected records in the denominator, and use absolute values including credits. No signed cancellation, no 100% claim when denominator is zero, no percentage for mixed tax bases, partial overlap, inconsistent evidence or excess records. The denominator excludes unseen records, raw unmaterialised rows and completely unmatched lines; therefore the percentage is observed-only and never substitutes for the external G0 validation threshold. Payroll coverage uses all-site attributed amounts divided by whole selected source-declared pools, not the selected contract's share or proof of complete payroll. Site overhead may enter only via a separately reviewed supplier match with explicit exclusive attribution and payroll/duplicate checks; shared overhead may not be inferred or allocated. Report contribution before overhead and included operating result after overhead separately. Definitive margin/completeness remain suppressed; full source inventory, shared overhead allocation, bank/accounting reconciliation and tax remain outstanding.

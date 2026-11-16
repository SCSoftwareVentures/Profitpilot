# Financial Calculation Verification Cases

**Status:** expected-behaviour test specification; not proof of implementation or execution.
**Scope:** strengthen verification of the contract × site × service-period economics workflow. Use synthetic values only.
**Authority:** the payroll source total remains authoritative. Site allocations are management allocations unless directly coded. Invoice match candidates require human confirmation. Candidate variations are not approved or billable.

## 1. Global calculation contract

Every calculation fixture must declare:
- tenant, contract, contract version, site and service-period identifiers;
- source period and service-period boundaries, including timezone where relevant;
- currency and GST/tax basis for every amount;
- source row counts and source monetary totals;
- included/excluded cost components and rationale;
- mapping and allocation method versions;
- calculation engine version;
- rounding mode and rounding boundary;
- expected output, including held/unallocated values;
- reviewer decision where human confirmation is required.

Use decimal arithmetic. Never use binary floating-point for authoritative money calculations. Preserve raw source precision and round only at explicitly defined boundaries. The selected rounding mode must be documented and applied consistently; no mode is silently assumed by a fixture.

## 2. Payroll allocation fixtures

### PAY-V01 — exact pool reconciliation
Given a payroll pool of AUD 10,000.00:
- direct-coded site A: 4,000.00;
- approved allocation site B: 2,500.00;
- non-site: 1,000.00;
- unallocated residual: 2,000.00;
- explicitly excluded amount: 500.00.

Expected: buckets sum exactly to 10,000.00; site allocations total 6,500.00; non-site, residual and excluded amounts remain separately visible.

### PAY-V02 — allocation exceeds eligible pool
Given eligible payroll pool 10,000.00 and proposed allocations totalling 10,000.01.

Expected: block confirmation; do not silently reduce, proportionally scale or round away the excess.

### PAY-V03 — residual is not zero-filled
Given pool 10,000.00 and only 8,700.00 supported by direct/approved allocation, with 1,300.00 not attributable.

Expected: preserve 1,300.00 as unallocated residual; do not distribute it to sites to make the report look complete.

### PAY-V04 — no double allocation
Given one payroll source row referenced by two allocation lines whose combined allocation exceeds that row's eligible amount.

Expected: reject or hold the conflicting allocation run; identify source row and conflict.

### PAY-V05 — unsupported statutory loading
Given a payroll export that does not state whether superannuation, leave, workers compensation or payroll tax is included.

Expected: do not estimate or add statutory loading. Mark basis unknown and request qualified source clarification.

### PAY-V06 — incomplete pay period
Given a pay period whose end date is after the latest available payroll export.

Expected: label period incomplete; do not annualise, extrapolate or compare as a complete period without an explicitly approved estimate clearly separated from actuals.

### PAY-V07 — allocation method restatement
Given a confirmed allocation run and a later corrected mapping/method.

Expected: create a new run linked to the previous run, preserve original outputs, record reason, actor, timestamp and affected values.

## 3. Invoice matching fixtures

### INV-V01 — amount-only similarity
Given two invoice lines with the same amount but conflicting or absent customer/site/contract/period evidence.

Expected: amount similarity alone cannot produce high confidence or confirmed match.

### INV-V02 — identity/date/amount agreement
Given matching customer identity, contract/site reference, service period and amount with no conflict.

Expected: create a candidate with supporting source references; still require authorised human confirmation.

### INV-V03 — duplicate candidate
Given two identical invoice lines or duplicate source exports.

Expected: flag duplicate candidate and preserve source rows; do not delete or silently net the second line.

### INV-V04 — credit note
Given an invoice line and a related credit note.

Expected: preserve both records and their linkage; display gross, credited and net views only with explicit basis and no loss of history.

### INV-V05 — mixed GST basis
Given one GST-inclusive amount and one GST-exclusive amount.

Expected: do not compare or aggregate until a documented conversion basis is applied; retain original values and tax metadata.

### INV-V06 — unknown GST basis
Given a line with unknown tax basis.

Expected: hold from tax-sensitive aggregation or visibly isolate it; do not assume inclusive or exclusive.

### INV-V07 — period mismatch
Given a line dated outside the service period but with a similar amount and site description.

Expected: flag period mismatch; no automatic high-confidence match.

### INV-V08 — partial invoice
Given only part of the expected contract value invoiced.

Expected: distinguish invoiced-to-date, expected contract value and unbilled/unknown status; do not describe the difference as lost revenue without evidence.

### INV-V09 — human decision authority
Given an analyst-role user attempts to confirm or reject a match where reviewer permission is required.

Expected: deny the action and record the security/audit event according to policy.

## 4. Variations and scope

### VAR-V01 — requested but unapproved variation
Expected: record request and evidence as candidate; exclude from approved contract value and billable variation value.

### VAR-V02 — approval without scope/price evidence
Expected: hold approval as incomplete if policy requires both scope and price authority; do not infer missing terms.

### VAR-V03 — retrospective approval
Expected: preserve original request, actual event time, approval time and approver; do not backdate or rewrite history.

### VAR-V04 — rejected variation
Expected: retain rejection and rationale; do not delete the request or include its value as approved revenue.

## 5. Tax, currency and precision

### TAX-V01 — incompatible currency
Expected: never aggregate different currencies without an explicit, sourced FX rate, effective timestamp, conversion method and reviewer approval.

### TAX-V02 — rounding boundary
Expected: test and document whether rounding occurs per source line, per tax component or at invoice total; fixture expected result must follow the declared policy.

### TAX-V03 — half-cent boundary
Expected: test exact midpoint values under the declared rounding mode; verify deterministic output across runtime environments.

### TAX-V04 — negative amount/refund
Expected: preserve sign and source meaning; do not convert a credit/refund into a positive cost or revenue by absolute value.

### TAX-V05 — zero versus null
Expected: known zero remains zero; missing/unknown remains null/unknown and must not be treated as zero.

### TAX-V06 — locale parsing
Expected: ambiguous decimal/thousands separators are rejected or held unless source locale/format is known; never guess whether "1.234" means 1.234 or 1,234.

## 6. Import and reconciliation

### IMP-V01 — duplicate import
Expected: same source file/checksum and scope is idempotent; replay is visible and does not double-count rows or costs.

### IMP-V02 — changed file with same name
Expected: filename alone does not identify a source; changed checksum creates a distinct version/import decision and reconciliation.

### IMP-V03 — source row count mismatch
Expected: hold the batch or report explicit exclusions; no silent row drops.

### IMP-V04 — source monetary total mismatch
Expected: report expected, parsed, accepted, held and excluded totals separately; unresolved difference blocks a clean reconciliation status.

### IMP-V05 — malformed amount
Expected: hold row with source reference and reason; do not coerce malformed content to zero.

### IMP-V06 — formula injection in CSV export
Expected: escape or neutralise spreadsheet formula-leading content on export; preserve original raw source securely under access control.

### IMP-V07 — unknown site alias
Expected: keep unresolved mapping; do not merge sites on fuzzy name similarity alone.

### IMP-V08 — timezone boundary
Expected: retain source timezone and service-period semantics; a UTC conversion must not move a local service event into a different commercial period unnoticed.

## 7. Contribution and presentation

### CON-V01 — incomplete cost coverage
Expected: show missing cost categories and coverage; suppress definitive margin/contribution claims when material inputs are absent.

### CON-V02 — unallocated residual
Expected: show residual separately and explain that site-level contribution is incomplete; never silently spread it.

### CON-V03 — non-site costs
Expected: keep non-site overhead separate from site direct/allocated costs unless a documented management allocation is explicitly approved.

### CON-V04 — management contribution label
Expected: label result as a management contribution view with included/excluded basis; never call it audited, statutory, net or tax profit.

### CON-V05 — unsupported recovery claim
Expected: a flagged candidate is not "recovered revenue", "savings" or "profit improvement" until a separately evidenced realised outcome exists.

## 8. Security and privacy cross-checks

- Every source, row, candidate, calculation and decision is tenant-scoped.
- Cross-tenant IDs return no data and do not disclose object existence.
- Role checks occur server-side; client UI state is not authority.
- Audit records include actor, timestamp, action, target, reason and correlation ID where appropriate.
- Sensitive employee-level data is minimised; suppress small groups under the current policy.
- Data export, retention, deletion and backup deletion must be verified before real pilot data is accepted.
- Logs and error messages do not expose payroll, invoice payloads, tokens or personal data.

## 9. Test execution record

For every case record:
- case ID and fixture version;
- code/engine commit;
- environment and runtime version;
- expected and actual output;
- pass/fail/blocked/not run;
- exact monetary difference, if any;
- logs or evidence reference with sensitive data redacted;
- reviewer and date;
- defect link and retest result.

A case is not passed because it exists in documentation or a test runner. Only retained execution evidence supports a pass. A passing synthetic fixture does not establish lawful real-world data feasibility or accounting correctness.

# ProfitPilot — Release and Test Plan

**Status:** planned acceptance framework; no production release is authorised.

## 1. Validation before software

Follow G0–G6 in the V8.6.1 master blueprint. Do not treat a prototype or repository activity as gate evidence.

- G0: data feasibility and competitive proof.
- G1: problem validation.
- G2: workflow feasibility.
- G3: paid concierge demand.
- G4: prototype usability.
- G5: explicit signed build GO.
- G6: post-build paid software-pilot exit.

## 2. Calculation and data tests

### Financial arithmetic
- Zero, negative and missing revenue/cost inputs.
- Payroll pools with direct-coded, allocated, non-site and residual values.
- Site allocations cannot exceed the eligible source pool.
- GST-inclusive, GST-exclusive and unknown tax basis.
- Credits, partial invoices, prepayments, arrears, rounding and restatements.
- Overtime and penalty categories only where supplied by the customer and in scope.
- No fabricated visit-level metrics or statutory payroll conclusions.

### Import integrity
- Same file replay and true duplicate.
- Distinct legitimate rows with identical amounts.
- Missing IDs, conflicting aliases and unmatched sites.
- Invalid dates, currency, numeric fields and tax basis.
- Held, rejected, accepted and duplicate-candidate states.
- Corrected mapping and batch rollback.
- Full row-level source lineage.

### Matching and variation
- Exact source identifiers and ambiguous aliases.
- Confidence bands and evidence requirements.
- Amount-only evidence cannot produce high confidence.
- Human confirmation required for a final invoice match.
- Requested/observed/approved/rejected variation states.
- Delivery evidence and approval authority.
- Full, under- and over-invoiced outcomes.
- No automatic approval or billing inference.

### Access and audit
- Cross-tenant access attempts.
- Role and object-level permissions.
- MFA and account recovery.
- Audit records for import, mapping, calculation, approval, restatement and export.
- Data export and deletion behavior.
- Support access with purpose and expiry.

## 3. Customer transaction tests — later release

- Quote acceptance snapshots exact scope, price, exclusions and schedule.
- Variations require explicit authority and updated price/scope.
- Evidence submission is timestamped and attributable.
- Customer can accept, request rectification or open a dispute.
- Complaint alone is not proof; completion photo alone is not proof of satisfactory work.
- Proportionate remedy and undisputed amount handling.
- No arbitrary deduction or indefinite freeze.
- Accessible appeal and human support.
- Statutory rights preserved.

## 4. Payment tests — separate legal/provider gate

- Authorisation expiry and capture failure.
- Duplicate/out-of-order webhook events.
- Provider ledger vs internal subledger reconciliation.
- Partial release, refund, failed payout and chargeback.
- Provider reserve/hold expiry and insolvency scenarios.
- Negative balance, reversal and merchant offboarding.
- No internal release state may be represented as bank settlement.
- No funds handling before written provider and legal approval.

## 5. Test environments

1. Unit tests for deterministic calculations.
2. Property-based tests for arithmetic invariants.
3. Integration tests with synthetic fixtures.
4. Contract tests for external adapters.
5. End-to-end tests for core user journeys.
6. Accessibility tests with keyboard and assistive technology.
7. Security tests and independent penetration testing.
8. Native Microsoft Excel and Google Sheets workbook testing where those remain deliverables.
9. Controlled customer pilot with documented authority and de-identified/minimised records.

Synthetic tests prove only the tested behavior under the test conditions. They do not prove real-world data quality, legal compliance or customer value.

## 6. Release-blocking defects

Block release for:
- cross-tenant disclosure or privilege escalation;
- incorrect authoritative financial arithmetic;
- silent data loss or untraceable source transformation;
- unauthorised approval or payment action;
- missing audit trail for material financial decisions;
- unresolved critical/high security vulnerabilities;
- broken backup restore;
- legal/provider approval absent for money movement;
- inaccessible critical user journeys;
- misleading product claims about verified profit, assurance or safeguarded funds.

## 7. Release evidence

Every release must include:
- version and scope;
- build identifier and commit;
- test run identifiers and results;
- known limitations and open defects;
- security/dependency scan status;
- migration and rollback plan;
- backup/restore evidence;
- operational owner and support path;
- legal/provider sign-offs applicable to that release;
- explicit release approval.

## 8. Definition of done

A feature is done only when its acceptance criteria, automated tests, security/privacy controls, accessibility, audit events, error handling, documentation and operational support are complete and verified in the target environment.

A document describing a control is not evidence that the control has been implemented.

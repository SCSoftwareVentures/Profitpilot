# Architecture and Data-Control Principles

This document records design constraints for future implementation. It does not assert that the system has been built.

## Architectural shape
Prefer a modular monolith for an initial product, with explicit domain boundaries and replaceable integrations. Avoid premature microservices and avoid coupling all capabilities into one undifferentiated workflow.

Potential bounded domains:
- identity, tenant and access control;
- contract, scope and site records;
- source imports and immutable raw snapshots;
- labour-cost allocation and reconciliation;
- invoice matching and financial variance;
- variation candidates and approvals;
- customer–business transaction records;
- completion evidence;
- dispute and rectification workflow;
- payment-provider integration and reconciliation;
- reputation and reviews;
- audit and reporting.

The initial build, if authorised, should implement only the validated wedge.

## Data lineage
- Preserve source snapshots and source identifiers.
- Keep raw input separate from normalised records.
- Make transformations reversible where practical.
- Record mapping rules, allocation methods, confidence, reviewer and timestamps.
- Keep calculation versions and inputs so outputs can be reproduced.
- Do not silently overwrite source facts or delete uncertain imports.

## Deterministic financial calculations
Financial arithmetic must be deterministic, testable and versioned. AI may assist extraction, classification, mapping suggestions and draft explanations, but must not be authoritative for financial arithmetic, payroll/statutory determinations, contractual approvals, payment release, dispute outcomes or ratings.

## Import and matching states
Imports should support pending review, accepted, rejected, held/unmatched and duplicate-candidate states. Invoice matches are confidence-scored suggestions requiring human confirmation. Preserve unresolved exceptions.

## Labour allocation
Payroll remains authoritative for pay-period payroll cost. Site-level cost is a management allocation unless supported by site-coded source records. Keep direct, allocated, non-site and unallocated amounts distinguishable. Reconcile allocation buckets to the payroll pool and surface residuals.

## Privacy and worker protection
- Minimise personal data and define a specific purpose for every field.
- Use pseudonymisation where practical.
- Apply small-cell suppression by default when fewer than three distinct workers contribute to a reported group.
- Do not provide individual worker ranking or performance analytics.
- Define tenant isolation, role-based access, MFA, audit logs, retention, deletion and incident response before production data use.
- No identifiable employee data or production integration without documented authority, contractual terms and approved handling controls.

## Security
Before production: threat model and data-flow inventory; secrets management and least-privilege access; secure authentication and authorisation; tenant-isolation testing; dependency and vulnerability management; backup and recovery tests; logging and monitoring; incident response and breach procedures; and independent security assessment appropriate to the deployed system.

Never commit credentials, tokens, private keys, customer data or employee records to this repository.

## Payment and dispute boundaries
Do not design ProfitPilot as the custodian of customer funds by default. Distinguish payment authorisation, funding, safeguarded funds, eligible release, payout, bank settlement, refund and chargeback.

Any marketplace payment flow requires an appropriately authorised provider and specialist Australian legal review of custody/safeguarding, payment services, consumer law, AML/CTF applicability, insolvency, chargebacks and settlement mechanics.

No automated or opaque payment release, deduction, refund, dispute decision or rating action. Human review and an auditable decision record are required for consequential outcomes.

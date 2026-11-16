# ProfitPilot — Initial Threat Model

**Status:** design exercise; not a penetration test, legal assessment or security certification.

## Assets to protect
- Customer contract pricing, scopes and site details.
- Payroll and timesheet exports, including personal information.
- Supplier and subcontractor invoices.
- Customer invoices and financial performance reports.
- Identity credentials, sessions and MFA recovery.
- Payment-provider identifiers, webhook secrets and payout state.
- Completion photographs, property access details and dispute evidence in later phases.
- Audit history, approvals and calculation versions.

## Trust boundaries
1. Customer device to ProfitPilot service.
2. Tenant boundary inside application and database.
3. Application to storage, analytics and backup services.
4. Application to AI extraction/explanation providers.
5. Application to payroll/accounting/invoicing integrations.
6. Application to payment provider and webhook ingress.
7. Business/customer participants within a shared transaction.
8. Staff/support access to customer records.

## Principal threats and required controls

| Threat | Potential impact | Required controls |
|---|---|---|
| Cross-tenant data exposure | Confidential commercial/payroll data disclosed | Tenant-scoped authorization, database isolation controls, negative tests, least privilege |
| Compromised account | Data theft or unauthorised approvals | MFA, secure recovery, session controls, anomaly monitoring |
| Malicious or malformed import | Incorrect costs, injection, parser compromise | File type/size limits, sandboxed parsing, schema validation, formula-safe exports |
| Duplicate/replayed import | Double-counted cost or revenue | Checksums, idempotency, duplicate detection, reviewable batch rollback |
| Incorrect site mapping | Misstated contract economics | Confidence-scored candidates, human confirmation, source lineage |
| Allocation manipulation | Misleading profitability | Explicit direct/allocated/residual buckets, deterministic formulas, audit trail |
| AI hallucination | False financial explanation or match | AI non-authoritative; source-linked output; human approval; deterministic calculations |
| Insider misuse | Unauthorised access or alteration | Role separation, just-in-time support access, immutable audit, periodic review |
| Secret leakage | Account/provider compromise | Secret manager, secret scanning, rotation, no secrets in client bundle/repository |
| Webhook spoof/replay | Incorrect payment status or payout | Signature verification, timestamp/replay window, idempotency, reconciliation |
| Payment-provider failure | Funds delayed, duplicated or misreported | Provider reconciliation, explicit failure states, incident and customer support procedures |
| Dispute abuse or bias | Unfair withholding/refund/reputation harm | Published rules, evidence access, proportional remedies, human review, appeal |
| Photo/property privacy breach | Exposure of people, valuables or access information | Data minimisation, consent, metadata stripping, restricted access, retention schedule |
| Ransomware/data loss | Service disruption and loss of records | Backups, restore tests, least privilege, endpoint controls, incident plan |
| Dependency compromise | Remote code execution/data theft | Dependency pinning, vulnerability scanning, patch process, SBOM |

## Abuse cases to test

- A user changes an object ID to access another tenant's invoice.
- A user replays an import or payment webhook.
- A valid-looking invoice is assigned to the wrong site through an alias collision.
- A payroll total is allocated beyond the source pool.
- A variation is detected and incorrectly treated as approved.
- A customer or business edits evidence after a dispute begins.
- A staff member views records without a support case or valid purpose.
- A payment provider sends duplicate, delayed or out-of-order events.
- A malicious file attempts formula injection or parser exploitation.
- A customer tries to expose a worker's personal details through review or photo evidence.

## Minimum pre-production evidence

- Threat model reviewed by a qualified security practitioner.
- Data-flow diagram and data inventory.
- Tenant-isolation tests, including negative authorization tests.
- SAST, dependency, secret and container scans as applicable.
- Independent penetration test and remediation retest.
- Backup restoration evidence.
- Incident-response tabletop exercise.
- Privacy impact assessment and retention/deletion test.
- Provider webhook and payment reconciliation tests before money movement.
- Documented residual-risk acceptance by an accountable owner.

No item above is claimed complete merely because this document exists.

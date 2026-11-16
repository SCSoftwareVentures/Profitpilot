# ProfitPilot — Canonical Data Dictionary

**Status:** proposed logical model for design and validation, not a deployed database schema. Field names and types must be confirmed against actual source exports and the authorised implementation stack.

## Conventions
- IDs are opaque stable identifiers; never rely on display names as keys.
- Monetary values use decimal precision, never binary floating-point.
- Currency is explicit. AUD is the initial market context, not a universal assumption.
- Dates and timestamps retain source timezone and service-period semantics.
- Null means unknown/not supplied; zero means a known zero.
- Every imported fact retains source file, source row, import batch and mapping version.
- Tenant ownership and access scope apply to every tenant-owned entity.

## Master data
| Entity | Key attributes | Integrity rule |
|---|---|---|
| Tenant | tenant_id, legal/display name, status | Mandatory tenant boundary |
| User | user_id, tenant_id, login, status | Membership and role explicit |
| RoleAssignment | user_id, tenant_id, role, granted_by, timestamps | Least privilege; revocation auditable |
| Business | business_id, tenant_id, legal/display name | Never merge without identity evidence |
| Site | site_id, tenant_id, business_id, name, status | Aliases are separate records |
| SiteAlias | alias_id, site_id, source_system, source_value | Conflicts require human resolution |
| Contract | contract_id, tenant_id, business_id, customer reference, status | Stable identity independent of version |
| ContractVersion | version_id, contract_id, effective dates, source reference | Approved versions immutable |
| ScopeVersion | scope_id, contract_version_id, service, exclusions | Preserve effective scope |
| ServicePeriod | period_id, site_id, start/end, timezone | Period boundaries explicit |

## Source and import
| Entity | Key attributes | Integrity rule |
|---|---|---|
| SourceSystem | source_system_id, tenant_id, name, export type | No implied live integration |
| SourceFileManifest | file_id, batch_id, filename, checksum, size, received_at, period | Preserve original identity/checksum |
| ImportBatch | batch_id, tenant_id, source_system_id, status, permission reference | Idempotent; replay detected |
| RawImportRow | raw_row_id, file_id, source row number, raw payload reference | Immutable; restricted access |
| MappingDecision | mapping_id, raw_row_id, target entity/ID, method, confidence, reviewer, version | Candidate distinct from confirmed |
| ImportException | exception_id, raw_row_id, type, severity, status, resolution | No silent discard |

## Cost and invoice
| Entity | Key attributes | Integrity rule |
|---|---|---|
| PayrollPool | pool_id, tenant_id, pay period, cost basis, currency, source | Reconciles to authoritative payroll export |
| LabourAllocationRun | run_id, pool_id, method/version, reviewer, status | Deterministic and reproducible |
| LabourAllocationLine | allocation_id, run_id, site or bucket, amount/hours, basis | Direct, allocated, non-site, residual distinct |
| CostRecord | cost_id, tenant_id, period, category, amount, tax basis, source | Direct/allocated/estimated explicit |
| SupplierInvoice | invoice_id, supplier, number/date, amount, tax basis, source | Duplicate candidate not auto-deleted |
| CustomerInvoice | invoice_id, customer, number/date, amount, tax basis, source | Total reconciles to lines |
| InvoiceLine | line_id, invoice_id, description, quantity, unit price, tax, amount | Preserve source line and basis |
| MatchCandidate | candidate_id, invoice_line_id, contract/site/period candidate, evidence, confidence | Suggestion until human confirmation |
| MatchReviewDecision | decision_id, candidate_id, reviewer, decision, reason, timestamp | Append-only decision history |

## Variations and audit
Variation, VariationEvidence, VariationApproval and VariationBillingRecord must preserve the observed/requested change, evidence, authorised approver, approved scope/price and invoice link. A candidate is not approved revenue.

Action and ActionOutcome track exception owner, due date, resolution, amount and closure evidence.

CalculationRun stores input versions, formula/method version, timestamp and tax basis. CalculationOutput is immutable per run. Restatement links prior and new runs with reason and approver. AuditEvent records actor, action, target, timestamp, reason and correlation ID.

## Future transaction domains — not initial release
Quote, JobAcceptanceSchedule, Job, Milestone, EvidenceItem, DefectNotice, RectificationAttempt, DisputeCase, PaymentIntent, ProviderAccount, ProviderEvent, Payout, Refund, Chargeback, LedgerAccount and LedgerEntry belong to later bounded contexts. They are not present capabilities.

## Universal metadata and governance
Where applicable store created_at, updated_at, created_by, source_system_id, source_record_id, source_file_id, source_row_id, import_batch_id, mapping_version, effective_from, effective_to, status and tenant_id.

Every schema change requires purpose, owner, source, sensitivity classification, permission basis, retention period, access role, validation rule, migration/rollback, audit requirement and downstream impact.

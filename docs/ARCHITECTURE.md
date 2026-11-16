# ProfitPilot — Target Architecture

**Status:** proposed architecture; not implemented or security-certified.  
**Baseline:** V8.6.1.

## 1. Product boundaries

ProfitPilot is a business intelligence and customer transaction-coordination platform. It is not the authoritative payroll, accounting, statutory recordkeeping or bank ledger system.

The long-term vision contains several domains. They must not be collapsed into one undifferentiated application.

## 2. Recommended delivery sequence

### Phase A — validation tooling
- Controlled import of approved, minimised exports.
- Immutable raw-source snapshots and source manifest.
- Reversible normalisation and mapping review.
- Deterministic contract/site/service-period calculations.
- Human-reviewed invoice match candidates and variation exceptions.
- Traceable variance report and action register.

### Phase B — validated financial intelligence product
- Tenant/user/role management.
- Contract and site master data.
- Baseline and service-period versioning.
- Import batches, raw rows and mapping decisions.
- Payroll pools, cost allocation runs and residuals.
- Supplier/subcontractor costs.
- Invoice lines and confidence-scored match candidates.
- Variation register and action history.
- Reconciliation, restatement and audit event history.

### Phase C — customer transaction coordination
Only after separate customer, legal, provider and operational validation:
- Customer/business workspace.
- Quote and Job Acceptance Schedule.
- Agreed scope, itemised price, exclusions, milestones and change approvals.
- Completion evidence and customer response.
- Rectification and proportionate dispute workflow.
- Reputation and review controls.

### Phase D — payment orchestration
Only after written payment-provider and legal approval:
- Provider-hosted payment collection and onboarding.
- Provider-supported safeguarded funds / marketplace payout model.
- Payment state machine and provider reconciliation.
- Refund, chargeback, payout failure and dispute evidence.
- Double-entry internal accounting subledger.

ProfitPilot must not represent itself as holding escrow or safeguarded money unless the legal and provider structure explicitly supports that claim.

## 3. Modular monolith

Start with one deployable application and a relational database, with strict domain boundaries. Avoid microservices until scale and team ownership justify them.

Suggested bounded contexts:
1. Identity and tenancy
2. Business and customer profiles
3. Contracts, sites and scope
4. Imports and source lineage
5. Costing and allocations
6. Invoicing and matching
7. Variations and approvals
8. Reporting and actions
9. Jobs and evidence (later)
10. Disputes and reputation (later)
11. Payments and ledger (separately gated)
12. Notifications and support
13. Audit and compliance

## 4. Core entity model

- Tenant, User, Role, Permission
- Business, Customer, Supplier, Subcontractor
- Site, SiteAlias, SourceSystem, ExternalIdentifier
- Contract, ContractVersion, ScopeVersion, BaselineVersion
- ServicePeriod
- ImportBatch, SourceFileManifest, RawImportRow, MappingDecision
- PayrollPool, LabourAllocationRun, LabourAllocationLine
- CostRecord, SupplierInvoice, CustomerInvoice, InvoiceLine
- MatchCandidate, MatchReviewDecision
- Variation, VariationEvidence, VariationApproval, VariationBillingRecord
- Action, ActionOutcome, Restatement
- AuditEvent
- Later: Job, Quote, JobAcceptanceSchedule, Milestone, EvidenceItem, DefectNotice, RectificationAttempt, DisputeCase
- Later: PaymentIntent, ProviderAccount, ProviderEvent, Payout, Refund, Chargeback, LedgerAccount, LedgerEntry

Every tenant-owned record must carry tenant identity and be protected by tenant-scoped authorization at the data-access layer.

## 5. Source lineage and calculation integrity

- Preserve the original source snapshot and manifest.
- Store source row identifiers, file checksum, import timestamp, source period and permission reference.
- Normalised records must retain links to source rows and mapping version.
- Never silently overwrite source facts. Corrections create a new mapping/version or restatement.
- Calculations are deterministic, versioned and reproducible.
- Store input references, calculation version, tax basis, allocation method and output.
- AI may propose extraction, mapping, anomaly descriptions and draft explanations. It must not perform authoritative arithmetic, approve variations, confirm matches, decide disputes or release money.

## 6. Financial model boundaries

Payroll is authoritative for pay-period payroll cost. Site allocation remains a management allocation unless direct site-coded source evidence supports it.

Keep separate:
- direct site cost;
- allocated site cost;
- non-site cost;
- unallocated residual;
- estimated cost;
- missing cost.

Never force residuals into a site to make a report appear complete.

The internal financial subledger, if introduced, must be distinct from the payment provider's settlement records and from the customer's accounting ledger. A funded payment is not earned revenue; a payout instruction is not proof of bank settlement.

## 7. Payment state machine — future gated domain

At minimum distinguish:
- quote accepted;
- payment method authorised;
- payment captured/funded;
- funds held by provider under approved structure;
- work in progress;
- completion evidence submitted;
- customer accepted / rectification requested / dispute opened;
- amount eligible for release;
- payout instructed;
- provider settlement confirmed;
- refund pending / completed;
- chargeback opened / resolved;
- payout failed / reversed.

Never equate customer acceptance, internal eligibility or payout instruction with final settlement. Provider capabilities and legal advice determine valid transitions and time limits.

## 8. Security architecture requirements

- Deny-by-default authorization and tenant isolation.
- MFA for privileged and business accounts.
- Short-lived sessions and secure recovery.
- TLS in transit and managed encryption at rest.
- Secrets manager; never store API keys or credentials in repository or spreadsheet.
- Idempotency for imports, provider webhooks and financial actions.
- Signed webhook verification and replay protection.
- Append-only audit events for approvals, money state transitions and data access.
- Backups with tested restore.
- Dependency and secret scanning.
- Secure SDLC, threat modelling and independent penetration testing before production.
- Data minimisation, retention, export and verified deletion workflows.

## 9. Integration approach

Integrations are adapters, not sources of product truth. Each connector must declare:
- supported entities and fields;
- read/write direction;
- permission scope;
- pagination and rate limits;
- identity matching strategy;
- idempotency and retry rules;
- reconciliation process;
- error handling and operator override;
- customer revocation and disconnection behavior.

Do not claim an integration is live until it has been implemented and tested against an authorised sandbox and then a controlled production account.

## 10. Non-functional targets to validate

Set measurable service objectives before launch:
- tenant isolation test coverage;
- backup recovery point/time;
- import size and processing limits;
- audit-event completeness;
- accessibility target WCAG 2.2 AA;
- support response windows;
- availability and incident communication;
- data export and deletion completion time.

These are requirements to engineer and test, not current capabilities.

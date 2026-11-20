# Functional product requirements and workflows

All roles are tenant-scoped except external customer participants who receive explicit job-level access; role proposals below supplement, not replace, current API permissions. Owner is accountable for setup, admin configures, analyst prepares, reviewer approves, read_only views authorised records. No user assigns a role beyond their delegated authority. Support access requires case, purpose, expiry and independent audit.

| ID | Module and primary role | Proposed user journey and acceptance |
|---|---|---|
| FR-01 | Identity & membership / owner | Sign in, select permitted tenant, invite/revoke, change role, review access; revoked or cross-tenant requests denied; owner transfer requires explicit approval and audit. |
| FR-02 | Business/customer/contract/site / admin | Create stable IDs, version scope/price and periods, review aliases; overlapping effective versions block calculation; archived master data cannot erase historical references. |
| FR-03 | Imports / analyst | Declare permission and period, upload bounded export, review receipt/hash and counts, resolve mapping/held rows, export safe diagnostics; identical retry is idempotent and differing same-key data conflicts. |
| FR-04 | Payroll and cost / analyst, reviewer | Reconcile source pool to approved control total, review direct/allocated/non-site/excluded/residual and cost evidence; confirmation is atomic and rejects mismatch or duplicate source; show unallocated amount. |
| FR-05 | Invoices / analyst, reviewer | Resolve issuer identity and conflicts across batches, inspect source lines, candidate match, confirm/reject/hold; every conflicting identity held before confirmation; a confirmed identity cannot contribute twice. |
| FR-06 | Variation / reviewer | Capture request/evidence, identify authorised approver, approve exact scope/price, record completed/invoiced/reconciled; unapproved value excluded and historic scope preserved. |
| FR-07 | Reporting / analyst, reader | Select site/contract/period; show coverage, exclusions, residuals and snapshot version; generate report/export; incomplete source never displayed as verified profit. Restatement links old/new result and reason. |
| FR-08 | Exceptions / analyst, reviewer | Group issues, assign owner/due date, show evidence and materiality, resolve or reopen with reason; no hidden unresolved records. |
| FR-09 | Quote/job / business and customer | Draft itemised quote, approve exact acceptance schedule, track milestones, request explicit variation; amendments never alter accepted version silently. |
| FR-10 | Evidence/completion / participants | Upload scoped evidence, record actor/time and provenance, review required items, accept or issue defect notice; photo not proof of compliance and complaint not proof of fault. |
| FR-11 | Dispute and rectification / independent reviewer | Triage, give each party access to permitted evidence and response, agree or set reasonable deadline, record reasoned remedy and appeal; no automatic fund movement. |
| FR-12 | SecurePay / authorised finance reviewer | Conditional on legal/provider approval: authorise via hosted payment, reconcile actual provider funding, approved release/refund, settlement exceptions; no raw card data or self-custody. |
| FR-13 | Reviews/aftercare / participant | Verified transaction linkage, moderated review, reply/appeal, warranty contact; no retaliation or conditioning statutory remedy on review. |
| FR-14 | Notification/support / admin | Event-based preferences, permitted recipient, bounded retries, no sensitive payload in messages; access case and delivery outcome auditable. |
| FR-15 | Integration adapters / admin | Connect only scoped authorised source, test read-only sync, show progress/error and reconcile counts, revoke and stop access; no live provider claim before acceptance. |

## Screen and interaction contracts

First-release navigation remains Overview, Contracts, Imports, Exceptions, Reports, Settings. Overview has eligible revenue, delivery cost and contribution with source coverage and a clear incomplete state. Contract detail shows active/historical version and sites; import detail shows receipt status, counts, mapping, conflict group and evidence permission; review screens show provenance and rationale beside actions; reports link source and formula version. Settings owns membership, integration permissions, audit exports and retention requests. Future transaction workspace adds quote/job, evidence, dispute, payment timeline and aftercare only when gated.

For each screen: loading, empty, permission-denied, invalid-input, stale-version conflict, offline/retry and successful states. Never equate empty with zero. Disable consequential actions until required evidence and role exist; server still enforces. Mobile-first layouts, accessible forms and error focus, keyboard navigation, status text and confirmation preview. No optimistic confirmation of money or approvals. Error messages carry correlation ID, not internal SQL.

## Acceptance scenarios

A1 synthetic end-to-end demonstration: sign in as tenant A, import fixture, review duplicate and incomplete records, reconcile valid payroll, confirm eligible invoice, produce incomplete/complete-labelled management report, trace every amount, and demonstrate denial from tenant B. Negative path: replay same file, tamper hash, conflict identity, invalid allocation, stale approval, denied access and failed export; evidence remains, no duplicate financial effect. Browser UI is currently not connected end-to-end; this scenario is a target, not evidence of completion.

Later demonstration uses synthetic customer/job and provider simulator only; show quote acceptance, agreed change, defect notice, documented rectification and resolution without real funds. Do not enable production payments simply because this sequence passes.

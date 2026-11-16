# ProfitPilot — MVP Implementation Epic and Dependency Plan

**Status:** implementation planning only; production feature coding remains blocked pending G5 signed GO.  
**Architecture direction:** modular monolith, PostgreSQL, clear domain boundaries, iPhone-first web experience.  
**Principle:** implement the narrow initial economics workflow before expanding into all six differentiators.

## 1. Delivery sequence

The sequence is dependency-led. Work packages may be parallelised only where prerequisites and ownership allow; financial and security foundations must not be bypassed.

| Stage | Epic | Core output | Exit evidence |
|---|---|---|---|
| 0 | Authorisation and delivery setup | G0–G5 evidence, named owners, scope, budget, legal/privacy plan | Signed G5 GO |
| 1 | Integration baseline | PR #25 security changes reconciled with product branch; one database/migration/API baseline | Combined candidate SHA; complete CI; code review |
| 2 | Identity and tenancy | OIDC, MFA, provisioning, roles, membership, tenant context and RLS | Role × route × tenant tests, recovery and key-operations evidence |
| 3 | Core records | Business, customer, contract, contract version, site, service period and searchable IDs | Versioning, tenant FK and audit tests |
| 4 | Source intake and provenance | Permission record, private storage, quarantine, malware scan, source manifest, parser and mapping | Secure upload lifecycle, exact row/total reconciliation, retention/deletion tests |
| 5 | Financial foundation | Money type, locale parser, currency, GST basis, precision, rounding registry and policy versions | DEC/TAX suite and independent expected-result review |
| 6 | Payroll allocation ledger | Source rows, five exclusive buckets, caps, approvals, reconciliation, concurrency and restatement | PAY/PAYLED/property suite |
| 7 | Invoice evidence and decisions | Candidate evidence, conflicts, human confirmation, duplicate controls and coverage denominator | INV suite and reviewer authority tests |
| 8 | Variations | Requested/observed/candidate/approved/rejected/completed/invoiced/reconciled states | VAR suite and immutable decision history |
| 9 | Contribution and exceptions | Completeness-aware management contribution, exception ownership and resolution | CON suite; incomplete inputs suppress definitive result |
| 10 | Reporting, search and exports | Period report, source lineage, policy/engine versions, safe exports | Report reconciliation and export-security tests |
| 11 | iPhone UX and resilience | Responsive critical workflows, offline-safe drafts, accessibility and recovery | G4 usability and accessibility/device evidence |
| 12 | Operational readiness | Monitoring, alerts, backup/restore, incident response, support and runbooks | Operational rehearsal; security/privacy sign-offs |
| 13 | Paid software pilot | Controlled customer onboarding, weekly usage, outcome measurement | G6 exit criteria |
| 14 | Commercial launch | Pricing, support, customer terms, capacity and release controls | Explicit release approval |

## 2. Implementation epic acceptance

### EPIC-01 — Integration baseline
- Resolve PR #25/PR #26 sibling-branch dependency.
- Review all migrations from empty database and supported upgrade path.
- Verify schema/API agreement for every query.
- Verify runtime grants and default privileges, including behaviour for new tables.
- Run all configured CI and financial acceptance tests on the same combined SHA.
- No unresolved critical/high integration defect.

### EPIC-02 — Identity, tenant and permission boundary
- Managed OIDC/OAuth Authorization Code + PKCE.
- MFA for privileged and financial reviewers.
- Secure session/revocation/recovery.
- Tenant membership verified server-side.
- Object-level permissions on every API route.
- Append-only security and approval audit.
- Tenant-owned records carry tenant identity; every relationship has the required tenant-safe constraint.
- Production HMAC/secret custody, rotation and emergency revocation rehearsed.
- Independent penetration testing and retest remain separate exit requirements.

### EPIC-03 — Source intake
- Written authority/permission reference and purpose.
- Data-minimised source fields and period.
- Private object store, quarantine, malware scan and isolated parsing.
- Source checksum, manifest, row identity and parser/mapping versions.
- Source row counts and monetary totals reconcile.
- Idempotent retries, held rows and explicit exclusions.
- Customer export, retention, deletion and backup-expiry behaviours tested.
- Import registration is never mislabeled as binary upload.

### EPIC-04 — Financial domain foundation
- Named finance/payroll owners approve source and policy decisions.
- Source decimal text retained.
- Exact decimal arithmetic from parser through persistence, API and export.
- Explicit ISO currency, GST basis, source precision, scale limits and rounding boundary.
- Unknown is not zero; unlike basis/currency is held.
- Credits, reversals and negative values are tested.
- Run and policy versions are immutable.

### EPIC-05 — Payroll ledger
- Five mutually exclusive buckets: direct-coded, approved allocated, non-site, unallocated and explicitly excluded.
- Every source row reconciles to its eligible exact value or visible unallocated remainder.
- Row allocation cap enforced under concurrency.
- Reviewer role, evidence, reason and time are mandatory.
- Duplicate source-row assignments/replays cannot double count.
- Old runs preserved; restatements link reason, actor and new inputs.

### EPIC-06 — Invoice and variation authority
- Candidate evidence uses identity, scope, site, service period, amount, currency and tax basis.
- Candidate confidence is separate from final human decision.
- Eligible denominator policy is versioned.
- Credits, duplicates and multi-period invoices stay traceable.
- Variations remain non-billable until authorised approval with evidence.
- Event time and approval time remain distinct.

### EPIC-07 — Contribution, exception and reporting
- Contract × site × service-period grain.
- Source completeness and eligibility drive result status.
- Material missing inputs suppress definitive contribution/margin.
- Management contribution is labelled and limitations displayed.
- Non-site, unallocated, excluded and estimated amounts remain visible.
- Every report metric links to sources, mapping, policy, calculation and reviewer decisions.
- Export is formula-injection safe and audited.

### EPIC-08 — Mobile and operations
- Core tasks usable on supported iPhone Safari versions.
- Screen-reader, keyboard, dynamic text and WCAG 2.2 AA checks.
- Network interruption and sync conflicts handled explicitly.
- Offline financial approvals prohibited.
- Monitoring, backups, restore tests, incident response and customer support are operational.
- No real-data pilot until the release control register is satisfied.

## 3. Cross-epic technical dependencies

| Dependency | Must precede | Why |
|---|---|---|
| G5 signed GO and named owners | All implementation | No authorisation otherwise |
| Identity/tenant baseline | Any real-data operation | Data boundary and access authority |
| Private storage lifecycle | Original source file intake | Current metadata registration is not secure upload |
| Decimal/source contract | Payroll, invoice and contribution arithmetic | Avoid rework and hidden conversion |
| Payroll row ledger | Site cost attribution and contribution | Aggregate pool totals are insufficient |
| Invoice evidence/period identity | Revenue coverage and contribution | Issue date is not automatically service period |
| Completeness policy | Definitive contribution/reporting | Non-empty inputs do not prove completeness |
| Immutable runs/audit | All financial approval and restatement workflows | Reproducibility and accountability |
| Ops/privacy/legal | Private pilot | Engineering checks do not replace operational/legal readiness |

## 4. Required project roles

These are responsibilities to assign, not assumed people:

- Product owner: scope, prioritisation, customer outcomes and change control.
- Technical owner: architecture, integration, code quality, CI and delivery.
- Finance/payroll reviewer: source inclusion, allocation method, rounding, tax and expected results.
- Security owner: identity, tenant isolation, key custody, threat model and penetration-test remediation.
- Privacy/legal owner: lawful handling, customer terms, employee information, subprocessors, retention and deletion.
- UX/accessibility owner: iPhone usability, research and WCAG acceptance.
- Operations/support owner: hosting, monitoring, incident, backup, support and customer onboarding.

A single person may cover more than one role only if competence and conflicts are documented. Independent review must remain independent.

## 5. Delivery planning and estimation rules

Do not promise a launch date from the current repository. Once G5 is approved:
- size each epic with the named technical owner;
- record assumptions, external vendor dependencies and unknowns;
- define a critical path and contingency;
- estimate onboarding and support effort from concierge trials;
- size security, data migration and operational work as first-class delivery, not post-launch cleanup;
- re-estimate when policy, schema or customer evidence changes.

## 6. Release controls

No epic is complete because code merges or CI turns green. Each requires acceptance, security/privacy controls, audit, mobile UX, failure handling, documentation and operational ownership.

The full project remains gated by G0–G5 before implementation and G6 after software pilot. No production code, migration, customer data or deployment is authorised by this planning document.
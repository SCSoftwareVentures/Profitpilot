# ProfitPilot — Australian privacy, legal and PIA review
Review date: 18 November 2026
Status: first-party documentary review, subject to qualified Australian counsel and actual deployment verification. No legal opinion, compliance certification, live-data permission or regulatory filing.

## Scope and assumptions

ProfitPilot is a proposed Australian small-business operations and financial
decision-support SaaS. Its public repository uses synthetic data. Production
import intake is disabled; the payroll workflow, live identity provider,
hosting, external alert destination, customer terms, legal entity and operating
privacy contacts have not been verified. Do not represent these as implemented
real-world processing. For design, apply the Australian Privacy Principles
(APPs) even if a small-business exemption might apply. Formal applicability
depends on the legal entity, turnover, activities, exceptions and relationships
with customers; counsel must decide. The employer employee-record exception
does not automatically extend to a SaaS contractor collecting employee records.

## PIA: purpose, handling and design decisions

| Data/process | Design and risk | Before real use |
|---|---|---|
| Account identity and membership | Auth subject/email, RBAC, session cutoff and audit; identity theft and account linkage | Approve actual identity provider, collection notice, support identity verification and access/correction |
| Contract/invoice and financial records | Confidential, tenant boundary, minimized outputs and permitted columns; invoices may incidentally contain personal information | Confirm necessary fields and purpose; prohibit sensitive/personnel identifiers and validate classifier on approved corpus |
| Worker/payroll information | Employee data may include personal or TFN data; source-row ingestion disabled | Separate approved field map; lawful need, retention and recipient analysis; no TFNs, bank detail or health data by default |
| Security logs and incident/recovery state | UUIDs, subject hashes, session digests, authorization state and audit history remain potentially identifiable; not anonymous | Restricted access, encryption at rest and in transit, named custodians and reviewed retention; no real records in public repository |
| Alert notifications | Fixed categories and state only; no tenant or account identifiers; webhook approval not yet obtained | Verify provider, destination region, processor agreement, individual authentication and on-call routing |
| Backup/restore | Encrypted archives and signed deny-only reconciliation; stale backups can resurrect rights or disposed records | Independent offsite custody and current checkpoint; hold-aware expiry and actual restore exercise |
| Decision support and rating | Financial indicators and proposed recommendations can affect worker/customer interests | Evaluate APP 1.7–1.9; document kinds of personal information and decisions, substantial direct involvement, notice, human accountability, review and correction |

## Legal obligations and required evidence

| Area | Review finding and required action |
|---|---|
| Privacy Act 1988, applicability | Confirm legal entity, turnover and exemptions; review customer/contractor responsibilities. Do not assume TFN or employee record exemptions. |
| APP 1 | Adopt and publish an accurate privacy policy, complaint mechanism, internal accountability and review schedule; maintain PIA and data inventory. |
| APP 2 | Evaluate anonymous or pseudonymous interactions where practicable; authenticated business functions require verified identities. |
| APPs 3–5 | Collect necessary information for lawful functions; define handling of unsolicited data and notify at collection; do not enable real imports until screened and approved. |
| APP 6 | Limit use/disclosure to authorized purposes or valid exceptions. Customer agreements must specify instructions, categories, processor use and support access. |
| APP 7 | No use of customer records for direct marketing without lawful basis, required opt-out and review. |
| APP 8 | Inventory every overseas disclosure and processor; establish reasonable protective steps and accountability, assess exceptions and contractual terms. No promise of Australia-only hosting before chosen regions are verified. |
| APP 9 / TFN Rule | Do not collect government identifiers unless authorized and necessary. TFN Rule is binding on lawful TFN recipients; keep TFN handling prohibited until counsel and controls explicitly approve. |
| APP 10 | Validate data, preserve provenance and corrections; human review of outputs; no silent overwrite of financial records. |
| APP 11 | Technical AND organizational measures; protect from unauthorized handling; reasonable destruction/de-identification when no longer needed unless legal retention applies. Technical controls alone are not compliance. |
| APPs 12–13 | Verified access/correction process, authorized redaction, reasons for refusals, response within applicable reasonable period, complaint and escalation channels. Narrow finance export is not a full privacy request workflow. |
| NDB | Identify suspected eligible breach promptly, contain, assess serious harm and remedial action. Take reasonable steps to complete assessment within 30 calendar days of awareness of grounds for suspicion. If eligible and no exception applies, notify OAIC and individuals as soon as practicable; do not treat 30 days as notification deadline or automatic reporting trigger. |
| Automated decision transparency | APP 1.7–1.9 commences 10 December 2026. Where applicable, include prescribed kinds of personal information and significant decisions made or substantially/directly informed by programs. Human review alone does not automatically remove applicability. |
| Fair Work | Employers generally preserve time/wage records for seven years. Determine which records ProfitPilot holds on behalf of customers, contractual support for employer obligations, and separation from unnecessary operational or raw staging data. Avoid blanket seven-year retention. |
| Australian Consumer Law / customer contract | Qualified review of marketing security claims, service scope, liability, unfair contract terms, billing, refunds, data return and exit. No guarantee of being unhackable. |
| Other applicable regimes | Determine sector/state obligations, tax and accounting records, overseas processing and future payments/escrow regulatory perimeter with counsel before the corresponding feature is enabled. |

## Retention and rights decisions (proposed, not binding)

Choose a provisional **30 calendar day rolling encrypted backup expiry**
for new operational planning; this supersedes the inconsistent 35-day proposed
target, subject to measured restore tests, legal hold exceptions and counsel.
Do not erase required records, immutable hold evidence or legally retained
records solely because the backup window has elapsed. Backups may still hold
copies within approved periods; isolate old copies and reapply signed deletion
and security restrictions before service. Distinguish product deletion,
cryptographic disposal, physical erasure, and processor confirmation. Counsel
must approve record-specific schedules and documented holds before live use.

For privacy rights requests: log an opaque case ID; verify identity through
approved channel; determine which party controls the record; review affected
persons' information; provide a minimized, access-controlled response or lawful
refusal reasons and complaint options; record authorized correction and notify
appropriate recipients if required. No auto-disclosure of other tenants'
personal information. Define owner and actual contact before publication.

## Incident response and independent assessment

Use the existing emergency containment and alert mechanisms only as technical
tools. Human responders classify personal information, affected parties,
serious harm, remedial action, legal duties and evidence. Start incident clock
when grounds for suspicion arise, not when an incident is classified.
Proposed internal escalation within 1 hour, triage within 24 hours and daily
review of suspected eligible incidents; these are internal objectives, not
statutory deadlines. No automatic regulator or affected-person notifications.
Retain confidential assessment records and approvals.

## Authoritative references checked 18 November 2026

- OAIC, APP guidelines and statutory principles:
  https://www.oaic.gov.au/privacy/australian-privacy-principles/australian-privacy-principles-guidelines
  and https://www.oaic.gov.au/privacy/australian-privacy-principles/read-the-australian-privacy-principles
- OAIC, small business:
  https://www.oaic.gov.au/privacy/privacy-guidance-for-organisations-and-government-agencies/organisations/small-business
- OAIC, employee records exemption:
  https://www.oaic.gov.au/privacy/privacy-guidance-for-organisations-and-government-agencies/organisations/employee-records-exemption
- OAIC, PIA guidance:
  https://www.oaic.gov.au/privacy/privacy-guidance-for-organisations-and-government-agencies/privacy-impact-assessments/guide-to-undertaking-privacy-impact-assessments
- OAIC, APP 11 security:
  https://www.oaic.gov.au/privacy/australian-privacy-principles/australian-privacy-principles-guidelines/chapter-11-app-11-security-of-personal-information
- OAIC, NDB scheme:
  https://www.oaic.gov.au/privacy/notifiable-data-breaches/preventing-preparing-for-and-responding-to-data-breaches/data-breach-preparation-and-response/part-4-notifiable-data-breach-ndb-scheme
- OAIC, TFN Rule:
  https://www.oaic.gov.au/privacy/privacy-guidance-for-organisations-and-government-agencies/handling-personal-information/the-privacy-tax-file-number-rule-2015-and-the-protection-of-tax-file-number-information
- OAIC, automated decision-making:
  https://www.oaic.gov.au/news/media-centre/new-resources-on-transparency-for-use-of-ai-and-automated-decision-making
- Fair Work Ombudsman, record keeping:
  https://www.fairwork.gov.au/pay-and-wages/paying-wages/record-keeping

## Release decision

Documentary assessment completed; real operating facts, legal/entity
applicability, data processing agreements, published notices, rights workflow,
retention schedule, independent assessment and counsel sign-off outstanding.
No launch approval. Re-review whenever features, jurisdiction, data categories,
processors or the law change.


## Core payroll confirmation supplement — 18 November 2026

Exact core baseline 9fb36818c2663a6870678acc04651eab7e60b5fe, CI #1899 passed. New work must be independently reviewed against the final candidate. Private proposal/decision records and confirmation receipts now include tenant, run, reviewer identity, evidence digest, session digest, authentication time and event time. These records are potentially identifiable; neither hashing nor tenant scoping removes privacy obligations. The API remains disabled for these records.

### Counsel decision register (unresolved, no sign-off)

| ID | Question and required deliverable | Release consequence |
|---|---|---|
| L-01 | Establish operating entity, turnover, applicable Privacy Act/TFN and other statutory coverage; decide customer/provider responsibilities and exceptions. | No real collection |
| L-02 | Approve each payroll field and customer instruction, lawful purpose, notice at collection, prohibited identifiers and recipient/processor arrangements. | No payroll intake |
| L-03 | Reconcile confirmed-evidence immutability with APP 11, record-specific statutory preservation, employee access/correction, disposal, legal holds and backup expiry. Approve a correction/supersession and authorised disposal design that preserves necessary financial integrity. | No live payroll; current freeze must not be represented as a lawful indefinite retention schedule |
| L-04 | Determine whether any financial recommendation, allocation, rating or other feature triggers APP 1.7–1.9; inventory actual personal data and kinds of significant decisions. Approve required disclosures before MarCom publication or real processing. | No affected feature enabled |
| L-05 | Confirm real subprocessors, storage/support regions, overseas disclosure protections, breach allocation, retention and exit/return instructions in executed customer and supplier agreements. | No real data transfer |
| L-06 | Approve privacy policy, collection notice, customer service terms, contractual security claims, rights and complaint procedure, designated contact, refund/termination and non-excludable rights. Review standard-form terms under ACL. | No customer contract or public compliance claim |
| L-07 | Determine relevant Fair Work, tax, financial services and other obligations from actual product scope; distinguish financial management reporting from payroll processing or payment custody. | No representation of statutory payroll or regulated payment service |
| L-08 | Approve the NDB incident decision process, record of assessment, confidentiality, retention and notification authority; complete tabletop and independent review. | No production security/legal acceptance |

### Updated primary-source checks
- OAIC, APP 1 guidance (updated 30 September 2026): https://www.oaic.gov.au/privacy/australian-privacy-principles/australian-privacy-principles-guidelines/chapter-1-app-1-open-and-transparent-management-of-personal-information — additional automated-decision transparency obligations commence 10 December 2026 for covered APP entities when the statutory conditions are satisfied. Do not infer exemption solely from human review.
- OAIC, employee records exemption: https://www.oaic.gov.au/privacy/privacy-guidance-for-organisations-and-government-agencies/organisations/employee-records-exemption — the employer exemption does not generally extend to external contractors handling these records.
- Fair Work Ombudsman: https://www.fairwork.gov.au/pay-and-wages/paying-wages/record-keeping — employers must generally retain time and wage records seven years; establish the customer's required record subset rather than retaining every input indefinitely.
- ACCC: https://www.accc.gov.au/business/selling-products-and-services/contracts — standard-form business contract terms and marketing claims require review; do not disclaim rights that cannot lawfully be excluded.
- OAIC, NDB: https://www.oaic.gov.au/privacy/notifiable-data-breaches/preventing-preparing-for-and-responding-to-data-breaches/data-breach-preparation-and-response/part-4-notifiable-data-breach-ndb-scheme — assessment period and notification obligations remain separately determined.

### External review acceptance
Supply counsel with the final feature scope, data flow and field maps, operating entity and actual processor contracts, candidate version, retention schedule, security evidence and draft customer documents. Obtain a confidential dated written opinion covering L-01 through L-08, named reviewer, conditions, remediation evidence and residual risks. The owner must authorize publication and real processing separately. No sign-off, lawyer engagement, consent to launch, or claim of regulatory approval is made by this supplement.

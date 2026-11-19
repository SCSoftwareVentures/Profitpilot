# ProfitPilot — Data Classification, Access Control, Retention and Australian Privacy Governance

**Status:** proposed product governance baseline; not implemented, legally approved or independently audited.
**Date:** 16 November 2026.
**Scope:** customer, employee/worker, payroll, invoice and related financial/evidence information processed by ProfitPilot.
**Repository:** public repository. Synthetic data only. No real personal, payroll, invoice, customer or confidential commercial information may be committed.
**Build authority:** this specification does not authorise production feature work, live data ingestion, a customer pilot, merge or deployment. G0–G4 and competitive preconditions remain required before build; G5 signed GO remains mandatory.

## 1. Executive decisions

ProfitPilot should adopt the following defaults:

1. Classify data by sensitivity and potential harm, not merely by table name.
2. Treat employee identity, payroll, tax, bank, identity-document and sensitive information as RESTRICTED.
3. Treat customer commercial records and invoices as CONFIDENTIAL at minimum; personal details embedded in them inherit the higher personal-information classification.
4. Give each tenant its own access boundary. Tenant membership never grants every role access to payroll or employee-level records.
5. Separate view, import, approve, export and delete permissions. Importing is not approval; viewing is not export authority.
6. Use purpose-bound, time-limited support access with customer visibility and immutable audit.
7. Do not collect TFNs, identity documents, health information, bank account details or full card data in the first release unless a documented product need, lawful basis, security design and accountable approval exist. Prefer tokenised/provider-held values.
8. Customer deletion requests trigger a verified workflow, not immediate indiscriminate cascading deletion. Preserve only records that must lawfully be retained or are subject to a documented hold; isolate them and restrict use.
9. Use a proposed 30-day rolling backup expiry as an operational target only, subject to restore testing and privacy/legal approval. This supersedes the previous proposed 35-day target; it is not a statutory retention period. See the current Australian privacy/legal review for the required record-specific and hold-aware approval.
10. No customer data enters ProfitPilot until private object storage, malware scanning, retention/deletion, access logging, incident response and tenant-isolation controls are implemented and independently reviewed.

## 2. Roles and responsibility model

Australian privacy law does not map perfectly to the GDPR controller/processor labels. ProfitPilot must assess who determines the purpose and means of each handling activity and who has possession or control of the record. A SaaS provider may continue to hold personal information when it outsources storage if it retains the right or power to access, amend or retrieve it.

For each data flow, the contract and privacy notice must identify:
- the customer business's role and permitted purpose;
- ProfitPilot's own purposes (service delivery, security, billing, support, legal compliance);
- whether ProfitPilot acts only on documented customer instructions or also determines an independent purpose;
- relevant subcontractors and hosting/AI locations;
- access, correction, export, retention, deletion and breach responsibilities.

Do not promise the customer is the sole privacy-responsible party or that ProfitPilot is merely a processor in every circumstance.

## 3. Classification scheme

| Class | Label | Examples | Minimum handling |
|---|---|---|---|
| C0 | Public | Published help pages, marketing material, synthetic test fixtures | Approved public release; no real identifiers |
| C1 | Internal | Non-sensitive operational metadata, generic templates, non-customer system diagnostics | Staff access; no public repository secrets |
| C2 | Confidential | Customer names/contact details, contract scopes/pricing, customer and supplier invoices, site details, commercial reports | Tenant-scoped access, encryption, export controls, audit |
| C3 | Restricted | Employee names linked to wages/hours, payroll source rows, payslips, TFN data if ever exceptionally handled, bank details, identity documents, sensitive information, access codes, dispute evidence with personal details | Need-to-know access, stronger authentication, field-level restrictions, no general support access, heightened monitoring, short staging retention |

Classification is inherited from the most sensitive field in a record, attachment, export or derived report. A financial report containing employee names and wage allocation is C3 even if the aggregate report would otherwise be C2.

### 3.1 Category-specific rules

**Customer and business information**
- Legal entity name and ABN are generally business information, but named contacts, sole-trader identifiers, direct contact details and information about an identifiable individual are personal information.
- Contract pricing, scope, customer invoices, supplier details and site economics are C2.
- Site access codes, keysafe details, alarm instructions and security plans are C3 and should be excluded from the first release.
- Customer lists must not be repurposed for marketing or cross-tenant benchmarking without a separately approved lawful basis and appropriate notice/consent.

**Employee and worker information**
- Names, contact details, rosters, hours, wages, leave, performance and employment details are personal information and normally C3 in this product.
- Health, disability, union membership, religion, race/ethnicity, criminal record and other statutory sensitive information are C3 with additional restrictions. Do not collect these for profitability analysis.
- Use pseudonymous worker IDs wherever possible. The customer retains the identity mapping. Avoid worker-level screens where site-level aggregates satisfy the purpose.
- Do not infer attendance, misconduct, productivity or entitlement from financial allocation data.

**Payroll**
- Payroll exports, payslips, hours, rates, allowances, superannuation, tax withheld, bank/payment details and employee identifiers are C3.
- TFNs are subject to the Privacy (Tax File Number) Rule 2015 and must not be included in normal ProfitPilot imports. If TFN data is unexpectedly detected, quarantine, block processing, notify the authorised privacy contact and securely remove it unless a specifically approved legal basis requires retention.
- ProfitPilot must not become an employer payroll system or replace the employer's statutory payroll records.

**Invoices and financial records**
- Customer and supplier invoice content is C2.
- Invoice lines naming an individual, sole trader, worker, bank account, home address or other personal information inherit C3 where the potential harm warrants it.
- Do not ingest cardholder data or payment credentials. Use payment-provider tokens only in the separately approved future payment domain.
- Supplier bank details should be excluded or masked unless operationally essential and specifically approved.

**Derived data and AI**
- Site contribution, margin, exception and allocation outputs inherit the source classification. De-identification must be assessed for re-identification risk; removing a name alone is not enough.
- AI prompts, embeddings, extracted text, cached results, model logs and support transcripts inherit the source classification if they contain or can reconstruct source information.
- No customer/employee/payroll/invoice data may be sent to an AI provider until provider terms, retention, training use, region, subprocessors, deletion and cross-border handling have been assessed and approved.
- AI output is not an approval, payroll decision, invoice confirmation, employment assessment or authoritative financial calculation.

## 4. Permission model

Permissions are tenant-scoped, resource-scoped and purpose-bound. The matrix below is the maximum default authority; customer configuration may reduce it, not silently expand it.

Roles:
- **Tenant Owner:** accountable customer administrator; manages members and data lifecycle.
- **Tenant Admin:** manages configuration and membership as delegated; cannot approve their own high-risk financial decisions by default.
- **Operations:** manages contracts, sites and operational imports.
- **Finance Analyst:** views approved financial data, prepares allocations and match candidates.
- **Payroll Custodian:** designated small group allowed to import and view restricted payroll source material.
- **Approver:** separately authorised reviewer for payroll allocations, invoice matches and variations.
- **Read-only Auditor:** time-limited read access to explicitly selected records; no raw payroll by default.
- **ProfitPilot Support:** no standing customer-data access. JIT access only for a recorded support case, narrow tenant/resource scope and expiry.
- **Platform/SRE Administrator:** infrastructure administration, not routine business-data access. Break-glass access is exceptional, independently approved and audited.

### 4.1 Action matrix

Legend: **Y** allowed within assigned scope; **C** conditional/explicit grant; **N** denied by default.

| Data class / action | Owner | Admin | Operations | Finance Analyst | Payroll Custodian | Approver | Read-only Auditor | Support / SRE |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| C2 customer records — view | Y | Y | Y | Y | C | C | C | C |
| C2 customer records — import | Y | C | Y | C | C | N | N | N |
| C2 customer records — approve | C | C | C | C | N | Y | N | N |
| C2 customer records — export | Y | C | C | C | C | N | C | N |
| C2 customer records — delete | Y* | C* | N | N | N | N | N | N |
| C3 employee details — view | C | C | N | C | Y | C | N | C |
| C3 employee details — import | C | C | N | N | Y | N | N | N |
| C3 employee details — approve allocation | N | N | N | C (prepare only) | N | Y | N | N |
| C3 employee details — export | C | C | N | C | C | N | N | N |
| C3 employee details — delete | Y* | C* | N | N | N | N | N | N |
| C3 payroll source — view | C | C | N | C (masked/aggregate default) | Y | C (minimum necessary) | N | C |
| C3 payroll source — import | C | C | N | N | Y | N | N | N |
| C3 payroll allocation — approve | N | N | N | N | N | Y | N | N |
| C3 payroll source — export | C | C | N | C (aggregate default) | C | N | N | N |
| C3 payroll source — delete | Y* | C* | N | N | N | N | N | N |
| C2/C3 invoices — view | Y | Y | C | Y | C | C | C | C |
| C2/C3 invoices — import | Y | C | C | Y | C | N | N | N |
| C2/C3 invoice match — approve | N | N | N | N | N | Y | N | N |
| C2/C3 invoices — export | Y | C | C | C | C | N | C | N |
| C2/C3 invoices — delete | Y* | C* | N | N | N | N | N | N |

* Delete means initiate a deletion request for the tenant's data, subject to retention/hold checks and platform execution controls. No tenant user may hard-delete statutory records, immutable audit events or records held under a legal hold. A deletion request cannot erase records belonging to another tenant or another data subject.

### 4.2 Mandatory separation of duties

- Importer cannot approve their own payroll allocation or invoice match.
- A user who creates/edits a variation cannot approve it when the decision is financially material.
- Tenant Owner cannot bypass statutory retention or platform security holds.
- Platform Support cannot grant itself access.
- Break-glass access requires two-person approval, reason, scope, short expiry, customer notification where safe/lawful and post-event review.
- Export of C3 requires step-up authentication, explicit purpose, selected records, expiry and audit.
- Bulk export requires a second authorised approver for C3.
- Permission revocation must invalidate sessions/tokens and queued exports promptly.

## 5. Retention and deletion schedule

Retention periods below distinguish legal minimums that may apply to the customer's records from proposed ProfitPilot service defaults. They are not legal advice and do not create a blanket authority for ProfitPilot to retain every copy for the full period.

| Data | Proposed ProfitPilot handling | External retention rule / trigger | Deletion approach |
|---|---|---|---|
| Temporary upload staging/quarantine | Delete within 24 hours after scan/decision; rejected file immediately after incident evidence is safely retained | No universal statutory period; minimise exposure | Secure object deletion; log outcome without retaining content |
| Accepted original payroll/time-wage records | Only if necessary; customer-directed retention schedule; default service copy 7 years only where contractually instructed and legally justified | Fair Work employee records generally 7 years; ATO payroll/tax records generally 5 years, with exceptions/extended review periods | Retain only necessary source/evidence; delete at applicable end date; customer must preserve its own employer records |
| Payroll-derived allocation and calculation records | Proposed 7 years where they form evidence of employment/payroll or support a retained financial record; otherwise shorter approved schedule | Fair Work and tax obligations differ; customer-specific obligations must be assessed | Keep minimal evidence needed for the lawful purpose; pseudonymise where identity is not needed |
| Customer/supplier invoices and tax evidence | Proposed 5 years from the later applicable statutory start date where required for tax records; longer only for a specific legal rule/hold | ATO generally requires business tax records for 5 years; some records longer | Preserve legally required transaction evidence; delete redundant source copies and excess personal data |
| Contract and commercial records | Contract term plus approved dispute/limitation and statutory period; default not fixed until counsel confirms | Depends on contract, limitation, tax and industry rules | Version and retain evidence required to establish obligations; remove unnecessary personal details |
| Customer contact/profile information | While account active; delete or de-identify within 30 days after verified account closure unless necessary for legal/security purpose | APP 11.2 where covered: destroy/de-identify when no longer needed, subject to legal retention exceptions | Remove profile and contact data from active systems; retain only required transaction/complaint records |
| Support tickets and support attachments | Proposed 12 months after closure; C3 attachments shorter (30 days) unless incident/claim hold | No general fixed period; APP 11 minimisation applies where relevant | Delete attachment content; retain minimal redacted ticket metadata if justified |
| Security/access logs | Proposed 12 months searchable; 24 months protected archive only if risk/legal need is documented | No universal APP log-retention duration | Logs must avoid content/secrets; delete at schedule expiry unless incident hold |
| Audit events for financial approvals/restatements | Retain with the underlying financial record's applicable retention schedule; immutable during that period | Depends on underlying record and legal duties | Pseudonymise actor identifiers only where this does not undermine legally required auditability |
| Backups | Proposed rolling 35-day expiry; no routine user access | APP 11 deletion/de-identification extends to copies held in backups where applicable | Expire/overwrite by schedule; for urgent verified deletion use crypto-erasure/key isolation where technically sound and document residual backup expiry |
| Legal hold / active dispute | Retain only the specifically identified records for the hold duration | Court order, regulator notice, statutory obligation or documented legal claim | Freeze deletion narrowly; record authority, owner, review date and release event |

### 5.1 Important distinctions

- Fair Work employers generally must keep employee records for seven years and make them accessible to employees/former employees and Fair Work Inspectors. This is the employer's obligation; ProfitPilot must not imply it replaces the employer's records.
- ATO guidance generally requires business tax records for five years, but start dates and some record types differ, and certain records must be kept longer.
- Do not apply “seven years” to every customer profile, support log, raw file or unrelated personal detail.
- Where a source record contains personal information but only an aggregate is needed for a financial calculation, retain the aggregate and remove or pseudonymise unnecessary worker identifiers where lawful and operationally sound.
- A customer may have its own recordkeeping obligations. The contract must say the customer remains responsible for preserving its authoritative records and ProfitPilot is not their sole statutory archive.

## 6. Customer-authorised access, export, correction and deletion workflow

### 6.1 Request validation

1. Authenticate the requester with step-up authentication.
2. Verify tenant authority and, where applicable, the data subject's identity/authority.
3. Identify affected tenant, systems, data subjects, data categories, date range and requested action.
4. Distinguish customer business records from personal information about employees, contacts, suppliers or third parties.
5. Record request ID, lawful authority, requested scope, received date and due date.

A tenant administrator cannot automatically exercise another individual's privacy rights merely because that individual appears in the tenant's data. The requester's authority and the relevant data holder's obligations must be checked.

### 6.2 Deletion decision

Before deletion:
- determine whether the data is still required for the original/authorised purpose;
- identify applicable Fair Work, tax, superannuation, corporate, contract, litigation, regulatory or court-order retention obligations;
- check legal holds, active disputes, chargebacks and investigations;
- identify third-party and cross-tenant references;
- identify whether the data is needed to preserve an immutable financial audit trail;
- decide whether deletion, de-identification, restricted retention or partial deletion is lawful and proportionate.

If a retention exception applies, do not reject the entire request without analysis. Delete the unnecessary portions, restrict the retained portion to the lawful purpose, prevent ordinary operational use, set a review/expiry date and explain the outcome to the requester where permitted.

### 6.3 Execution and verification

1. Create a deletion plan with a record-level manifest and counts by storage location.
2. Revoke active sessions, API tokens, connector grants and queued exports associated with the deleted account/tenant as appropriate.
3. Delete active database records and object versions, caches, search indexes, derived files and AI-provider copies where contractually/technically supported.
4. For records that must remain, segregate them in a restricted retention vault or equivalent access-controlled state; do not leave them in ordinary tenant views.
5. Ensure downstream processors and subprocessors receive deletion instructions where required.
6. Record completion evidence, exceptions, operator and timestamps without copying the deleted content into the audit record.
7. Run a verification query against the record manifest and storage inventory.
8. Provide the customer a completion report identifying deleted, de-identified, retained-under-authority and backup-expiry items.

Deletion is not complete merely because a database row is hidden or an account is disabled.

### 6.4 Backup handling

- Backups are encrypted, access-restricted, segregated and unavailable for ordinary application queries.
- Proposed rolling backup expiry: 35 days, with immutable backup manifests and automated expiry evidence.
- A deletion request received while a record exists in a backup must be tracked to the relevant backup generations.
- If the system cannot selectively remove a record from an immutable backup, use a documented control such as cryptographic erasure where per-object/per-tenant encryption keys make this effective; otherwise expire the backup within the defined schedule and prevent restored data from re-entering service.
- Every restore must replay a deletion/tombstone ledger before customer access is enabled.
- Restored data must not resurrect a deleted account, user, export or object.
- Test the process by restoring a backup containing a synthetic deleted subject and proving the data is removed or remains inaccessible before the restored environment is exposed.
- A blanket “backups are exempt” statement is not acceptable. OAIC APP 11 guidance expects reasonable steps to destroy/de-identify copies including archived and backup copies when the entity no longer needs them, subject to lawful retention exceptions.

## 7. Private document storage and malware pipeline

The current prototype does not provide secure binary object storage, upload/download, malware scanning, retention or deletion. Do not accept real files until this architecture is implemented and tested.

### 7.1 Upload sequence

1. Authenticated user requests an upload slot; API verifies tenant membership, role, category and purpose.
2. Server creates a random opaque object ID and short-lived, single-use upload URL. Never expose a public bucket or predictable path.
3. File is uploaded into a private quarantine bucket/prefix, not the accepted-data area.
4. Enforce file-size, count, extension, declared MIME and magic-byte limits. Treat all client metadata as untrusted.
5. Compute cryptographic checksum and bind the object to tenant, uploader, import batch, retention class and consent/authority reference.
6. Run malware scan in an isolated, resource-limited environment with current signatures; inspect archive nesting, decompression bombs, macros, scripts, embedded objects and malformed document structures.
7. Apply content disarm/reconstruction where appropriate for supported document formats; never execute macros or active content.
8. Parse only allowlisted file types in sandboxed workers with CPU, memory, time and output limits.
9. If clean and parseable, promote to a private accepted object store using a server-side state transition. If infected, suspicious, encrypted/password-protected or unsupported, hold or reject; never pass to AI/OCR.
10. Record scan engine/version/signature timestamp, checksum, outcome and reviewer exception if any.

A clean antivirus result is not proof that a file is safe. Defence in depth remains required.

### 7.2 Storage controls

- Private object storage with public access blocked at account and bucket policy levels.
- Encryption in transit and at rest; managed KMS with key rotation and separation of duties.
- Tenant-scoped object authorization enforced by the API; storage URLs are short-lived and narrowly scoped.
- Separate quarantine, accepted, legal-hold and deletion-pending states.
- Object versioning and lifecycle rules; deletion must cover all versions and replicas.
- No customer files in application logs, analytics events, error traces or public GitHub artifacts.
- No permanent local temp files; encrypted ephemeral scratch with automatic cleanup.
- Malware scanner and parser run as isolated services with no general database credentials and minimal network egress.
- File downloads require fresh authorization and are audited. Avoid long-lived signed URLs.
- Exports are generated in a private area, expire automatically, and are one-time or short-lived.
- Customer-specific keys or envelope encryption should be assessed for high-sensitivity tenants; do not claim crypto-erasure unless key granularity and all key copies make it demonstrably effective.

### 7.3 Download controls

- Check tenant, object, record, role, purpose and current legal-hold/deletion state on every download.
- Step-up authentication and explicit reason for C3 exports.
- Mask payroll identifiers by default.
- Watermark sensitive exports with tenant, user, timestamp and export ID where suitable.
- Prevent public cache/CDN storage; set restrictive cache headers.
- Audit both successful and denied access, including bulk access and repeated failures.

## 8. Access logging, monitoring and incident response

Log security-relevant metadata:
- actor/service identity, tenant, role, action, target opaque ID, purpose/ticket, timestamp, source session/device context, outcome, correlation ID and policy version;
- C3 view, import, export, approval, permission change, support access and deletion events;
- denied cross-tenant access, bulk enumeration, repeated export attempts, unusual download volume, privilege changes and break-glass activity.

Do not log raw payroll rows, invoice contents, passwords, tokens, TFNs, bank account numbers, full signed URLs or sensitive document text. Redact identifiers and secrets.

Controls:
- append-only or tamper-evident log storage with separate write authority;
- restricted log access and alerting on privileged queries;
- time synchronisation, retention lifecycle and integrity monitoring;
- alert on unexpected C3 exports, mass reads, tenant context failures, disabled scanning, failed deletion jobs and repeated malware events;
- regular access recertification and immediate offboarding/revocation;
- incident runbook covering containment, evidence preservation, impact assessment, customer/regulator communications and remediation.

For entities subject to the Notifiable Data Breaches scheme, suspected eligible breaches must be assessed promptly. OAIC guidance says take all reasonable steps to complete an assessment within 30 calendar days; where an eligible data breach is established, notify affected individuals and the OAIC as soon as practicable, subject to statutory requirements/exceptions. Do not treat 30 days as a target response time.

## 9. Australian privacy and related legal obligations

This section is a product-design compliance map, not legal advice. Applicability depends on ProfitPilot's own turnover, activities, customers, contracts, data flows and exemptions. Obtain Australian privacy/employment/tax counsel review before live data.

### 9.1 Privacy Act 1988 (Cth) and APPs

- The Privacy Act generally covers Australian Government agencies and organisations with annual turnover above $3 million, plus specified entities/activities regardless of turnover and other exceptions. The small-business exemption is not universal.
- A small business may still be covered if it provides a health service, trades in personal information, provides services under a Commonwealth contract or falls within other statutory categories. Do not assume every customer is exempt.
- Where applicable, map the product to APP 1 (open and transparent management/privacy policy), APP 2 (anonymity/pseudonymity where practicable), APP 3 (collection), APP 4 (unsolicited information), APP 5 (collection notice), APP 6 (use/disclosure), APP 8 (overseas disclosure), APP 10 (quality), APP 11 (security and destruction/de-identification), APP 12 (access) and APP 13 (correction).
- Collection must be reasonably necessary for a function/activity and notices must explain purpose, disclosures, consequences and access/complaint pathways.
- Use/disclosure must remain within the primary purpose or a permitted APP 6 exception.
- Reasonable steps are required to protect personal information; unnecessary information must be destroyed or de-identified unless a legal retention exception applies.
- APP 12 and APP 13 workflows need identity verification, response handling, correction propagation and exception reasons.
- APP 8 cross-border disclosure must be assessed for overseas recipients. OAIC guidance distinguishes an overseas provider acting only as a controlled storage/service provider (potentially a use) from a disclosure where subsequent handling is released from the Australian entity's effective control. Contractual controls, subcontractors, access, retrieval and deletion matter.
- Australian data residency is a product option, not a substitute for APP compliance. Do not claim data stays in Australia until every database, object, backup, support, telemetry, AI and subprocessor location is verified.

### 9.2 Employee records exemption — do not over-rely on it

The Privacy Act employee records exemption is limited to acts/practices directly related to a current or former employment relationship and an employee record held by the employer. It does not automatically exempt ProfitPilot as a separate SaaS provider merely because the data originated in an employer's payroll system. It also does not cover unrelated uses such as marketing. Treat employee/payroll data as protected regardless of whether a particular employer can rely on the exemption.

### 9.3 Tax File Number Rule

TFN information is subject to specific restrictions under the Privacy Act and Privacy (Tax File Number) Rule 2015. The initial product should prohibit collection and processing of TFNs. If a TFN is found in an import, quarantine it, prevent parsing/AI transmission, alert the tenant's designated contact and execute a documented deletion/incident process unless legal counsel confirms a specific authorised handling path.

### 9.4 Victorian privacy laws

The Victorian Privacy and Data Protection Act 2014 (Vic) and its Information Privacy Principles primarily regulate Victorian public sector organisations and private organisations handling information on behalf of Victorian public sector bodies. It is not a general substitute privacy statute for ordinary private-sector customer data. The Health Records Act 2001 (Vic) may apply to health information and health service providers. If ProfitPilot serves government customers or handles health information, conduct a separate applicability assessment and contract-specific controls.

### 9.5 Fair Work and tax recordkeeping

- Fair Work employee records: generally seven years; accessible to the employee/former employee, employer, relevant payroll staff and authorised persons, with Fair Work Inspector access.
- ATO business tax records: generally five years, but the commencement point varies and some records must be retained longer.
- Payroll source data may therefore have overlapping obligations. Apply the longest specifically applicable legal period to the required record, not indiscriminately to all associated personal data.
- ProfitPilot is not the employer's statutory recordkeeping system. Contractually clarify that the customer must preserve its authoritative employment, payroll and tax records.

### 9.6 Automated decision-making transparency from 10 December 2026

From 10 December 2026, APP 1.7–1.8 require APP entities to include specified information in their privacy policy where they have arranged for a computer program to make, or do something substantially and directly related to making, a decision that could reasonably be expected to significantly affect an individual's rights or interests, using personal information.

Before that commencement date, ProfitPilot must inventory AI and algorithmic features and determine whether any could fall within scope. A future feature that ranks workers, affects access to work, flags misconduct, or materially affects an individual's commercial/employment opportunity needs a separate impact assessment, meaningful human review and appropriate transparency. Current design intent is that AI does not make authoritative payroll, employment, approval, dispute or payment decisions.

### 9.7 Privacy governance deliverables before pilot

- Privacy impact assessment and data-flow map.
- APP applicability analysis for ProfitPilot and each customer segment.
- Privacy policy, collection notices and customer data-processing terms.
- Subprocessor register, location map and cross-border assessment.
- Access/correction/deletion request procedures.
- TFN and sensitive-information prohibition/exception procedure.
- Data breach and NDB assessment playbook.
- Records retention schedule approved by counsel and customers.
- Employee/worker transparency materials.
- ADM inventory and privacy-policy updates before 10 December 2026 if applicable.
- Independent legal review and accountable sign-off.

## 10. Tenant isolation assurance — exhaustive verification design

Tenant isolation is a property of every data path, not just the main database query. It must be tested across relational tables, object storage, APIs, search, exports, logs, backups, AI adapters and support tooling.

### 10.1 Database controls

- Every tenant-owned table carries tenant_id.
- Every tenant-owned parent has a unique (tenant_id,id) key.
- Every tenant-owned foreign key uses composite (tenant_id,parent_id) references.
- RLS is enabled and forced for tenant-owned tables; policies use verified signed tenant context.
- Runtime role is non-owner, NOSUPERUSER, NOBYPASSRLS, cannot alter policies, cannot access signing secrets and has only explicit required grants.
- No security-definer function, view, materialized view, trigger or background job may bypass tenant scope.
- Tenant context is transaction-scoped and cleared on commit/rollback/connection reuse.
- Unique indexes and idempotency keys are tenant-scoped.
- Database audit covers schema additions: a new tenant table cannot ship without RLS, composite FKs and catalog tests.

### 10.2 Test coverage matrix

| Surface | Required positive test | Required negative test |
|---|---|---|
| Every tenant table | Tenant A sees its own seeded row | Tenant A cannot read/write/update/delete tenant B row |
| Every foreign-key edge | Same-tenant parent-child insert works | Cross-tenant parent reference rejected |
| Every API route/object ID | Own tenant object succeeds | Another tenant's ID returns safe denial/no data |
| Search/list/count/report | Results/counts limited to tenant | Guessed IDs, filters and aggregates cannot reveal another tenant |
| Imports and replay | Own batch idempotent and traceable | Cross-tenant batch/row replay rejected |
| Payroll allocations | Own source rows and run reconcile | Other tenant source row cannot be allocated; caps enforced under concurrency |
| Invoice/matches/variations | Own candidates and decisions trace | Cross-tenant invoice, contract, site or reviewer rejected |
| Calculation/restatement | Reproducible own run | Cross-tenant source/run cannot be linked or fetched |
| Object storage | Own object authorized through API | Tenant B cannot fetch Tenant A object by key, URL, metadata or replay |
| Exports/downloads | Scoped export contains authorised rows only | Stale URL, revoked role, cross-tenant ID and expired token denied |
| Background jobs/queues | Job processes tenant in signed context | Missing, forged or mismatched tenant context fails closed |
| AI/OCR/cache | Request uses only authorised tenant content | Cross-tenant cache/embedding/prompt retrieval impossible |
| Logs/support/admin | Support case grants exact scoped access | No ticket/no approval/expired grant denies; staff cannot enumerate tenants |
| Backups/restores | Restore preserves tenant partition and deletion ledger | Restore cannot resurrect deleted data or expose other tenant |
| Search index/analytics | Tenant filters enforced server-side | Client-supplied tenant filters cannot override authenticated context |

### 10.3 Exhaustive test method

1. Generate synthetic tenants A, B and C, with unique canary strings and objects in every tenant-owned table and storage surface.
2. Build a catalogue inventory from PostgreSQL metadata and compare it to a reviewed allowlist. Fail CI if a new tenant-owned table lacks RLS, forced RLS, policy coverage, tenant composite FK review or fixture coverage.
3. Enumerate every API route, repository method, background job, export, file endpoint and support action. Maintain a route-to-test traceability matrix.
4. Run tests as the actual restricted runtime role, not a superuser/table owner.
5. For each object operation test same-tenant allow, cross-tenant deny, unauthenticated deny, revoked membership deny, insufficient role deny, forged tenant claim deny and stale-session deny.
6. Test nested and indirect relationships, bulk IDs, pagination, aggregate counts, sort/filter expressions, duplicate identifiers and timing/error side channels.
7. Test connection pool reuse after success, exception, timeout, rollback and cancellation to prove tenant context cannot leak.
8. Test storage object IDs, signed URL expiry, CDN/cache, object versions, export jobs, temporary files, AI/OCR providers, search vectors, backups and restore.
9. Run concurrency/race tests for allocations, approval and deletion, including membership revocation during an active job.
10. Require independent security review and penetration testing after implementation; automated CI is necessary but not sufficient.

### 10.4 Release-blocking assertions

- Every tenant-owned table and every endpoint has an explicit test owner and evidence reference.
- Zero cross-tenant disclosure or mutation in the complete negative matrix.
- Zero unexplained tenant FK or RLS catalogue gaps.
- No production role with BYPASSRLS or schema ownership.
- All background tasks carry a verified tenant context or run only against explicitly public/system data.
- All tenant data export/deletion jobs are tenant-scoped and audited.
- All failed isolation tests block merge/release.
- Schema migrations and API changes must rerun the complete isolation suite against the exact release commit.

The PR #25 branch reports automated coverage for 19 protected tables and implemented API routes at its reviewed commit. That is useful CI evidence, but it does not prove future tables, storage, backups, AI or support workflows are isolated. This specification requires extending the catalogue and matrix to those surfaces.

## 11. Implementation backlog and gates

| Priority | Work package | Required evidence | Gate |
|---|---|---|---|
| P0 | Data inventory, classification and prohibited-field policy | Owner-approved inventory and field map | Before any real data |
| P0 | Privacy impact assessment, APP applicability, notices and contracts | Australian counsel sign-off | Before pilot |
| P0 | RBAC/ABAC and separation of duties | Permission tests for every action | Before pilot |
| P0 | Private object storage, malware pipeline and secure download | Threat review, scanner/parser tests, isolation tests | Before any file upload |
| P0 | Retention/deletion engine including backups | End-to-end deletion and restore test | Before pilot |
| P0 | Tenant isolation exhaustive suite | Catalogue/API/storage/job/backup test evidence | Before pilot |
| P1 | Access logging, alerting and breach response | Alert tests and incident tabletop | Before pilot |
| P1 | Subprocessor/cross-border inventory | Contract and region review | Before any external processor |
| P1 | ADM transparency assessment | Feature inventory and privacy policy update before 10 Dec 2026 if applicable | Before relevant use |
| P2 | Customer-facing privacy dashboard and deletion receipt | Usability/accessibility and legal review | Later release |

No implementation is authorised by this document. Each work package requires a named owner, acceptance tests, privacy/security review and G5 authority before build.

## 12. Sources and legal currency

Primary regulator and government sources consulted on 16 November 2026:
- OAIC, Australian Privacy Principles quick reference: https://www.oaic.gov.au/privacy/australian-privacy-principles/australian-privacy-principles-quick-reference
- OAIC, APP 11 security and destruction/de-identification: https://www.oaic.gov.au/privacy/australian-privacy-principles/australian-privacy-principles-guidelines/chapter-11-app-11-security-of-personal-information
- OAIC, APP 8 cross-border disclosure: https://www.oaic.gov.au/privacy/australian-privacy-principles/australian-privacy-principles-guidelines/chapter-8-app-8-cross-border-disclosure-of-personal-information
- OAIC, employee records exemption: https://www.oaic.gov.au/privacy/privacy-guidance-for-organisations-and-government-agencies/organisations/employee-records-exemption
- OAIC, small business and Privacy Act coverage: https://www.oaic.gov.au/privacy/privacy-guidance-for-organisations-and-government-agencies/organisations/small-business
- OAIC, NDB scheme and 30-day assessment: https://www.oaic.gov.au/privacy/notifiable-data-breaches/preventing-preparing-for-and-responding-to-data-breaches/data-breach-preparation-and-response/part-4-notifiable-data-breach-ndb-scheme
- OAIC, automated decision-making transparency from 10 December 2026: https://www.oaic.gov.au/news/media-centre/new-resources-on-transparency-for-use-of-ai-and-automated-decision-making
- OVIC, Victorian privacy law overview: https://ovic.vic.gov.au/privacy/resources-for-organisations/privacy-officer-toolkit/privacy-law-an-overview/
- Fair Work Ombudsman, employee recordkeeping: https://www.fairwork.gov.au/pay-and-wages/paying-wages/record-keeping
- ATO, business recordkeeping rules: https://www.ato.gov.au/businesses-and-organisations/preparing-lodging-and-paying/record-keeping-for-business/overview-of-record-keeping-rules-for-business

## 13. Current decision

**Classification and governance design:** proposed; ready for product, security and legal review.  
**Australian legal compliance:** not certified; applicability requires counsel review.  
**Private storage, scanning and deletion:** not implemented.  
**Exhaustive tenant isolation:** test specification only; not executed across all proposed surfaces.  
**Real customer/employee/payroll/invoice data:** not authorised.  
**Pilot/production:** not approved.

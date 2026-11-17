# ProfitPilot — Preliminary Privacy Data Inventory

**Status:** Engineering inventory derived from the repository's current PostgreSQL schema and migrations. This is a preliminary code-based inventory, not a verified inventory of a deployed environment, production data, external processors, backups or infrastructure.

**Scope reviewed:** `database/schema.sql` and migrations `008`–`012` on `security/comprehensive-hardening`. Earlier migrations and application behaviour must also be reviewed before this inventory can be treated as complete.

## 1. Data inventory

| Table / data store | Data represented in schema | Provisional classification | Privacy / security considerations |
|---|---|---|---|
| `users` | Authentication subject, email, account status | Confidential / identity data | Avoid exposing authentication subject; email is personal information. No retention or account-erasure workflow is established. |
| `tenant_memberships` | User-to-business tenant relationship, role, status, grant time | Confidential | Reveals employment or business affiliation and access privileges. Revocation must not be confused with deletion. |
| `tenants` | Legal business name, status, creation time | Confidential business information | May identify a sole trader or other natural person in some cases. |
| `businesses`, `sites` | Business and site names, tenant associations | Confidential | Names and site relationships may identify customers, workers or operating locations depending on entered values. |
| `contracts`, `contract_versions` | Customer names, contract status, prices, dates, billing basis, scope JSON, source references, approver | Highly confidential commercial data | Contract scope and customer names can contain personal or commercially sensitive information. JSON and free-text references need validation/minimisation. |
| `import_batches` | Source type, period, permission reference, status, file hash, filename, creator | Confidential; potentially sensitive metadata | Filenames and permission references may disclose customer or worker details. Hashes are not anonymisation. |
| `raw_import_rows` | Arbitrary imported row payload stored as JSON | Highly confidential; potentially restricted | Payload may contain payroll, worker, customer, invoice, bank or other personal/financial data. Schema does not constrain or redact payload fields. |
| `mapping_decisions` | Row linkage, target identifiers, decision, confidence, reviewer, reason | Highly confidential | Can reveal worker/customer associations and reviewer decisions; reason is free text. |
| `payroll_pools`, `allocation_runs` | Payroll pool totals, periods, source references and allocation amounts | Highly confidential financial data | Aggregates may still be sensitive, especially for small teams or identifiable sites. |
| `invoices`, `invoice_lines` | Invoice numbers, dates, amounts, tax basis, descriptions and source row references | Highly confidential commercial/financial data | Line descriptions and source records may contain personal information. |
| `match_reviews`, `variations` | Contract/site associations, evidence JSON, descriptions, amounts, decisions and reviewer identity | Highly confidential | Evidence and free-text descriptions may contain personal or commercially sensitive information. |
| `calculation_runs` | Calculation inputs, outputs, completeness, contract/site, period and creator | Highly confidential | Inputs/outputs may reproduce sensitive source data or derived worker/site economics. |
| `audit_events` | Actor, action, object, reason, correlation ID, metadata and timestamp | Confidential security record; metadata may be highly confidential | Append-only hash chain is implemented, but metadata/reasons must be minimised and must not contain secrets or unnecessary source data. Retention and export controls remain to be defined. |
| `tenant_membership_permission_overrides` | User, permission, grant/deny, reason, granting member and timestamp | Confidential access-control data | Reveals privileges and administrative decisions. |
| `privacy_requests` | Subject, submitter, request type, details, status, assigned reviewer, resolution and legal-hold reason | Confidential personal information; details may be highly sensitive | Database-level subject isolation is implemented. Request details must not invite unnecessary identity documents or sensitive data. Fulfilment execution is not implemented. |
| `private.auth_sessions` | Token identifier, authentication subject, issue/expiry/last-seen and revocation metadata | Restricted security metadata | Never expose bearer tokens or signing material. Session identifiers and subjects remain security-sensitive. |

## 2. Known data flows and boundaries

- The current schema stores imported row payloads in PostgreSQL as JSON. It stores import metadata and a file hash; the reviewed schema does not establish private binary file storage or a malware-scanning pipeline.
- Payroll, invoice, contract, matching and calculation records can contain or derive personal and commercial information.
- Privacy request workflow records requests and decisions. It does not yet generate access exports, execute corrections, enforce processing restrictions, or delete/de-identify records.
- The repository does not yet establish the production hosting region, database backup topology, object-storage inventory, log aggregation destination, email/SMS provider, analytics provider, AI provider, or other subprocessors.
- Environment variables and signing secrets are configuration/secret-management concerns, not ordinary application data. Their actual production storage and rotation arrangements are not established.

## 3. Retention and deletion status

**Not yet defined or evidenced:** approved retention periods by data category; deletion triggers; data subject verification procedure; export format and delivery security; correction execution; legal/accounting retention exceptions; backup expiry; restoration behaviour after deletion; downstream processor deletion; and independently tested deletion evidence.

Do not implement blanket cascading deletion. The schema contains cross-table references and audit records whose retention may be required for security, accounting, dispute or legal reasons. A safe deletion design must first map each table's tenant/user relationships, foreign-key dependencies, derived records, legal holds and backup lifecycle. It must distinguish deletion, de-identification, access restriction and legally required retention.

## 4. Required verification before production

1. Reconcile this schema-derived inventory against every migration, API route, deployment configuration and actual production service.
2. Identify every field that may contain personal, payroll, financial, identity or free-text data; define allowed formats and minimise collection.
3. Trace primary records to derived records, audit metadata, exports, caches, object storage, logs, backups and subprocessors.
4. Approve purpose, lawful basis, retention period and deletion/exception rule for each data category with qualified privacy/legal review.
5. Implement verified access/export/correction/restriction/deletion workflows with identity checks, approval controls, legal-hold handling and tamper-evident evidence.
6. Test tenant isolation and subject isolation for API and direct database access, including negative tests for every new data store.
7. Test deletion and backup restoration so deleted data is not silently reintroduced.
8. Complete a privacy impact assessment and maintain a current processor, hosting-region and cross-border disclosure register.

## 5. Current conclusion

The codebase contains a meaningful set of privacy-relevant data structures and tenant/subject access controls. It does **not** yet have a complete, environment-verified data inventory, approved retention schedule, automated privacy fulfilment, production processor register, or proven deletion lifecycle. This document is a starting evidence artefact and must not be presented to a buyer as proof of full privacy compliance.
## Restricted export coverage (migration 014)
The account-v1 JSON export covers only users.email/status/created_at, current tenant membership role/status/granted_at and that subject's privacy request metadata in the selected tenant. It does not include auth_subject, raw text, third-party identifiers, underlying imported/derived operational data, audit contents, or provider/session metadata. The private privacy_export_approvals table stores request, tenant, approving manager, confirmation time, expiry and consumption time; it never stores exported contents. Retention and full subject attribution remain release gates. Earlier descriptions of absent export execution refer to full personal-data fulfilment; this limited first export path does not fulfil requests.

## Migration 015–016 additions
Account-v2 extends account-v1 with actor-attributed import, mapping, matching, contract approval, variation approval and calculation timestamps only. The new private retention policy, subject hold and redaction approval tables store approval metadata; no original removed narrative is copied into them. Closed request details can be replaced under an explicitly enabled policy and audited independent approval, with a redaction timestamp. All other personal-data categories, backups and legal retention exceptions remain subject to inventory and reviewed execution procedures. The system never treats partial redaction as full fulfilment.

Migration 018 adds private account closure and approval records (user/request/tenant IDs, times, approval scope and policy revision). Local account status, membership and sessions are revoked; optionally the primary profile email is removed from active storage under explicit policy. No old email is copied to the closure marker. Authentication subject and legal history remain pseudonymous identifiers, not anonymous data. Provider, backup and source-record eradication are separate.

Migration 021 adds session cleanup receipts with user ID, cutoff, count, authority reference and timestamps. Eligible expired revoked token identifiers are removed from active storage; closure markers prevent reactivation. Historic legal/financial records and external systems remain outside this cleanup.

Migration 022 records restricted provider erasure grants and operator-recorded verification of provider absence. These records retain local subject mapping and authorization references; they do not establish erasure of provider logs, backups, storage, processors or unrelated business records.

Migration 024 extends narrow active-storage erasure to unreferenced rejected/failed import payloads, with retention, dependency and legal-hold controls. Row IDs, batch metadata, original hashes and audit records are retained; payroll totals, financial records, accepted imports and derived records are excluded. Subject attribution within arbitrary accepted JSON still requires reviewed source provenance and data-subject mapping; actor/creator is not the data subject.

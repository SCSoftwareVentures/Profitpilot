# Privacy Engineering and Data Governance Baseline

**Status:** Engineering requirements and implementation register. This document is not a customer privacy notice, legal opinion, or assertion that every control is implemented.

## 1. Privacy objectives

ProfitPilot must collect and use only information needed for a defined product purpose; keep each business tenant's information isolated; make access traceable; protect sensitive records throughout their lifecycle; and support lawful access, correction, export, retention and deletion processes.

Privacy requirements apply to customer, business-owner, worker, supplier, contractor and administrator information, including information imported from third-party business systems.

## 2. Data classes and handling

| Data class | Examples | Required handling |
|---|---|---|
| Restricted | Authentication secrets, signing keys, recovery material, payment credentials | Never expose in API responses or ordinary logs; store in managed secret/key systems; tightly restrict access and rotate after suspected exposure |
| Highly confidential | Payroll, worker details, financial records, contract rates, bank/payment identifiers, identity documents | Tenant-scoped access; encryption in transit and at rest; least privilege; audited access; minimise copies and exports |
| Confidential | Customer contacts, job/site details, invoices, business performance and operational records | Purpose-limited access; tenant isolation; retention and deletion controls; secure export |
| Internal | Operational metadata, non-sensitive configuration and security events | Role-restricted access; prevent accidental disclosure; retain only as operationally necessary |
| Public | Approved public product information | May be published only after review; never infer that internal records are public |

Classification is based on the most sensitive information in a record or export.

## 3. Collection and purpose controls

Before a new field, integration, import or analytics feature is released, document:
- the information collected and its source;
- the specific product or legal purpose;
- whether the field is mandatory or optional;
- the roles and services that can access it;
- whether it is disclosed to a processor, integration or other tenant;
- the retention trigger and deletion behaviour;
- whether the information is sensitive or creates elevated harm if exposed.

Do not collect a field merely because it may be useful later. Avoid collecting identity documents, precise location, special-category or similarly sensitive information unless a defined feature genuinely requires it and appropriate safeguards have been reviewed.

## 4. Tenant and role boundaries

Tenant membership must be verified server-side for every protected operation. Client-supplied tenant identifiers are selectors, never proof of authority. Database row-level security remains a second enforcement layer, not a substitute for API authorisation.

Access to payroll, payment settings, exports, user administration and other high-impact functions must be separately permissioned. Support and operational access must be time-bound, justified, attributable and logged. Cross-tenant support access must never be implicit.

## 5. Data subject and account lifecycle

The product must provide documented workflows for:
- access and export requests;
- correction of inaccurate personal information;
- account closure and tenant offboarding;
- deletion or de-identification where legally permitted;
- retention of records that must be preserved for legal, accounting, security or dispute purposes;
- restricting processing while a request or dispute is reviewed.

Deletion must cover primary records, derived records, search indexes, object storage, caches and downstream processors where applicable. Backup expiry and restoration procedures must be documented so deleted data is not silently reintroduced. Legal holds and statutory retention exceptions must be explicit and auditable.

The privacy-request API records requests and review states, but does not execute access exports, corrections, restrictions or deletions. The API now fails closed if an administrator attempts to mark a request fulfilled. A workflow status must not be treated as evidence that a data subject request has been completed.

No fixed retention period is asserted by this baseline. Retention periods must be approved against the actual purpose, applicable Australian Privacy Act obligations and any other jurisdictions in which the product operates before production launch.

## 6. Logging, analytics and AI

Logs must not contain access tokens, passwords, signing keys, full payment credentials, unnecessary payroll details or raw imported files. Use opaque identifiers and correlation references where possible.

Analytics should be aggregated or pseudonymised where this meets the purpose. Do not use tenant data to train or improve external AI services unless the relevant data use, provider terms, lawful basis, customer disclosure and opt-in/contractual controls have been reviewed and approved.

AI-generated classifications or recommendations must be labelled as such, traceable to their inputs where appropriate, and subject to human review for material financial, employment or access decisions. AI must not receive more tenant data than the task requires.

## 7. Processors, integrations and data location

Maintain a register of subprocessors, hosting regions, data categories disclosed, purposes, security assurances, retention/deletion terms and cross-border transfers. Integrations must use scoped credentials, least privilege, revocation and auditable connection ownership.

Do not claim Australian-only hosting, data residency, end-to-end encryption or a particular compliance status unless architecture and provider configuration prove it.

## 8. Privacy incident response

Suspected personal-data exposure must trigger the incident process: contain access, preserve relevant evidence, identify affected tenants and data categories, assess likely harm and applicable notification duties, remediate the cause, and document decisions. Notifications must be accurate, timely and legally reviewed. Never conceal or silently rewrite an incident record.

## 9. Release evidence required

Before production release, maintain evidence for:
- a completed data inventory and data-flow map;
- approved purposes and privacy notice matching actual behaviour;
- a privacy impact assessment proportionate to the data and risks;
- retention schedule and verified deletion tests;
- access/export/correction/deletion workflows;
- processor and cross-border disclosure register;
- log redaction tests;
- backup expiry and restore behaviour;
- incident response and notification runbook;
- security review of each new integration and AI feature.

## 10. Current limitations

This baseline does not establish that ProfitPilot currently has a production privacy centre, customer self-service privacy requests, configurable retention enforcement, a completed privacy impact assessment, a subprocessor register, production data residency controls or independently audited privacy compliance. These remain release gates until implemented and evidenced.

## Account-control confirmation (migration 013)
The requesting member must reauthenticate using the configured provider's MFA before confirming their own privacy request. Request-bound HMAC evidence uses the tenant, actor, request, action, authentication time and transaction nonce; PostgreSQL validates it before changing state. A different manager with fresh MFA can begin review within 24 hours of confirmation. Direct runtime writes of status and verification evidence are revoked. A legal hold can preserve even an unverified request; release clears confirmation and returns it to identity verification, while retaining the previous authentication timestamp as a replay-prevention watermark. A manager cannot approve their own request for review; a single-manager tenant requires a separately authorised reviewer or reviewed alternative procedure. This demonstrates control of an established account, not independent real-world identity proofing. The live provider, recovery and higher-risk proofing policy must still be tested and export/deletion executors remain disabled. No identity documents are collected by this endpoint.

## Restricted account export (migration 014)
An independent MFA-authenticated manager may approve a reviewed access/export request for 15 minutes. Only the requesting member can consume that approval, with recent MFA, active membership and matching account confirmation. Request-row locking serializes release, review, withdrawal and legal hold; expiry and single-use are enforced in PostgreSQL. No export copy is persisted, and the response is a JSON attachment with no-store headers. A failed delivery consumes the grant and requires independent reapproval; the audit event records release authorization and generation, not receipt. Only allowlisted account profile, current membership and own privacy request metadata are included. Free text, provider data, payroll/imported records, audit contents and third-party data are intentionally excluded until safe subject attribution and disclosure review exist. A maximum of 100 request rows and 1 MiB of JSON are allowed; oversized exports fail closed, never silently truncate. The request remains under review: this is a partial download, not completed legal fulfilment. Delivery requires HTTPS in production, and live MFA provider verification remains outstanding. No production readiness or privacy compliance is claimed.

## Expanded export and controlled deletion (migrations 015–016)
Account-v2 adds six fixed-label operational activity timestamp types, using explicit same-tenant actor foreign keys; no underlying business data or third-party records are included. Old approvals cannot authorize v2, activity is capped at 500 records, and oversized exports fail closed. Attribution does not prove the actor is the subject of imported or derived data. The only automated deletion scope is removal of the details narrative of an individually approved, closed, non-deletion privacy request belonging to the requester. No default retention policy is enabled. A privileged database operator must document legal approval and insert an enabled tenant policy with an explicit minimum closed age and unique revision. Change the revision on any substantive policy change. A separate authenticated manager approves the target; the requester must authenticate again after approval and execute within 15 minutes. The database rechecks policy, age, subject-wide legal holds, state, confirmation and active approver, then replaces the narrative with a fixed marker in the same transaction as the audit event. The original legal record, financial data, global identity and audit history remain. A tenant-specific retention hold can be placed by a privileged operator even for closed records; ordinary request legal holds are also enforced across the subject's requests in the tenant. Do not activate deletion policy on real data without qualified retention review and backup/restore deletion controls. No backup, WAL, logs, external providers or downstream processors are erased by this feature. It is not full personal data deletion; request remains open for additional processing. No scheduled automatic purge is enabled. Runtime privileges on tenant/membership/permission administration and request deletion are explicitly revoked.

Migration 017 automatically assigns a new retention-policy revision on every insert or update, invalidates unconsumed deletion grants on every hold placement or release, and requires strictly later MFA timestamps for exports as well as deletions. Same-second authentication cannot be treated as a new event. Existing unconsumed deletion grants require independent reapproval.

## Local account closure (migration 018)
A new account_closure request uses the existing requester-confirmation and independent review flow, followed by a separately approved 15-minute one-use grant with explicit eraseEmail true/false. Only the requester with new MFA can execute. Automatic closure is restricted to non-owner accounts with exactly one historical membership, another active owner, no outstanding privacy requests and no legal holds. The transaction disables the global local account, revokes membership and all registered local sessions, and preserves a protected closure marker. Valid new provider tokens for disabled or unknown subjects cannot register or reach authenticated endpoints. Already-running operations may finish; provider refresh tokens and the external account require provider-specific revocation/deletion. Optional email removal requires an explicit enabled policy authorizing profile email erasure, and substitutes a non-deliverable placeholder; identity subject and relational/audit history remain retained. This is not full erasure. No such policy is seeded. Owner or multi-tenant closure and post-closure privacy access require a reviewed support procedure. Receipt must be saved before sign-out; no new login is possible. Restrict provisioning and database administrator access.

## Backup and restoration safeguards (migration 019)
An operator-only privacy state function returns closure/redaction markers and consistency violations, without email addresses, request narratives, session tokens or identity-provider subjects. The checkpoint tool signs the marker set with an independent 32-byte key; verification requires the latest independently recorded digest, matching deployment identity, a fresh authentic checkpoint and every marker in the restored database. Any mismatch blocks the verification command. Redacted narratives cannot be overwritten through ordinary UPDATEs. Backup inventory assessment flags missing encryption, excessive retention, overdue expiry or missing hold evidence; it never deletes files. No default backup period is selected. Operational release gate: isolate the restore from users and integrations; obtain the latest checkpoint and digest from independent protected storage (not the restored database); verify; if missing state, reconcile under approved procedure and reverify; only then permit network traffic. Capture immediately after each closure/redaction, before backup and before restoration cutover, and retain checkpoint history independently. A checkpoint taken before the latest privacy action cannot establish that newer actions survived. If the original database is unavailable, do not generate a new authoritative checkpoint from the restored copy. Production orchestration must enforce this gate, and must provide an independently durable checkpoint store, verified encryption, backup expiry and deletion documentation. No storage provider or backups have been configured, and the command has not been exercised against a live backup service. CI uses synthetic restore-state comparisons only.

Migration 020 extends closure to owners only if another active owner remains, and multi-tenant accounts only if each active organization independently approves its own reviewed request with matching erasure scope and new requester MFA after all approvals. Global holds or other outstanding privacy requests block closure. Optional email erasure with historical inactive memberships is still blocked for manual retention review. Memberships and local sessions are revoked atomically. Ownership transfer or dissolution of a sole-owner business remains an authorized governance operation, not automatic closure.

The CI recovery drill uses real PostgreSQL logical backups and restores in disposable databases and tests the signed privacy gate against both pre-action and current data. Live provider recovery and independent production checkpoint custody remain deployment gates.

Migration 021 adds an operator-only cleanup of expired, revoked session records for closed accounts. Every historical membership must explicitly authorize this scope; the longest approved retention period is enforced and any hold or open request blocks deletion. The cleanup is audited and included in restore markers. No policy is enabled by default. Recently revoked sessions and the closed-account identity marker remain. The restore tool also checks cleanup markers against restored session rows.

Migration 022 prepares a disabled-by-default, operator-only Supabase erasure adapter. Separate subject mapping, documented requester consent and independent approval references, all historical retention policies, no holds and a short-lived authorization are required. The adapter checks exact provider identity before hard deletion and explicit user-not-found afterward; errors require reconciliation, not a false success. The trusted operator must verify provenance and authorization evidence; database receipts are not cryptographic provider attestations. Provider credentials, actual endpoint compatibility, live revocation/deletion and provider backup/processors remain unverified until a free project is connected and an authorized synthetic account test is performed. No live provider call is made in CI.

Migration 023 persists exact provider issuer provenance and enforces it for authentication and external erasure authorization. Unknown/unbound users or wrong issuers are denied even with otherwise valid signatures. No auto-binding from a login or email is permitted. Existing sessions are revoked on migration; trusted provisioning must establish bindings before enabling access.

Migration 024 adds source-specific, operator-only retention for discarded payroll and invoice imports. It removes only raw payloads from rejected/failed batches after approved minimum age, separate authorization and dependency review references, and checks for any tenant legal hold or open privacy request. Referenced source rows, accepted batches, financial records and audit evidence are preserved. Purged batches and empty row placeholders cannot be restored through ordinary writes or reused as sources. The restore checkpoint covers purge markers. No retention duration is enabled or deemed legally appropriate by default; indirect references, copies, legal duty and source retention must be independently reviewed before authorization. This is not subject-level deletion of accepted records.

Discarded-import age is measured from discard time, original batch creation and every stored row's creation, not only the batch's creation date. Pre-existing discarded batches wait the full period from migration unless a separate reviewed migration establishes provenance. Runtime cannot forge timestamps. Privacy request creation/state transitions and hold changes serialize with import purges.

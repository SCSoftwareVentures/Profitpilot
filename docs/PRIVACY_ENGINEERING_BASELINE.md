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

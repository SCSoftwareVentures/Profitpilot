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

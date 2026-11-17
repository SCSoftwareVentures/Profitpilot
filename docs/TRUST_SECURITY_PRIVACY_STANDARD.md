# ProfitPilot — Trust, Security & Privacy Standard

**Document status:** Engineering standard and release-control baseline  
**Applies to:** Product, API, database, infrastructure, integrations, support operations and acquisition handover  
**Assurance statement:** This document defines required controls. It is not evidence that every control is implemented, independently assessed or certified.

## 1. Security and privacy objectives

ProfitPilot must protect the confidentiality, integrity and availability of customer information and business operations. Controls must be enforced server-side and at the data layer, be proportionate to risk, generate useful evidence, and remain maintainable by a future owner.

Design principles:
- Secure by default; deny by default.
- Verify identity, tenant membership, role and object-level permission for every sensitive operation.
- Minimise collection, access, retention and disclosure of personal information.
- Separate customer tenants cryptographically or logically with enforceable database controls.
- Treat financial calculations, approvals, audit events and payment state as high-integrity records.
- Make security events observable without logging passwords, tokens, secrets or unnecessary personal information.
- Fail closed when identity, tenant context, permissions, signatures or critical dependencies cannot be verified.
- Do not represent planned controls as implemented controls.

## 2. Information classification

| Classification | Examples | Minimum handling |
|---|---|---|
| Restricted | Credentials, signing keys, MFA recovery material, payment tokens | Secret manager, strict role separation, no application/client logging, rotation and access audit |
| Highly confidential | Payroll, bank/payment details, employee records, contracts, pricing, invoices, disputes | Tenant isolation, encryption in transit/at rest, least privilege, access logging, retention controls |
| Confidential | Business reports, site records, customer correspondence, operational data | Tenant-scoped access, encryption, authorised sharing, audit |
| Internal | Product telemetry, non-sensitive configuration, operational documentation | Access control, integrity protection, retention |
| Public | Approved marketing and public documentation | Publication review; no embedded secrets or customer data |

Classification must be assigned to every data field and file category in the data inventory. When uncertain, handle data at the higher plausible classification.

## 3. Identity, authentication and account lifecycle

Required controls:
- Use a managed OpenID Connect identity provider with Authorization Code flow and PKCE for browser clients.
- Validate token signature, issuer, audience, expiry, not-before, allowed algorithms and key identifier. Reject unsigned, malformed, expired and wrong-audience tokens.
- Never accept a user ID, email address or tenant ID supplied by a client as proof of identity or membership.
- Require MFA for owners, administrators, support personnel and other privileged roles. Prefer phishing-resistant passkeys/security keys where supported; provide secure fallback and recovery.
- Apply rate limits, progressive delays and abuse detection to login, recovery, invitation and MFA endpoints.
- Provide session expiry, server-side revocation, refresh-token rotation and reuse detection, logout and device/session management.
- Make account recovery at least as resistant to takeover as normal authentication. Notify users of recovery, MFA and credential changes.
- Provision and deactivate users through an explicit, audited lifecycle. Disable access promptly when membership or employment ends.
- Require re-authentication or step-up MFA for high-risk operations such as changing payment destinations, exporting sensitive data, managing privileged memberships and changing security settings.
- Avoid account-enumeration responses and do not expose secrets in URLs.

## 4. Tenant isolation and authorisation

- Resolve active tenant membership from verified identity and server-side membership records on every request.
- Treat a requested tenant selector as context only, never as authorisation.
- Enforce tenant scope in application queries and PostgreSQL Row-Level Security. Enable and FORCE RLS on all tenant-owned tables.
- Every policy must have appropriate USING and WITH CHECK predicates. Missing, invalid, expired, forged or membership-invalid context must return no access.
- Use short-lived, signed transaction context; keep signing keys unavailable to the runtime database role and outside source control.
- Ensure connection-pool transactions set context locally and clear it on commit/rollback. Test reuse of pooled connections.
- Enforce same-tenant foreign keys for creator, reviewer, approver, parent and referenced records.
- Check object-level permissions in addition to route-level roles. Prevent insecure direct object reference (IDOR) attacks.
- Separate owner, administrator, analyst, reviewer and read-only privileges. Separate high-impact duties where practicable.
- Audit role changes, invitations, membership removal, privileged access and denied access.
- Audit tables, views, materialized views, functions, triggers, background jobs, exports and administrative paths for RLS bypasses.
- Runtime roles must not be superusers, table owners or BYPASSRLS roles. Migration and emergency roles must be separate, tightly controlled and audited.
- Global identity records must remain self-only for runtime access; provisioning must use a controlled administrative path.

## 5. Data protection and cryptography

- Require TLS for all external connections and verify certificates. Disable insecure protocols and weak cipher configurations.
- Encrypt databases, backups, object storage and managed disks at rest using provider-managed or customer-managed key facilities appropriate to deployment.
- Store secrets in a managed secret store. Never commit credentials, private keys, signing keys or production connection strings.
- Separate development, test, staging and production secrets and accounts.
- Define key ownership, access, rotation intervals, overlap windows, emergency revocation and recovery procedures.
- Use modern, vetted cryptographic libraries and authenticated encryption; do not invent cryptographic algorithms or manage raw encryption primitives unnecessarily.
- Hash passwords only if the product ever manages passwords directly, using a current password-hashing algorithm and parameters; preferred design is managed identity.
- Redact tokens, credentials, personal data and sensitive payloads from logs, traces, error messages and analytics.
- Document data residency and encryption-key location for each deployment.

## 6. API and application security

- Validate every request against explicit schemas, including types, bounds, formats, enums and allowed fields. Reject unknown or unsafe fields where appropriate.
- Use parameterised database queries. Prevent SQL, command, template and path injection.
- Apply request body, upload, pagination, timeout and concurrency limits.
- Rate-limit authentication, imports, exports, search and computationally expensive endpoints.
- Configure strict CORS allowlists, secure cookies where used, appropriate security headers and a restrictive Content Security Policy for browser surfaces.
- Protect state-changing browser requests against CSRF where cookie authentication is used.
- Return generic client errors with correlation IDs; keep stack traces and internal details server-side.
- Apply safe output encoding and context-aware rendering to prevent XSS.
- Protect against SSRF, open redirects, path traversal, mass assignment, prototype pollution and unsafe deserialisation.
- Review every endpoint for authentication, tenant, role, object permission, validation, audit and abuse controls.
- Keep health endpoints minimal; never expose environment variables, configuration secrets or internal topology.

## 7. File, import and export security

- Store customer files in private object storage, never in public web roots, source repositories or browser local storage as the authoritative copy.
- Issue short-lived, narrowly scoped signed upload/download URLs after authorisation.
- Enforce file size, extension, MIME and file-signature allowlists; do not trust client-provided content types.
- Scan files for malware and parse them in isolated, resource-limited workers with patched libraries.
- Prevent archive bombs, oversized decompression, parser exploits and formula injection in CSV/spreadsheet exports.
- Validate CSV structure, row widths, headers, encodings, dates, currencies and numeric bounds before ingestion.
- Calculate content hashes; use idempotency keys and duplicate detection to prevent replay and double counting.
- Preserve source provenance and link derived values to source records and reviewer decisions.
- Strip unnecessary image metadata and restrict access to photographs or documents containing personal, property or access information.
- Define quarantine, rejection, retention, deletion and incident procedures for uploaded files.

## 8. Financial integrity, approvals and fraud resistance

- Use deterministic, versioned calculation logic; do not allow AI output to authoritatively set financial amounts, approvals or payment state.
- Preserve source lineage, calculation inputs, formula version, reviewer, timestamps and reason for changes.
- Require explicit human approval for high-impact mappings, allocations, baseline changes and other sensitive decisions.
- Use database constraints and transactions to prevent duplicate confirmations, over-allocation and invalid state transitions.
- Use idempotency for payment and webhook processing; verify signatures, timestamps and replay windows.
- Reconcile provider events and internal payment state. Treat delayed, duplicate and out-of-order events safely.
- Require step-up authentication and independent confirmation for changes to payout destinations or bank details.
- Maintain clear dispute, appeal and correction workflows. Preserve evidence and prohibit silent alteration of historical decisions.
- Never imply that management contribution calculations are audited or statutory profit unless independently validated as such.

## 9. Audit, monitoring and detection

Record security-relevant events including authentication outcomes, MFA and recovery changes, membership/role changes, sensitive reads and exports, file access, approvals, calculation changes, payment state transitions, administrative access and policy denials.

Audit requirements:
- Append-only or tamper-evident storage with restricted write and delete permissions.
- Trusted timestamps, actor, tenant, action, target, outcome, reason and correlation ID.
- No passwords, tokens, signing keys or unnecessary personal data in event payloads.
- Alert on anomalous login activity, privilege escalation, bulk export, unusual access patterns, repeated denial, key events and suspicious payment changes.
- Restrict audit-log access and log access to the logs themselves.
- Define retention, legal hold, deletion and customer access rules.
- Monitor service health and security signals without collecting excessive telemetry.

## 10. Privacy and responsible data lifecycle

- Maintain a data inventory describing data categories, purpose, source, legal basis as determined by the operator, recipients, storage location, retention and deletion method.
- Collect only information necessary for stated product functions. Avoid collecting sensitive personal data unless essential and properly justified.
- Provide clear privacy notices describing purposes, sharing, processors, international transfers, retention and user rights.
- Define tenant-controlled retention and deletion schedules, subject to applicable legal holds and obligations.
- Support access, correction, export and deletion workflows where legally applicable.
- Delete or irreversibly de-identify data when no longer required; propagate deletion to replicas, search indexes, analytics and subprocessors according to documented schedules.
- Establish processor/subprocessor inventory, contracts, security review and change notification.
- Conduct privacy impact assessments for payroll, employee, location, photo, AI and other high-risk processing.
- Do not use customer data to train AI models or for unrelated purposes without a clear lawful basis, transparent notice and required consent/contractual authority.
- Minimise AI disclosures: redact identifiers, send only necessary fields, use approved providers and contractual no-training/retention controls where available.
- Document data residency and cross-border transfer arrangements. Obtain jurisdiction-specific legal review before making compliance claims.

## 11. Infrastructure, dependencies and software supply chain

- Pin dependencies and commit a reproducible lockfile. Review and update dependencies on a defined cadence.
- Run static analysis, dependency vulnerability, secret, container and infrastructure configuration scans in CI.
- Generate a Software Bill of Materials (SBOM) for release candidates.
- Use supported base images, minimal runtime images, non-root containers and read-only filesystems where practical.
- Sign release artifacts where supported and protect release workflows and repository permissions.
- Require peer review for security-sensitive changes and protect the main branch.
- Keep production and CI credentials separate; use short-lived CI credentials and least privilege.
- Patch exploitable vulnerabilities according to severity and exposure, with documented exceptions and deadlines.

## 12. Backup, resilience and incident response

- Encrypt backups and restrict backup administration separately from production application access.
- Define recovery point and recovery time objectives with the eventual operator and infrastructure provider.
- Test restoration regularly, including database, object files, keys/configuration and audit continuity.
- Protect against ransomware and accidental deletion with isolated or immutable backup options where supported.
- Maintain incident playbooks for account compromise, tenant data exposure, secret leakage, ransomware, malicious uploads, payment fraud and provider outage.
- Define severity, escalation, evidence preservation, containment, recovery, customer communication and legally required notification responsibilities.
- Conduct tabletop exercises and record corrective actions.
- Do not claim backup or disaster recovery readiness until restoration has been demonstrated.

## 13. Secure development lifecycle

- Threat-model new features and material architecture changes.
- Perform security-focused code review for authentication, tenant scope, payments, imports, exports and cryptography.
- Add regression tests for every security defect.
- Keep test data synthetic; prohibit production personal data in development and CI.
- Require passing unit, integration, migration, security and build checks before release.
- Track findings with severity, owner, due date, remediation and retest evidence.
- Maintain a vulnerability disclosure contact and a documented process for receiving and resolving reports.

## 14. Assurance and release gates

A production release must not be approved until the accountable operator has evidence for:
1. Production identity provider, MFA, recovery and session controls.
2. Complete table-, endpoint- and object-level tenant isolation tests.
3. Runtime database privilege and RLS bypass review.
4. Secure private file storage, scanning and export protections.
5. Secrets custody, rotation and emergency revocation exercise.
6. SAST, dependency, secret and container scans with no unresolved release-blocking findings.
7. Backup restoration and incident-response exercise.
8. Privacy inventory, notices, retention/deletion and processor review.
9. Independent penetration test and remediation retest.
10. Documented residual risks and authorised risk acceptance.

A failed critical control blocks release. High findings require remediation or explicit, time-limited acceptance by the accountable operator; no developer may silently waive them.

## 15. Customer-facing security and privacy centre

The product may present a clear Trust Centre containing:
- Security architecture overview and tenant isolation explanation.
- Data categories, purposes, retention and deletion practices.
- Encryption and access-control descriptions that match actual deployment.
- Subprocessor and integration disclosures.
- Incident contact and vulnerability reporting process.
- Available assurance reports and dated assessment status.
- Downloadable security and privacy documentation.

Only publish claims supported by current evidence. Do not display certifications, audit badges, uptime guarantees, encryption claims or compliance assertions that have not been independently substantiated.

## 16. Acquisition and transfer requirements

- Maintain a complete architecture and data-flow map.
- Maintain a current data inventory, threat model, risk register and security test evidence.
- Document all infrastructure, identity, storage, monitoring and integration dependencies.
- Document key transfer/re-issuance procedures. Never transfer personal credentials or disclose live secrets in a sale data room.
- Provide a controlled ownership-transfer plan covering domain, cloud, database, identity provider, source control, signing keys, backups, processors and customer notices.
- Ensure IP ownership, third-party licences and processor terms are reviewable.
- Prepare a redacted security due-diligence pack; disclose sensitive architecture and vulnerability details only through controlled diligence.
- Require new-owner key rotation, access review and incident contact changes at handover.

## 17. Current repository evidence and known gaps

At the inspected baseline, the repository documents and tests:
- JWT/JWKS verification scaffold and tenant membership checks.
- HMAC-signed, short-lived transaction-scoped tenant context.
- PostgreSQL RLS and cross-tenant read/write denial tests.
- Runtime database role restrictions and global-user self-only RLS.
- Same-tenant actor foreign-key constraints.
- CI migration, API and container health checks.

The repository also explicitly records material gaps:
- No production environment or configured identity provider.
- No production user/tenant provisioning flow.
- No secure binary file upload, private object storage or malware scanning.
- Production HMAC key custody, recovery and operational rotation exercises remain unverified.
- Comprehensive all-table/all-endpoint adversarial isolation testing remains outstanding.
- Independent penetration testing, privacy impact assessment, retention/deletion verification, backup restore and incident exercises remain outstanding.

These limitations must remain visible until closed with evidence. Passing ephemeral CI is not equivalent to production assurance or independent certification.

## 18. Definition of done

A control is **Implemented** only when code/configuration is present and reviewed.
A control is **Tested** only when repeatable tests or documented operational exercises pass.
A control is **Verified** only when evidence has been reviewed against the requirement.
A control is **Independently assessed** only when a suitably qualified external assessor has performed and documented the assessment.
A control is **Not applicable** only with a written rationale and approval.

No aggregate security score may conceal a failed critical control. The Trust Centre and acquisition pack must report actual status, assessment date, scope, exceptions and residual risk.

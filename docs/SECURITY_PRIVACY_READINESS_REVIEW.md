# ProfitPilot — Security and Privacy Readiness Review

**Review date:** 16 November 2026  
**Status:** documentary readiness assessment; not an independent security audit, legal opinion, penetration test or release approval.  
**Repository:** `luxhustle01-ux/Profitpilot` (public). Synthetic fixtures only.  
**Build authority:** G0–G4 and competitive preconditions remain mandatory; G5 explicit signed GO remains the build gate.

## 1. Executive decision

**Decision: NOT READY for real customer data, private pilot or production.**

The repository has a meaningful prototype security foundation and a growing set of product, financial and privacy specifications. Two separate draft pull requests have passing CI on their respective exact heads. They are not integrated, and their evidence must not be conflated.

- **PR #25** contains security/database hardening on branch `security/exhaustive-hardening`, head `17178768002b978d6f5bd76f0192b2bbff7a4355`. Its CI run #310 passed both Node.js 22 verification and PostgreSQL migrations/tenant RLS.
- **PR #26** contains product and governance documentation on branch `product/six-differentiators-blueprint`, head `2aa3ecbd4cebd4ea379f5953b60a3177b26b1e6d`. Its CI run #335 passed both Node.js 22 verification and PostgreSQL migrations/tenant RLS.
- Both PRs are open drafts against the same `main` base SHA `55d1403c0dc34ac26a9bdb58107662754f34a8e3`. PR #25 is not part of PR #26's base. PR #26's passing PostgreSQL job therefore validates the database scaffold available on its own branch, not the security changes exclusive to PR #25.
- No PR has been merged, no production environment exists, no live data was loaded, and no storage/deletion/privacy control described only in documentation is implemented.

The immediate engineering dependency is controlled integration of the security branch with the product documentation branch, followed by full CI on the integrated candidate. Do not merge either PR merely because its current CI is green.

## 2. Evidence standard

Statuses used in this register:
- **PASS — CI evidence:** exact automated test evidence exists for the specified commit and scope only.
- **DOCUMENTED:** requirement or design is written; implementation is not established.
- **PARTIAL:** some prototype controls exist, but coverage or operational evidence is incomplete.
- **NOT IMPLEMENTED:** no functioning implementation evidence identified.
- **BLOCKED:** cannot be accepted until a named owner, external review, or additional evidence is supplied.

A green CI badge is not legal compliance, production security certification, independent assurance or evidence that unimplemented components are secure.

## 3. Branch and CI reconciliation

| Item | PR #25 security branch | PR #26 product/governance branch |
|---|---|---|
| Base SHA | `55d1403c0dc34ac26a9bdb58107662754f34a8e3` | `55d1403c0dc34ac26a9bdb58107662754f34a8e3` |
| Head SHA | `17178768002b978d6f5bd76f0192b2bbff7a4355` | `2aa3ecbd4cebd4ea379f5953b60a3177b26b1e6d` |
| PR state | Open, draft, not merged | Open, draft, not merged |
| CI run | #310 / run ID 43854035099 | #335 / run ID 43856738773 |
| Node.js 22 job | Passed | Passed |
| PostgreSQL migration/RLS job | Passed on PR #25 branch | Passed on PR #26 branch's own base/schema |
| What it establishes | Automated evidence for the PR #25 code and tests at its exact head | Documentation branch does not break its own CI baseline |
| What it does not establish | Independent penetration test, production readiness, storage/privacy implementation | PR #25 security changes are integrated, or governance requirements are implemented |

### Integration rule

1. Preserve both branch heads and their CI evidence.
2. A named technical owner must compare all changed files and migration ordering between PR #25 and current `main`.
3. Decide whether PR #25 is the accepted security baseline or needs changes before integration.
4. Rebase/retarget or merge in a controlled sequence only after reviewing conflicts, migration order, runtime grants, RLS policies and API contract changes.
5. Run the complete security workflow on the resulting integrated candidate SHA.
6. Run a fresh full test suite after any subsequent change; old CI results do not transfer to a new commit.
7. Do not merge or deploy without explicit user approval and the required G5 authorisations.

No automated mergeability indicator substitutes for this review.

## 4. Readiness register

| ID | Control domain | Current status | Evidence / gap | Release condition |
|---|---|---|---|---|
| SR-01 | Data inventory and C0–C3 classification | DOCUMENTED | Governance specification defines classes and examples; no implemented field-level inventory in a live system | Owner-approved inventory mapping every field, file, derived value and processor |
| SR-02 | Prohibited data (TFNs, sensitive data, card data) | DOCUMENTED | Design prohibits TFN/card ingestion by default; no deployed detection/quarantine control | Import validation and security tests prove prohibited content is blocked/quarantined |
| SR-03 | RBAC and action separation | DOCUMENTED / PARTIAL | PR #25 has role checks for implemented API decisions; complete view/import/approve/export/delete matrix is a specification | Implement and test every permission across UI/API/jobs/exports; separation-of-duty tests |
| SR-04 | Authentication and tenant context | PASS — CI evidence on PR #25 | JWT, signed tenant context, restricted runtime role and negative tests in PR #25 CI | Integrated branch verification, identity-provider/MFA configuration, account recovery review |
| SR-05 | Database tenant isolation | PASS — CI evidence on PR #25 | Catalogue and RLS tests for current protected tables on PR #25 head | Re-run after integration; add every new table/relationship and exhaustive catalogue drift checks |
| SR-06 | API object-level isolation | PASS — CI evidence on PR #25 | Implemented API route IDOR negatives covered by PR #25 test suite | Complete route inventory and tests for all future APIs, filters, reports, bulk endpoints |
| SR-07 | Tenant-safe foreign keys | PARTIAL | PR #25 adds actor-reference integrity; base schema has tenant composite-key gaps identified in database spec | Composite tenant FK on every tenant-owned relationship, with catalogue/negative tests |
| SR-08 | Private object storage | NOT IMPLEMENTED | No production private binary storage or authenticated file lifecycle | Private buckets, private ACL, encryption/KMS, tenant object authorization and lifecycle tests |
| SR-09 | Malware scanning and safe parsing | NOT IMPLEMENTED | No production quarantine/scanner/parser sandbox | Isolated scanning, archive limits, content checks, safe parser and malicious-file test corpus |
| SR-10 | Retention and deletion | DOCUMENTED | Schedule and customer-authorised deletion workflow specified; no deletion engine | End-to-end deletion across DB, objects, versions, caches, indexes, subprocessors and backups |
| SR-11 | Backup and restore | BLOCKED | No verified production backup/restore or deletion replay evidence | Restore exercise, RPO/RTO approval, deletion tombstone replay and proof no deleted data reappears |
| SR-12 | Access logging and monitoring | PARTIAL | Audit events and security test logging exist in prototype; no production SIEM/alerting/recertification evidence | Immutable/tamper-evident logs, sensitive-data redaction, alert tests and incident tabletop |
| SR-13 | Secrets and key management | PARTIAL | PR #25 documents signing-key handling and CI secrets; no managed production KMS/secret manager or recovery exercise | Managed key custody, rotation, access review, revocation and recovery evidence |
| SR-14 | Rate limiting and edge controls | PARTIAL | In-process limiter is not a shared multi-instance store; trusted-proxy config remains a blocker | Shared store, correct proxy trust, abuse tests and operational alerting |
| SR-15 | Identity provider, MFA and provisioning | NOT IMPLEMENTED for production | JWT validation scaffold exists; no production IdP/tenant provisioning/MFA/account recovery | Configured provider, MFA policy, lifecycle, recovery and revocation tests |
| SR-16 | Australian Privacy Act / APP applicability | BLOCKED | Governance design maps APPs; ProfitPilot coverage and each customer segment require legal analysis | Australian privacy counsel signs applicability assessment, notices, contracts and PIA |
| SR-17 | Employee records and TFN controls | DOCUMENTED / BLOCKED | Employee records exemption is not assumed; TFNs prohibited by default | Counsel review and technical proof of TFN detection/quarantine; worker privacy notice |
| SR-18 | Cross-border and subprocessor controls | NOT IMPLEMENTED | No complete hosting, backup, support, AI and subprocessor region register | Verified data-location map, contracts, APP 8 analysis and customer disclosure |
| SR-19 | NDB and incident response | DOCUMENTED / NOT IMPLEMENTED | Response expectations described; no tested operational plan | Named incident lead, escalation contacts, tabletop, evidence preservation and notification workflow |
| SR-20 | Automated decision-making transparency | BLOCKED | New APP 1.7–1.8 transparency rules commence 10 Dec 2026; AI feature inventory not final | Feature-by-feature legal assessment and privacy-policy update before relevant use |
| SR-21 | AI/OCR data protection | NOT IMPLEMENTED | No approved AI data flow, provider terms, region, retention or deletion evidence | Provider assessment, no-training/retention terms as required, scoped minimisation, tenant-separated retrieval and deletion test |
| SR-22 | Data export | DOCUMENTED / NOT IMPLEMENTED | Export authority and audit requirements defined; no complete controlled export workflow | Role-limited, step-up, expiring export with audit and redaction tests |
| SR-23 | Legal holds and retention exceptions | DOCUMENTED / NOT IMPLEMENTED | Decision workflow described; no legal-hold engine or review process | Hold authority, scope, expiry/review, restricted access and release evidence |
| SR-24 | Independent security assessment | NOT IMPLEMENTED | No independent penetration test or remediation retest | Qualified independent tester assesses integrated release candidate and all critical/high findings close |
| SR-25 | Accessibility and iPhone security UX | DOCUMENTED | Acceptance specification exists; no product end-to-end validation | Moderated usability/accessibility tests on target iPhones and assistive technologies |
| SR-26 | Operational readiness | NOT IMPLEMENTED | No production service, support, backups, on-call or incident operations | Named owners, support SLAs, monitoring, backup/restore, incident and release approvals |

## 5. Data governance minimum viable baseline

Before accepting any live customer export:
- approved C0–C3 field inventory and prohibited-data list;
- customer privacy notice and collection authority;
- contractually documented purpose, instructions, processors and retention;
- named tenant owner and data custodian;
- role grants for each operation and least-privilege defaults;
- import manifest, checksum, source lineage and retention class;
- private storage, malware scanning and quarantine;
- deletion, export and access-request workflows;
- audited access to C3 data;
- verified backup and restore process;
- tested tenant isolation across every current data surface;
- incident response and breach assessment contacts.

A controlled concierge trial using customer-authorised data must not bypass these requirements. If the proposed trial cannot meet them, use synthetic data or do not accept the export.

## 6. Required owners

These roles are not yet named. A single person may hold multiple roles only where conflicts are controlled.

| Role | Accountability |
|---|---|
| Product owner | Scope, purpose limitation, customer notices and release decision |
| Technical owner | Architecture, migrations, tenant isolation, implementation and test evidence |
| Security owner | Threat model, secure SDLC, incident response, independent testing and risk register |
| Privacy/legal counsel (Australia) | Privacy Act/APP applicability, contracts, employment/tax record retention, cross-border and NDB advice |
| Finance/accounting reviewer | Payroll source treatment, invoice/tax policy, calculation evidence and retention requirements |
| Customer data custodian | Customer authority, source accuracy, access approval and statutory record preservation |
| Operations owner | Support access, backup/restore, monitoring, deletion execution and service continuity |

## 7. Priority remediation sequence

### P0 — resolve before any real data
1. Assign named technical, security, privacy/legal and customer data owners.
2. Decide PR #25 security branch disposition and integrate it into a single reviewed branch.
3. Create a complete schema/API/object-storage/job inventory and close tenant composite-FK gaps.
4. Implement private object storage and quarantine/scanning before file upload.
5. Implement RBAC/ABAC for view/import/approve/export/delete and separation of duties.
6. Implement retention/deletion and backup restore with deletion replay.
7. Complete Privacy Impact Assessment, APP applicability and customer terms.
8. Run exhaustive tenant isolation tests and independent penetration testing.

### P1 — before paid pilot
1. Production identity provider, MFA and secure provisioning.
2. Managed secrets/KMS and shared rate limiting.
3. Access-log alerting, support JIT access and incident tabletop.
4. Subprocessor and cross-border data map.
5. Export, access/correction and deletion request operations.
6. AI/OCR provider assessment or disable AI processing for customer data.

### P2 — before scale
1. Automated access recertification and anomalous-access detection.
2. Tenant-specific key strategy where risk justifies it.
3. Automated retention/deletion evidence reporting.
4. Ongoing penetration testing, restore drills and privacy review cadence.

## 8. Release gates

- **No live data:** until all P0 controls applicable to the data flow are implemented and independently reviewed.
- **No private pilot:** until G0–G4 validation is passed, G5 signed GO exists, privacy/legal approval is recorded, operational owners are named, and critical/high security findings are closed or explicitly accepted by accountable owners.
- **No production:** until production identity, private storage, backup/restore, incident response, monitoring, support, independent penetration test, privacy/legal clearance and release approval are complete.
- **No payments or safeguarded-funds claims:** separate written legal and provider approval remains required.

## 9. Review sign-off

The following sign-offs are required and currently outstanding:
- [ ] Product owner
- [ ] Technical owner
- [ ] Security owner / independent security reviewer
- [ ] Australian privacy/legal counsel
- [ ] Finance/accounting reviewer
- [ ] Operations/incident owner
- [ ] Explicit user G5 build approval

No signatures or approvals are implied by this document.

## 10. Source documents

- `docs/THREAT_MODEL.md`
- `docs/ARCHITECTURE.md`
- `docs/DATA_DICTIONARY.md`
- `docs/FINANCIAL_DATA_CONTRACT_AND_DECIMAL_ARITHMETIC.md`
- `docs/FINANCIAL_DATABASE_SCHEMA_AND_MIGRATION_SPEC.md`
- `docs/DATA_CLASSIFICATION_PRIVACY_AND_TENANT_GOVERNANCE.md`
- `docs/RELEASE_AND_TEST_PLAN.md`

## 11. Final status

**Security engineering foundation:** partially implemented; PR #25 exact-head CI passed.  
**Product/privacy governance:** documented; PR #26 exact-head CI passed.  
**Branch integration:** not completed.  
**Private storage, malware scanning, production deletion and backup operations:** not implemented.  
**Australian legal/privacy approval:** not obtained.  
**Independent penetration test:** not performed.  
**Customer data, pilot and production:** not authorised.

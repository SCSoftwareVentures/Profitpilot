# ProfitPilot — Master Completion and Evidence Register

**Review date:** 16 November 2026  
**Repository:** luxhustle01-ux/Profitpilot  
**Visibility:** public; synthetic fixtures only  
**Purpose:** one authoritative view of what is documented, what has been tested, what remains unproven, who must supply evidence and what constitutes completion.

## 1. Executive status

**Overall status: NOT COMPLETE — pre-build validation and technical integration remain open.**

ProfitPilot currently consists of a product-validation specification, a partial API/database implementation scaffold, static UI concepts, security-hardening work on a draft branch, and a substantial product/financial/security design pack on another draft branch. It is not a complete customer-facing application, a deployed service, a verified accounting system or a commercially validated business.

The correct completion measure is evidence, not the volume of documentation or commits.

### Verified repository position

| Item | Exact position | Interpretation |
|---|---|---|
| Common base | main commit 55d1403c0dc34ac26a9bdb58107662754f34a8e3 | Both active PRs originate from this base |
| PR #25 | security/exhaustive-hardening; head 17178768002b978d6f5bd76f0192b2bbff7a4355; open, draft, unmerged | Application, database, CI and security hardening changes for review |
| PR #25 CI | Run #310; Node.js 22 and PostgreSQL migration/RLS jobs passed | Configured automated checks passed on PR #25's exact head |
| PR #26 | product/six-differentiators-blueprint; last fully CI-verified content head 559c7476d13e42ec9d9190409b8e3b091407a1bb; later changes limited to README/status documentation; open, draft, unmerged | Documentation-only product, validation, financial and governance design |
| PR #26 CI | Run #347; Node.js 22 and PostgreSQL migration/RLS jobs passed | Configured checks passed on PR #26's exact head and its own base |
| Branch relationship | PR #25 and PR #26 are sibling branches, not a combined candidate | PR #26's CI does not exercise PR #25's changes |
| Production | No production deployment or configured customer environment established | No customer data or production use authorised |

A passing CI run is limited to the tests and environment actually exercised. It is not a penetration test, finance/accounting sign-off, privacy approval, customer validation, or combined-branch integration test.

## 2. What is complete within the current preparation scope

The following are documentation or repository artefacts, not claims that the corresponding product capabilities exist in production:

- Initial market hypothesis and first customer segment.
- Concierge-first validation model and G0 evidence requirements.
- G1 customer discovery interview instrument.
- Competitive teardown and customer-stack scorecard.
- Six differentiator product blueprint and shared foundations.
- Initial navigation and core workflow specification.
- iPhone-first acceptance and resilience protocol.
- Architecture, data dictionary, threat model and core calculation specification.
- Financial data contract and decimal-arithmetic design.
- Static financial-engine audit and remediation backlog.
- Financial-engine technical design and logical database/migration specification.
- Payroll source-row allocation ledger design and 24 proposed cases.
- Financial executable acceptance-test plan, synthetic oracle and test-to-requirement traceability matrix.
- Data classification, privacy, tenant governance and security readiness review.
- Branch integration and migration reconciliation.
- MVP product requirements, iPhone screen/workflow specification, concierge execution playbook and commercial validation framework.
- Existing partial API/database scaffold, browser demonstration, Node.js tests and configured CI workflows on their respective branches.

These are preparation artefacts. None authorises production feature implementation or real customer data handling.

## 3. Gate register — no gate is presumed passed

| Gate | Required evidence | Current status | Evidence owner |
|---|---|---|---|
| G0 — data feasibility and competitive proof | 5 complete authorised export sets from 3 unrelated businesses; >=80% of sets pass all data, matching, effort and reconciliation criteria; 5 product teardowns; 2 customer-stack reviews; 2 customers confirm material recurring gap; 1 buyer confirms willingness to pay | NOT EVIDENCED | Founder/product lead, participating businesses, finance reviewer |
| G1 — problem validation | 20 interviews; 3 recruitment channels; founder-network share <=40%; >=12/20 independently identify the same material pain before product explanation; >=8 quantified recent examples | NOT EVIDENCED | Founder/product lead |
| G2 — workflow feasibility | 3 concierge trials across 3 businesses; at least 2 confirm the output informed or changed a real decision | NOT EVIDENCED | Founder/product lead, trial participants |
| G3 — willingness to pay | 10 qualified buying conversations; 3 paid concierge engagements or commitments | NOT EVIDENCED | Founder/commercial lead and buyers |
| G4 — prototype usability | 8 moderated usability sessions; 6/8 complete core tasks without facilitator rescue; median first insight <=30 minutes | NOT EVIDENCED | Product/UX lead and participants |
| G5 — explicit build authorisation | Signed GO, named technical owner, legal/privacy plan, delivery capacity and approved budget; preceding gates and competitive preconditions satisfied | BLOCKED / NOT APPROVED | Founder/authorised decision-maker plus named accountable owners |
| G6 — paid software-pilot exit | 3 paid pilots; 2/3 weekly use for 4 consecutive weeks; >=30% reconciliation-effort reduction or another pre-agreed outcome; zero unresolved critical defects; support and gross-margin model | NOT STARTED | Product, customer success, finance and pilot customers |

### G0 per-export-set pass definition

A unique, complete, authorised business/source-period bundle passes only when every condition is met:

1. At least 80% of the eligible payroll pool is attributable through direct source coding or an explicitly approved allocation method.
2. At least 80% of eligible invoice value is matched with medium/high evidence and human-confirmed contract/site/service-period mapping.
3. One-site baseline work is completed within 120 customer minutes and 180 analyst minutes.
4. Source row counts and monetary control totals reconcile under a documented currency, GST and rounding basis.

The minimum denominator is five unique complete sets across at least three unrelated businesses. Duplicate copies of the same underlying source period do not increase the denominator. Incomplete or unauthorised bundles remain visible but are not passes.

### G1 interview integrity

The interviewer must explore recent unaided behaviour before explaining ProfitPilot. A leading question, a polite expression of interest, or enthusiasm after a product pitch is not proof of problem validation. Retain contradictory and disconfirming evidence.

## 4. Technical integration register

| Priority | Item | Current conclusion | Required closure evidence |
|---|---|---|---|
| Critical | Branch integration | Two separate PRs with independent green CI | Reviewed combined candidate and CI on its exact SHA |
| Critical | Allocation-line contract | API calculation route references allocation_lines; reviewed schema does not define it | Approved row-level ledger, migration, grants, RLS and authenticated route tests |
| Critical | Exact money path | API calculation route still converts values to JavaScript Number and uses toFixed | Exact-decimal path end to end; static/code-path audit; DEC suite passes |
| Critical | Payroll ledger | Prototype schema is aggregate-oriented | PAYLED cases, per-source-row caps, evidence, approvals and immutable restatements |
| Critical | Contribution completeness | Current endpoint can emit a contribution figure with incomplete inputs | Required-source policy; suppress definitive amount/margin where material inputs are incomplete |
| High | Tenant relationship integrity | Composite tenant FK/catalogue verification must be reviewed on the combined schema | Complete FK inventory and cross-tenant negative tests |
| High | Original import files | Metadata registration is not binary upload or secure storage | Private object store, quarantine, malware scanning, retention/deletion, access logs |
| High | Distributed rate limiting | In-process limiter is not a shared multi-instance control | Shared store, trusted proxy configuration and distributed tests |
| High | Identity and secrets operations | CI exercises code paths but does not establish production identity or secret custody | OIDC/MFA configuration, KMS/secret manager, rotation and recovery exercises |
| High | Operations | No production recovery or monitoring evidence | Backup restore, incident tabletop, monitoring, support and on-call ownership |
| High | Independent assurance | Hosted CI is not independent assurance | Independent penetration test, remediation retest, finance and privacy/legal review |

Do not create a superficial allocation_lines table merely to make the route compile. The model must capture source-row identity, eligible amount, mutually exclusive buckets, source lineage, reviewer authority, per-row limits, currency/tax status and restatement history.

## 5. Product scope boundary

### Initial validated wedge

Contract economics reconciliation and exception control for Australian independent commercial cleaning contractors with recurring multi-site B2B contracts. The analysis grain is tenant × contract × site × service period × calculation version.

### Initial software scope after G5

- Identity, business workspace, memberships and roles.
- Customer, contract, contract version, site, service-period and scope records.
- Controlled import registration and, only after secure storage readiness, original-file intake.
- Source-row lineage, mapping review and reconciliation.
- Payroll pool and row-level allocation ledger.
- Supplier cost records and customer invoice lines.
- Human-reviewed invoice match candidates.
- Variation request/observation/approval history.
- Incomplete-aware management contribution and traceable exception reporting.
- Search, export, audit and mobile-safe workflows.

### Explicitly deferred or separately gated

- Payroll processing, award interpretation or statutory payroll calculation.
- General ledger, tax returns or audited/statutory profit.
- Bank ledger or custody of client funds.
- Escrow, stored value or marketplace payout without written legal/provider approval.
- Full marketplace, reviews, CRM or broad job-management suite as part of the first wedge.
- AI approval, automatic financial posting, dispute adjudication or money movement.
- Broad trade support before the initial segment is validated.

The six differentiators remain part of the product vision; they are not all mandatory first-release features.

## 6. Minimum release definitions

### Concierge validation release
A controlled, manually/script-assisted service with documented authority, data minimisation, secure handling outside this public repository, source reconciliation, human decisions, time measurement and written customer feedback. G0–G3 evidence is recorded independently.

### Private software pilot
Only after G5 and private-pilot controls: controlled deployment, real identity and MFA, tenant isolation, secure file lifecycle, retention/deletion, monitoring, backup/restore, incident response, legal/privacy review, full financial test suite, independent security review and named support owner.

### Commercial production
In addition to pilot exit: independent penetration-test remediation, operational SLOs, support model, customer contracts, export/deletion, tested disaster recovery, pricing/unit economics, monitoring, onboarding and explicit launch approval.

## 7. Decision and approval register

| Decision | Responsible owner | Required record | Status |
|---|---|---|---|
| Merge/rebase/stack PR #25 and PR #26 | Repository owner | Written branch strategy and approval | OPEN |
| Approve payroll pool inclusions/exclusions | Qualified payroll/accounting reviewer | Versioned policy and sign-off | OPEN |
| Approve GST/currency/rounding/FX policy | Qualified finance/tax reviewer | Policy registry and reviewed fixtures | OPEN |
| Approve data categories, lawful basis, retention and subprocessors | Privacy/legal owner | Privacy impact assessment, agreements and retention schedule | OPEN |
| Approve production identity, keys and infrastructure | Security/technical owner | Architecture and operations sign-off | OPEN |
| Authorise software implementation | Founder/authorised decision-maker | G5 signed GO and approved budget | NOT GRANTED |
| Authorise real customer data | Data/privacy owner and customer | Written authority and secure handling approval | NOT GRANTED |
| Authorise deployment/launch | Accountable release owner | Release evidence and explicit approval | NOT GRANTED |

## 8. Completion checklist

ProfitPilot is not “completely finished” until each applicable statement is evidenced:

- [ ] All validation gates G0–G5 have passed, with G5 signed.
- [ ] A single combined branch has passed the full integrated CI suite.
- [ ] Critical financial/schema/API defects are closed.
- [ ] Decimal, payroll, invoice, contribution, variation and import suites pass.
- [ ] Every result has source lineage, policy version and reproducible calculation run.
- [ ] Identity, MFA, roles, tenant isolation and secure file lifecycle are implemented and independently tested.
- [ ] Privacy/legal and specialist financial reviews are documented.
- [ ] Mobile usability, accessibility and failure resilience are verified.
- [ ] Backup/restore, incident response, monitoring and customer support are operational.
- [ ] Paid software pilots pass G6.
- [ ] Pricing, cost-to-serve, support capacity and gross-margin model are evidenced.
- [ ] Explicit commercial production release is approved.

## 9. Operating rule

This register is the single project completion control document. Update a status only when evidence is attached or referenced. “Designed”, “specified”, “in CI”, “passed in synthetic CI”, “independently reviewed”, “customer validated” and “production operational” are different evidence states; never collapse them.

The repository remains public. Synthetic data only. No PR merge, production deployment, real customer-data intake, payment activity or production feature build is authorised by this register.


## 10. Additional implementation-ready artefacts

The following documents close further preparation gaps but do not constitute implementation:

- [Initial MVP Product Requirements](MVP_PRODUCT_REQUIREMENTS.md) — functional requirements MVP-001 through MVP-065, user roles, scope boundaries, non-functional requirements and primary acceptance journeys.
- [iPhone-First Screen and Workflow Specification](MOBILE_SCREEN_AND_WORKFLOW_SPEC.md) — screen-by-screen behaviour, states, error paths and mobile/accessibility acceptance.
- [Concierge Pilot Execution Playbook](CONCIERGE_PILOT_EXECUTION_PLAYBOOK.md) — recruitment, unaided interviews, permission controls, G0/G2/G3 execution, customer deliverable, measurement and stop/pivot rules.
- [Commercial Model and Unit-Economics Framework](COMMERCIAL_MODEL_AND_UNIT_ECONOMICS_FRAMEWORK.md) — pricing structures to test, willingness-to-pay method, value measurement and unit-economics formulas.
- [MVP Implementation Epic Plan](MVP_IMPLEMENTATION_EPIC_PLAN.md) — dependency-ordered epics, roles, acceptance and estimation rules after G5.
- [API Calculation Path Static Audit](API_CALCULATION_PATH_AUDIT.md) — code-level financial route and engine findings with proposed route acceptance tests.
- [G5 Signed Build Authorisation Record](G5_SIGNED_BUILD_AUTHORISATION_RECORD.md) — approval template that remains blank until all prerequisites have evidence.

### Refined tenant-FK evidence interpretation

PR #25 CI run #310 includes a catalog-driven check that forces RLS on tenant-owned/root tables and inspects tenant-to-tenant foreign-key pairs for a composite tenant_id constraint. This is stronger than a simple static assertion and passed on the PR #25 review branch. However, the security branch remains separate from this documentation branch. The combined candidate must retain the catalog check, review the complete logical relationship inventory and test each relevant route/relationship; the existence of a composite constraint for a table pair does not by itself prove every semantic relationship or workflow is complete.

### Additional API calculation findings

Static inspection of the PR #25 review branch identifies two further material risks:
- revenue selection uses invoice issue date for period filtering while the match model carries service-period evidence; invoice date and service delivery period must not be assumed equivalent;
- contract baseline data has currency, but the reviewed schema does not carry the full explicit tax-basis metadata needed to prove compatibility with invoice amounts.

These are recorded in API_CALCULATION_PATH_AUDIT.md. Findings are static; proposed tests are NOT RUN.


## 11. Final status snapshot

PR #26 head 559c7476d13e42ec9d9190409b8e3b091407a1bb completed CI run #347 successfully on 16 November 2026. Both configured jobs passed: Verify (Node.js 22) and PostgreSQL migrations/tenant RLS, including authenticated API integration, container build and health check. This result applies to this documentation branch and its own base; it does not constitute combined PR #25/#26 integration or execution of the proposed financial acceptance suites.


## 12. API contract conformance audit

A static Express/OpenAPI comparison is recorded in [API Contract Conformance Audit](API_CONTRACT_CONFORMANCE_AUDIT.md). It covers the nine observed route declarations (including the operational health route), status/response schema gaps, import lifecycle terminology, pagination, idempotency, concurrency, role matrix and 16 proposed contract tests. These tests are NOT RUN; no runtime API or generated-client conformance is claimed.


## 13. Latest CI and owner demonstration — 17 November 2026

PR #26 latest head: `a72c03386b08cf4c18ef42573bf1b790c81be211`. Workflow run #355 completed successfully on that exact commit. Both configured jobs passed: Verify (Node.js 22) and PostgreSQL migrations/tenant RLS. PR #25 remains a separate open draft at `17178768002b978d6f5bd76f0192b2bbff7a4355`; neither PR is merged. No combined candidate has been validated.

A standalone synthetic HTML owner demonstration was provided in the conversation. It is not connected to the API or database and is not a deployed product. It does not test authentication, tenant isolation, import processing, persistence or the full financial engine. Its output must not be used as business accounting evidence.


## 14. CI run #357 — 17 November 2026

The latest documentation refresh commit `e5fdf2ae84247b0dde84a7f79df0e31649da3cb6` completed CI run #357 successfully. Both configured jobs passed: Verify (Node.js 22) and PostgreSQL migrations/tenant RLS. The PostgreSQL job completed migration/schema checks, restricted runtime role RLS checks, authenticated API integration tests, production container image build and health endpoint verification. This is a configured CI pass on the PR #26 branch only. It does not prove full financial-engine correctness, independent security assurance, combined PR integration, production readiness or G0–G5 completion. PR #25 and PR #26 remain open draft pull requests and neither has been merged.


## 15. Named technical owner and current CI — 17 November 2026

The project owner has named **Sammy Chehade** as the technical owner. This is a recorded designation, not a recorded acceptance/signature or evidence of available delivery capacity.

PR #26 head `5faa5957493c7f8349300895e0d4b5dc3d61cc08` completed CI run #359 successfully. Both configured jobs passed. The result applies only to PR #26's current documentation branch and its own base. It is not combined-branch validation and does not execute the proposed full financial acceptance suite.

The G5 record has been updated with the named technical owner and explicit outstanding fields. G5 remains **DEFERRED / NOT AUTHORISED** because G0–G4 evidence, competitive preconditions, budget, delivery capacity, legal/privacy plan, specialist approvals and formal decision-maker signature are not established. No software build, merge, deployment, real-data intake or payment activity is authorised.


## 16. PR #25 security and payroll ledger verification — 17 November 2026

PR #25 remains separate from this product/documentation branch. Its current reviewed head is `ce66bcf6f9a705532313ce6e71892839a3b55344`; hosted CI run #43971209376 completed successfully on that exact commit. Both Node.js 22 and PostgreSQL 16 jobs passed, including migrations, tenant/RLS/FK catalogue checks, restricted-role isolation, authenticated API integration, production API image build and container health check.

Changes now present on PR #25 include the tenant-scoped immutable payroll source-row ledger, append-only allocation lines with per-source-row over-allocation protection, confirmation-time source/pool/currency/summary/reviewer reconciliation, rejection of legacy unlinked allocation lines, and a database provenance guard tying payroll evidence to the same payroll import batch. Payroll ingestion remains blocked in the API until privacy-safe mapping and reviewer workflow exist. The calculation route uses cent-based decimal arithmetic, blocks partial payroll and invoice service-period overlaps, and deliberately withholds definitive contribution/margin because the cost model remains incomplete.

**Evidence boundary:** this is a passing CI result on PR #25 alone. It does not validate a combined PR #25/#26 candidate, the proposed full financial acceptance/property suites, a production environment, independent penetration testing, privacy/legal clearance, customer discovery or commercial gates. PR #25 and PR #26 remain open drafts; neither is merged. G0–G4 evidence remains outstanding and G5 remains DEFERRED / NOT AUTHORISED.



## 17. PR #25 import replay, financial basis and migration verification — 17 November 2026

PR #25 head `ff354de4418b4d471ca0e8cd881af4f9acf5ef78` passed hosted CI run #43973502209. Node.js 22 and PostgreSQL 16 jobs both passed on the exact head.

Verified additions:
- Import registration checksum reuse compares source type, file name, source period and permission reference; mismatches return conflict.
- Parsed-row ingestion supports explicit source row offsets for multi-request chunks, locks the batch during ingestion, and rejects changed content at existing row numbers while allowing identical JSONB retries.
- Strict invoice amount parsing avoids Number coercion; prototype monetary conversion rejects values outside safe cent representation.
- Invoice matcher confidence no longer grants medium confidence from weak partial identity alone; human confirmation remains mandatory.
- Prototype aggregate metrics reject missing or mixed currency, tax basis and reporting periods.
- Contract versions have explicit tax-basis metadata. Migration 012 safely adds the field for existing schema states, and calculations require invoice tax basis to match the contract version.
- CI and local Compose initialization include the new migration sequence.

Evidence boundary remains unchanged: PR #25 alone passed CI. PR #25/#26 have not been combined. The full financial acceptance suite, private object storage, production identity/MFA, managed key custody, shared rate limiting, independent penetration test, legal/privacy/accounting approval and G0–G5 validation remain open. G5 is DEFERRED / NOT AUTHORISED.


## 18. PR #25 calculation basis integration tests — 17 November 2026

PR #25 head `ce168020eb49667616e5c36f1cc9b324f92c22b5` passed CI run #43974141222, with both Node.js 22 and PostgreSQL 16 jobs green. New synthetic integration fixtures create fully reconciled invoice and payroll evidence and verify the API blocks invoice tax basis that differs from the approved contract version, and payroll allocation currency that differs from the contract currency. No definitive contribution is emitted from these mismatched inputs.

This closes only these two targeted negative cases. The full financial acceptance suite, source completeness, credits/reversals, payroll workflow, production security, independent review and G0–G5 validation remain outstanding. The branches remain separate and unmerged.


## 19. Superseding combined candidate and exact CI evidence — 17 November 2026

This section supersedes the earlier branch-position snapshots and the prior recommendation that no combined candidate existed.

### Combined candidate

| Item | Verified position | Interpretation |
|---|---|---|
| PR #25 | Security implementation source branch; open, draft, unmerged | Retain as a source/review branch |
| PR #26 | Product blueprint/documentation source branch; open, draft, unmerged | Retain as a source/review branch |
| PR #27 | `integration/pr25-pr26-validation`; head `47f0a5c3dc5a1e4f85b565b27195e5d217195c0a`; open, draft, unmerged | Combined review candidate |
| Branch-push CI | Run #43975153600 passed on the exact PR #27 head | Combined branch-push automated checks passed |
| Pull-request CI | Run #43975210049 passed on the exact PR #27 head | Combined PR-triggered automated checks passed |
| PR review | No submitted reviews or inline review threads found | Human review remains outstanding |

The pull-request CI run completed both configured jobs successfully: Node.js 22 verification and PostgreSQL 16 migrations/tenant RLS. The Node job completed locked dependency installation, production dependency audit, syntax checks and unit tests (45 passed, 1 skipped, 0 failed). The PostgreSQL job applied the migration sequence through 012, ran the tenant/FK catalogue audit, restricted-role RLS checks, authenticated API integration tests, production image build and restricted-container health check.

### What this evidence closes—and does not close

**Closed:** the previously missing combined-branch CI checkpoint for the current candidate SHA.

**Not closed:** the full financial-engine acceptance plan; independent penetration testing and remediation retest; independent accounting/payroll/tax review; Australian privacy/legal review; secure binary-file lifecycle; production identity/MFA and managed secret custody; distributed rate limiting; production operations/recovery; G0–G4 customer and commercial validation; G5 signed build authorisation; G6 paid-pilot exit.

### Current code-review observations

- Migrations 010/011 provide a tenant-scoped payroll source-row ledger, immutable source provenance, append-only allocation lines, source-row allocation caps and confirmation-time reconciliation. The API still does not expose the full privacy-safe payroll import, mapping, reviewer allocation and confirmation workflow; payroll ingestion remains disabled.
- Migration 012 adds versioned contract tax-basis metadata. Unknown legacy basis and invoice/contract basis mismatches are blocked, but the underlying GST/tax policy and conversion rules still need qualified approval.
- The calculation route uses decimal text parsing and BigInt cents for its arithmetic. It deliberately stores/returns an incomplete management view with `contribution` and `marginPercent` null and an explicitly indicative contribution value. This does not establish complete source coverage or an audited profit figure.
- A remaining exactness issue exists in `normalizePayrollRows`: finite JavaScript-number amounts are accepted and stringified. Number inputs may already have lost decimal precision; tighten this boundary to canonical decimal strings only and add regression coverage before enabling any payroll ingestion path.
- The passing CI unit tests are not the full DEC/TAX/PAY/PAYLED/INV/CON/VAR/IMP and property-based acceptance suite. That complete suite remains NOT RUN.

### Gate register remains unchanged

G0, G1, G2, G3 and G4 remain NOT EVIDENCED. G5 remains BLOCKED / DEFERRED / NOT AUTHORISED. G6 remains NOT STARTED. No merge, deployment, production feature build, live-data intake, customer pilot or payment activity is authorised. The repository is public; synthetic fixtures only.


### Latest documentation-reconciliation head CI — 17 November 2026

PR #27 branch `integration/pr25-pr26-validation` advanced to exact head `688d50bb5e3b45479f48f9cf7bb20e5897750291`. CI run **#43980939798** passed on that exact SHA. Both Node.js 22 and PostgreSQL 16 jobs passed. Node.js reported 46 tests total (45 passed, 1 skipped, 0 failed); PostgreSQL migration/RLS, tenant/FK catalogue, authenticated API integration, image build and restricted-container health steps completed successfully. This is the latest combined-candidate CI evidence, not the full financial acceptance suite, independent certification or release approval.

 
## 20. Follow-up implementation hardening — 17 November 2026

A separate draft branch `hardening/financial-security-followup` and draft PR #28 were created from the CI-verified combined candidate. The purpose is to remediate source-boundary and database-authority findings without merging or enabling payroll ingestion.

### Implemented on the hardening branch

- Exact-money parser accepts only decimal strings (no JSON Number coercion, exponent notation or malformed decimal syntax) and enforces PostgreSQL `numeric(14,2)` bounds.
- Monetary helper outputs remain canonical decimal strings; BigInt cents are not converted back to JavaScript Number.
- Invoice and payroll normalizers reject numeric JSON amounts; payroll output remains minimal and privacy-reduced.
- Production database configuration fails closed unless verified TLS is explicitly enabled; optional PEM CA configuration is supported.
- Migration 013 introduces restrictive database-side reviewer-role enforcement for invoice-match UPDATEs and a signed-actor identity check for any future runtime payroll confirmation.
- CI applies migration 013 and tests both direct SQL reviewer denial/permission and payroll reviewer-identity substitution rejection.
- A deterministic property suite exercises 500 seeded payroll reconciliation cases using seed `0x5eed1234`, plus row-order invariance, null/sign preservation and mixed-currency/tax-basis blocking.

### Verification evidence

The initial hardening CI run exposed one stale numeric assertion in the contract aggregation test. That test was corrected to expect the new exact decimal-string contract. The corrected implementation passed CI run #43982291906 on exact head `e4f2a024d245af86a58992eb8cc113e0d9a0801d`: Node.js 22 reported 51 passed, 1 skipped, 0 failed; PostgreSQL 16 passed migrations, 20-table tenant/FK audit, restricted-role RLS, authenticated API integration, production image build and restricted-container health. The property-suite addition is a subsequent change and requires its own exact-head CI result.

### Outstanding and deliberately blocked

- The full deterministic financial acceptance suite is not complete. The 500-case property suite is a targeted invariant suite, not the complete DEC/TAX/PAY/PAYLED/INV/CON/VAR/IMP acceptance plan.
- GST/FX, source inclusion, rounding, credits/reversals, denominator, service-period, payroll classification and variation policy still need named finance/payroll/tax approvers.
- Payroll ingestion remains disabled; no complete private-file import, source-row mapping/review/allocation workflow exists.
- Private object storage, quarantine, malware scanning, retention/deletion and backup deletion verification remain unimplemented.
- Production identity/MFA/provisioning/recovery, managed secrets/KMS, distributed rate limiting, production database TLS handshake, backup/restore, monitoring and incident response remain unverified.
- Independent penetration testing, finance/accounting review, Australian privacy/legal review, G0–G4 customer/commercial evidence and signed G5 GO remain outstanding. G6 has not started.

PR #28 remains draft and unmerged. No merge, deployment, real-data intake, customer pilot or payment activity is authorised.

 
### 21. Exact-money, reviewer authority and production TLS hardening — 17 November 2026

Draft PR #28 (`hardening/financial-security-followup`) now includes:
- canonical decimal-string-only parsing and formatting for the prototype financial engine, with PostgreSQL `numeric(14,2)` bounds;
- rejection of JSON numeric invoice/payroll amounts before float coercion;
- production database TLS fail-closed configuration with certificate verification and optional PEM CA;
- migration 013 restrictive reviewer-role enforcement for match-review UPDATEs and signed-actor identity binding for payroll confirmation;
- direct-SQL reviewer denial/permission and payroll reviewer-identity substitution integration tests;
- a 500-case seeded payroll reconciliation property suite, seed `0x5eed1234`;
- expanded OpenAPI money and response schemas.

CI run **#43982827602** passed on exact implementation head `ead10a236e33684c25c5c7613d1c5a2fbeb883fd`. The PostgreSQL job generated and enabled an ephemeral server TLS certificate, verified a trusted CA connection, rejected an untrusted CA, and successfully ran the API container in production mode with verified database TLS. Node.js reported 56 passed, 0 failed and 3 skipped (the DB-dependent API/TLS tests are run in the PostgreSQL job). PostgreSQL migrations/RLS, the 20-table tenant/FK catalogue audit, authenticated API integration, image build and production-mode TLS health check passed.

The subsequent OpenAPI-only documentation updates do not change application code; their exact-head CI is tracked by the current branch run. PR #28 remains draft and unmerged.

The full financial acceptance plan and all nontechnical release gates remain outstanding. Payroll ingestion remains disabled; no real customer or employee data is authorised.

 
### 22. Database-enforced invoice decision integrity — 17 November 2026

Migration 014 extends the previous reviewer-role controls:
- candidate/held invoice decisions may transition only to confirmed/rejected/held; final decisions are immutable;
- invoice, contract, site, service-period, confidence and evidence identity fields cannot be rewritten during a decision update;
- the signed tenant actor must be the recorded reviewer and hold active reviewer/admin/owner membership;
- a bounded, non-empty audit reason is mandatory;
- the database writes the audit event in the same transaction as the decision, so a failed audit insert rolls back the decision;
- the API now supplies the transaction-local audit reason rather than independently writing a second audit event.

PostgreSQL integration coverage checks direct-SQL audit creation, final-decision immutability, evidence-tampering denial and missing-reason denial. Migration 014 is included in CI after migrations 012 and 013. Exact-head CI for this newest migration and the test additions must pass before this control is considered verified. The earlier passing CI run predates migration 014 and must not be cited as evidence for it.

 
### 23. Migration 014 exact-head verification — 17 November 2026

GitHub Actions run **#667** passed on exact PR head `6b98299006d9aa620f494ec4fe52d095e82947c4`. The Node.js 22 job passed (59 tests, 56 passed, 0 failed, 3 skipped; database-dependent API/TLS tests are exercised in the PostgreSQL job). PostgreSQL 16 passed migration application through 014, tenant/FK catalogue audit, restricted-role RLS, authenticated API integration including the distinct invoice-line fixture and database-enforced reviewer/audit tests, production image build, trusted-CA TLS connection, untrusted-CA rejection and production-mode API health against verified TLS. This supersedes the earlier "exact-head CI pending" note for migration 014.

The PR remains draft and unmerged. This CI pass is software verification only; it does not close the independent security, financial, privacy/legal, operational, customer-validation or signed release gates.

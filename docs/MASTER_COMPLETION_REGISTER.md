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
| PR #26 | product/six-differentiators-blueprint; head 4ca08f6418cc498cd0e5db05565403ac837e75a7; open, draft, unmerged | Documentation-only product, validation, financial and governance design |
| PR #26 CI | Run #343; Node.js 22 and PostgreSQL migration/RLS jobs passed | Configured checks passed on PR #26's exact head and its own base |
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

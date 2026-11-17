# ProfitPilot

ProfitPilot is a proposed business operations and customer transaction-management platform. Its initial beachhead is contract economics reconciliation for Australian independent commercial cleaning contractors with recurring multi-site B2B contracts.

## Current status

ProfitPilot is an **unreleased software prototype and acquisition-readiness project**. The target product is contract-economics reconciliation and exception control for Australian independent commercial cleaning contractors with recurring multi-site B2B contracts. It is not a deployed SaaS service, an accounting/payroll replacement, a verified accounting system or a commercially validated business.

- PR #25 and PR #26 are historical source/review branches.
- PR #27 is the combined security/product-design integration candidate.
- PR #28 (`hardening/financial-security-followup`) is the current draft hardening branch, based on PR #27. It remains open, draft and unmerged.
- PR #28 contains exact decimal-string money boundaries, PostgreSQL TLS fail-closed configuration, reviewer/actor database controls through migration 014, property tests and related financial/security hardening.
- Current PR #28 CI evidence and its exact commit are recorded in the pull request. Passing CI proves only the configured automated tests on the stated commit; it is not independent security assurance, accounting/tax approval, privacy/legal clearance, customer validation or production readiness.

The browser dashboard is a **synthetic local demonstration**. It does not connect to the API, authenticate users, persist customer data or provide secure server-side import. Invoice CSV validation runs in the browser only. Payroll ingestion remains deliberately disabled.

## Initial validation approach

Begin with evidence-led concierge validation using authorised data and an approved secure handling route. Validate data feasibility, customer pain, repeatability, willingness to pay and usability before authorising a software build. Preserve G0–G6 gates.

## Core controls

- Primary analysis unit: contract × site × service period × calculation version.
- Payroll source total is authoritative for the pay period; site allocation remains a management allocation unless direct source evidence supports attribution.
- Payroll allocation must reconcile to source rows and the authoritative pool; residual is never silently spread.
- Invoice matches require evidence and human confirmation.
- Variations are candidates until explicitly approved.
- Unknown is not zero; incomplete data cannot produce a definitive contribution or margin.
- AI may assist extraction and explanation but must not authorise financial calculations, approvals, payments, disputes or ratings.
- Repository visibility is public. Synthetic fixtures only; never commit customer, employee, payroll, invoice, identity, credential or confidential commercial data.

## Project completion pack

- [Master completion and evidence register](docs/MASTER_COMPLETION_REGISTER.md)
- [MVP implementation epic plan](docs/MVP_IMPLEMENTATION_EPIC_PLAN.md)
- [G5 signed build authorisation record](docs/G5_SIGNED_BUILD_AUTHORISATION_RECORD.md)
- [API calculation path static audit](docs/API_CALCULATION_PATH_AUDIT.md)
- [API contract conformance audit](docs/API_CONTRACT_CONFORMANCE_AUDIT.md)

- [Master completion and evidence register](docs/MASTER_COMPLETION_REGISTER.md)
- [Initial MVP product requirements](docs/MVP_PRODUCT_REQUIREMENTS.md)
- [iPhone-first screen and workflow specification](docs/MOBILE_SCREEN_AND_WORKFLOW_SPEC.md)
- [Concierge pilot execution playbook](docs/CONCIERGE_PILOT_EXECUTION_PLAYBOOK.md)
- [Commercial model and unit-economics framework](docs/COMMERCIAL_MODEL_AND_UNIT_ECONOMICS_FRAMEWORK.md)
- [Financial-engine test traceability matrix](docs/FINANCIAL_ENGINE_TEST_TRACEABILITY_MATRIX.md)
- [Branch integration and migration reconciliation](docs/BRANCH_INTEGRATION_AND_MIGRATION_RECONCILIATION.md)
- [Six differentiators product blueprint](docs/SIX_DIFFERENTIATORS_PRODUCT_BLUEPRINT.md)
- [Security and privacy readiness review](docs/SECURITY_PRIVACY_READINESS_REVIEW.md)

## Existing project documentation

- [Project status](docs/PROJECT_STATUS.md)
- [G0 concierge pilot pack](docs/G0_CONCIERGE_PILOT_PACK.md)
- [G1 customer discovery interview guide](docs/G1_CUSTOMER_DISCOVERY_INTERVIEW_GUIDE.md)
- [Competitive teardown scorecard](docs/COMPETITIVE_TEARDOWN_SCORECARD.md)
- [Target architecture](docs/ARCHITECTURE.md)
- [Initial threat model](docs/THREAT_MODEL.md)
- [Release and test plan](docs/RELEASE_AND_TEST_PLAN.md)
- [Canonical data dictionary](docs/DATA_DICTIONARY.md)
- [Core calculation specification](docs/CORE_CALCULATION_SPEC.md)
- [Core UX workflows](docs/UX_WORKFLOWS.md)
- [Identity and tenant security plan](docs/IDENTITY_AND_TENANT_SECURITY.md)
- [Data classification, privacy and tenant governance](docs/DATA_CLASSIFICATION_PRIVACY_AND_TENANT_GOVERNANCE.md)
- [Financial engine audit](docs/FINANCIAL_ENGINE_AUDIT.md)
- [Financial engine remediation backlog](docs/FINANCIAL_ENGINE_REMEDIATION_BACKLOG.md)
- [Financial engine executable acceptance test plan](docs/FINANCIAL_ENGINE_EXECUTABLE_ACCEPTANCE_TEST_PLAN.md)
- [Financial database schema and migration specification](docs/FINANCIAL_DATABASE_SCHEMA_AND_MIGRATION_SPEC.md)
- [Payroll source-row allocation ledger design](docs/PAYROLL_SOURCE_ROW_ALLOCATION_LEDGER_DESIGN.md)
- [iPhone-first UX resilience acceptance](docs/IPHONE_FIRST_UX_RESILIENCE_ACCEPTANCE.md)

## Application prototype and development

- [PostgreSQL schema scaffold](database/schema.sql)
- [Prototype calculation/import engine](src/engine.js)
- [Interactive application prototype](app/index.html)
- [Core API contract (OpenAPI)](api/openapi.yaml)
- [Synthetic development seed data](database/seed_demo.sql)
- [Synthetic invoice CSV fixture](tests/fixtures/invoices_demo.csv)
- [QA verification matrix](docs/VERIFICATION_MATRIX.md)
- [Local development guide](docs/LOCAL_DEVELOPMENT.md)
- [Implementation audit](docs/IMPLEMENTATION_AUDIT.md)
- [Database migrations](database/migrations/)
- [GitHub Actions CI](.github/workflows/ci.yml)

The API/database are implementation scaffolds, not a deployed service. The browser prototype is a static/local demonstration and does not call the API. Import metadata registration is not original-file upload. Review the implementation and security audits before any use.


## Acquisition readiness

The owner's commercial objective is to explore a possible AUD 30,000–50,000 sale. This is a target, not an appraisal or a guaranteed market value. The acquisition-readiness workstream is documented in [ACQUISITION_READINESS_PLAN.md](docs/ACQUISITION_READINESS_PLAN.md). The plan prioritises a complete demonstrable product, financial acceptance evidence, security/privacy assurance, IP ownership and licence diligence, reproducible engineering handover and credible customer evidence.

## Product and release boundaries

- The initial scope remains contract × site × service period × calculation version.
- Payroll pool reconciliation, invoice matching and variations require source evidence and human approval.
- Unknown is not zero; incomplete source coverage must not produce a definitive contribution or margin.
- AI may assist extraction and explanation but must not authorise calculations, approvals, payments, disputes or ratings.
- Repository visibility is public. Use synthetic fixtures only; never commit customer, employee, payroll, invoice, identity, credential or confidential commercial data.
- No merge, deployment, real-data intake, customer pilot, payment activity or external buyer outreach is authorised by this repository status.

## Governance and release boundary

Software implementation remains blocked until G0–G4 and competitive preconditions are evidenced and G5 records an explicit signed GO with named technical ownership, legal/privacy plan, delivery capacity and approved budget. A passing CI run or completed design document does not substitute for those approvals.

No merge, deployment, live customer-data intake or payment activity is authorised by the documents.
 

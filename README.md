# ProfitPilot

ProfitPilot is a proposed business operations and customer transaction-management platform. Its initial beachhead is contract economics reconciliation for Australian independent commercial cleaning contractors with recurring multi-site B2B contracts.

## Current status

The repository is a product-validation specification and partial API/database implementation scaffold, not a complete or deployed customer application. Customer demand, legal/privacy clearance, production security and unit economics are not yet established.

**Current review branches:** PR #25 (security implementation) and PR #26 (product blueprint) remain separate draft, unmerged source branches. Combined review candidate PR #27 (`integration/pr25-pr26-validation`) passed CI run #43981149128 on exact head `44d199f6f55eaf4972e83fe68b71dade15f9d0ad`; Node.js 22 and PostgreSQL 16 jobs both succeeded. The Node job reported 45 passed, 1 skipped and 0 failed; the PostgreSQL job passed migrations/RLS, tenant/FK audit, authenticated API integration, image build and restricted-container health checks. The earlier combined code-bearing head `47f0a5c3dc5a1e4f85b565b27195e5d217195c0a` also passed branch-push run #43975153600 and pull-request run #43975210049. Further documentation-only audit updates may advance the branch; PR #27 records the exact latest head and CI status. This is automated CI evidence only—not full financial acceptance, independent assurance, customer validation or production approval. All three PRs remain draft/unmerged.

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

## Governance and release boundary

Software implementation remains blocked until G0–G4 and competitive preconditions are evidenced and G5 records an explicit signed GO with named technical ownership, legal/privacy plan, delivery capacity and approved budget. A passing CI run or completed design document does not substitute for those approvals.

No merge, deployment, live customer-data intake or payment activity is authorised by the documents.
 
**Current hardening review:** Draft PR #28 (`hardening/financial-security-followup`) targets the combined PR #27 branch, not `main`. The implementation and TLS verification head `30f0c9fa8937eea5fed537162750a5b7caafeb40` passed CI run #43983253747 (Node.js 22 and PostgreSQL 16). The current branch has a subsequent OpenAPI/error-schema documentation correction at `c031d73b89961c520df68ad33a82db388694d847`; exact-head CI for that latest documentation update is pending. This remains a prototype hardening PR, not release approval.

 
**Latest hardening verification:** Draft PR #28 targets the combined PR #27 integration branch. Exact head `6b98299006d9aa620f494ec4fe52d095e82947c4` passed CI run #43983962328: Node.js 22 and PostgreSQL 16 passed, including migrations through 014, reviewer-authority/audit integration tests, trusted/untrusted TLS certificate tests and production-mode database health. The product is still a prototype; full financial acceptance, private storage, independent reviews and release gates remain open. No merge or production launch is authorised.

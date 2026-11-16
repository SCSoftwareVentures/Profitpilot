# ProfitPilot — Project Status

**Baseline:** V8.6.1 Master Product Blueprint, dated 16 November 2026  
**Repository:** public working project repository; synthetic fixtures only  
**Status:** extensive product/validation/security/financial specification plus a partial API/database scaffold; not a complete or deployed application

## Current product decision

ProfitPilot's overall vision is a business operations and customer transaction-management platform. Its initial beachhead remains contract economics reconciliation and exception control for Australian independent commercial cleaning contractors with recurring multi-site B2B contracts.

The first delivery mode is concierge validation using authorised data and an approved secure handling route. The initial analysis unit is contract × site × service period × calculation version.

## Latest verified repository position — 16 November 2026

- PR #25 security branch: 17178768002b978d6f5bd76f0192b2bbff7a4355; open, draft and unmerged.
- PR #25 CI run #310 passed Node.js 22 dependency/syntax/unit checks and PostgreSQL migrations, tenant/RLS, authenticated API, container-build and health checks.
- PR #26 product blueprint: last fully CI-verified content commit 559c7476d13e42ec9d9190409b8e3b091407a1bb; subsequent changes were limited to README and project-status documentation; PR remains open, draft and unmerged.
- PR #26 CI run #347 passed Node.js 22 syntax/unit checks and PostgreSQL migration/RLS, authenticated API, container-build and health checks.
- The PRs are sibling branches against main commit 55d1403c0dc34ac26a9bdb58107662754f34a8e3. The CI runs are separate; neither proves a combined candidate.
- Neither PR has been merged. No production environment or customer pilot is established.

## Current repository contents

- Product overview, market hypothesis and G0–G6 validation gates.
- G0 concierge pack, G1 customer interview guide, competitive scorecard and concierge execution playbook.
- Six differentiator product blueprint and shared platform foundations.
- MVP product requirements, workflow specification and iPhone-first acceptance/screen design.
- Architecture, data dictionary, threat model and release/test plan.
- Financial engine audit, decimal data contract, technical design, schema/migration specification and remediation backlog.
- Payroll source-row allocation ledger design.
- Synthetic financial test oracle, executable acceptance plan and test traceability matrix.
- Data classification/privacy/tenant governance and security readiness review.
- Branch integration/migration reconciliation and master completion register.
- Static landing-page and dashboard concepts.
- Partial Express API, PostgreSQL schema/migrations, JWT/JWKS auth, tenant membership/role controls and RLS scaffold.
- Node.js 22 tests, PostgreSQL CI, authenticated API integration checks and Docker health smoke test on the security review branch.

## What is not established

- G0–G4 customer, data-feasibility, commercial and usability evidence.
- G5 signed build authorisation.
- Combined integration of PR #25 and PR #26.
- Complete financial engine or executable financial acceptance suite.
- Production-grade original-file upload/storage, malware scanning, retention and deletion.
- Configured production identity provider/MFA, managed secrets, distributed rate limiting and operational recovery.
- Independent penetration test and security remediation retest.
- Legal/privacy clearance, accounting/payroll/tax policy approvals.
- Live integrations or customer data processing.
- Production deployment, customer support readiness or positive unit economics.
- G6 paid software-pilot exit.

## Critical technical findings

- The reviewed API calculation route references allocation_lines, while the reviewed schema does not define the required row-level ledger.
- The API calculation path still uses JavaScript Number and toFixed for money.
- Payroll persistence is aggregate-oriented and cannot demonstrate source-row caps and provenance.
- Contribution may still be emitted when important inputs are incomplete.
- Tenant-bound relationship integrity must be verified on the combined candidate.
- Import metadata registration is not a binary upload or secure file lifecycle.
- The in-process limiter is not a shared production rate-limit control.

See the master completion register, financial test traceability matrix and branch integration report for closure evidence.

## Build-control rule

Do not treat repository setup, CI, documentation, HTML concepts or technical preparation as authorisation to build the SaaS.

Software build remains blocked until G0–G4 and competitive preconditions pass and G5 records explicit signed GO with named technical ownership, legal/privacy plan, delivery capacity and approved budget.

G6 is a post-build paid software-pilot exit gate.

## Repository safety

This repository is public. Never commit customer exports, employee-identifiable records, confidential contracts, credentials, API keys, payment secrets or private source documents. Use synthetic fixtures only. Real pilot data must remain in an approved private environment under written authority and documented handling controls.

## Additional completion package — 16 November 2026

The product-blueprint branch now also contains:
- Master completion and evidence register.
- MVP product requirements (MVP-001–MVP-065).
- iPhone-first screen/workflow specification.
- Concierge pilot execution playbook.
- Commercial model/unit-economics framework.
- MVP implementation epic/dependency plan.
- G5 signed build-authorisation template.
- API calculation path static audit.

These documents improve preparation and make the remaining work actionable. They do not provide missing customer evidence, specialist sign-offs, signed G5 approval, implementation or production readiness.

Latest CI on the prior docs-only head 559c7476d13e42ec9d9190409b8e3b091407a1bb (run #347) passed both configured jobs. The latest documentation commit passed run #347 on its exact head.

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

## Critical technical findings and current branch evidence

PR #25 remains a separate draft review branch. Its latest reviewed head is `ce66bcf6f9a705532313ce6e71892839a3b55344`, with CI run #43971209376 passing both configured jobs (Node.js verification and PostgreSQL migrations, tenant/RLS/FK audit, authenticated API integration, container build and health check).

The following earlier findings have been partly addressed on PR #25 and must not be repeated as if unchanged:
- The payroll source-row ledger now exists in migration 010, is tenant-scoped and immutable, and allocation lines are append-only with source-row caps.
- Migration 011 requires source-row reconciliation, currency consistency, reviewer authority, exact summary reconciliation, source-linked allocation totals and immutable confirmed runs.
- Payroll source rows are now required to reference raw evidence from the same tenant's payroll import batch as the payroll pool; invoice-import evidence is rejected.
- The calculation route now uses the migrated allocation ledger and decimal-string/BigInt cent arithmetic for its calculation outputs, blocks partial payroll-period and partial invoice-service-period overlaps, and withholds authoritative contribution/margin while the cost model remains incomplete.
- The database catalogue/RLS/FK and authenticated API tests pass on the PR #25 head.

Remaining material technical gaps include:
- Payroll source-row normalization exists as a pure helper, but no privacy-safe payroll ingestion, mapping, allocation-review or reviewer confirmation API is implemented; payroll row ingestion remains deliberately blocked.
- The calculation is still an incomplete management view; it excludes material cost categories and must not be represented as audited profit or a complete margin.
- Contract tax-basis compatibility metadata and approved tax treatment/conversion policy remain incomplete.
- Invoice evidence matching, service-period completeness, source manifests, credit notes/reversals, duplicate/replay controls and restatement workflows need further implementation and executable acceptance coverage.
- Secure binary upload/private object storage, malware scanning, retention/deletion and backup deletion verification are not implemented.
- Production identity/MFA/provisioning, managed secret custody, shared rate limiting, database TLS, backups/monitoring and incident response remain unconfigured.
- No combined PR #25/#26 candidate has been validated; independent CI passes do not prove branch integration.
- Independent penetration testing, Australian legal/privacy review, accounting/payroll policy sign-off and G0–G4 customer evidence remain outstanding.

See the master completion register, financial test traceability matrix and branch integration report for exact scope and release gates.

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

Latest CI on product-blueprint head `a72c03386b08cf4c18ef42573bf1b790c81be211` (run #355, 17 November 2026) passed both configured jobs: Verify (Node.js 22) and PostgreSQL migrations/tenant RLS, including the configured authenticated API integration and container checks. This is CI evidence for the PR #26 branch only; it is not combined-branch validation, production readiness or execution of the proposed financial acceptance suite.


## API contract conformance review — 17 November 2026

Added `docs/API_CONTRACT_CONFORMANCE_AUDIT.md`, a static comparison of the Express route inventory and OpenAPI contract. It records response-schema gaps, import-state language, missing pagination/idempotency/concurrency definitions, route-role matrix requirements and 16 proposed contract tests. This is not a runtime test or implementation. No API/OpenAPI code or production feature was changed.


## Owner test environment note — 17 November 2026

A separate downloadable HTML owner demonstration was supplied in the conversation. It is a local, standalone synthetic calculator and evidence-threshold walkthrough. It is not connected to this repository's API/database, does not implement authentication, tenant isolation, imports or persistence, and is not evidence that the financial engine has passed acceptance. Do not use real customer or employee information in it.


## Latest CI confirmation — 17 November 2026

The documentation refresh commit `e5fdf2ae84247b0dde84a7f79df0e31649da3cb6` completed ProfitPilot CI run #357 successfully. Both configured jobs passed: Verify (Node.js 22) and PostgreSQL migrations/tenant RLS. The PostgreSQL job completed schema/migration checks, restricted-role tenant RLS verification, authenticated API integration tests, production-image build and container health check. This remains PR #26 branch-only evidence; it does not validate a combined PR #25/#26 candidate or the proposed full financial acceptance suite.


## Latest CI and ownership update — 17 November 2026

The current PR #26 head `5faa5957493c7f8349300895e0d4b5dc3d61cc08` completed ProfitPilot CI run #359 successfully. Both configured jobs passed. This confirms the current documentation-branch checks only; it does not test a combined PR #25/#26 candidate or execute the proposed full financial acceptance suite.

The project owner named **Sammy Chehade** as technical owner. This records the designation only; acceptance, delivery capacity, budget and other accountable specialist owners remain unverified. G0–G4 remain unevidenced and G5 remains deferred/not authorised. No implementation, merge, deployment or live-data permission is implied.


## PR #25 verification update — 17 November 2026

The latest PR #25 head `ce66bcf6f9a705532313ce6e71892839a3b55344` passed CI run #43971209376. Both jobs passed, including the authenticated PostgreSQL/API integration suite and restricted production-container health check. The PR remains open, draft and unmerged. No combined branch validation, customer pilot, production deployment or G5 GO has occurred.



## PR #25 follow-up verification — 17 November 2026

PR #25 head `ff354de4418b4d471ca0e8cd881af4f9acf5ef78` passed CI run #43973502209 on the exact head. Both Node.js 22 and PostgreSQL 16 jobs passed. The PostgreSQL job includes migration 012, exhaustive tenant/RLS/FK catalogue checks, restricted-role isolation, authenticated API integration, production image build and container health.

Further verified branch changes include deterministic chunked invoice-row ingestion with conflict-safe replay semantics; full import-metadata comparison on checksum reuse; explicit contract-version tax-basis metadata matched against confirmed invoice tax basis; safe-cent bounds in the prototype money helper; and guards against aggregating mixed currency, tax basis or reporting periods. Contract tax basis defaults to unknown for legacy versions and blocks calculation until reviewed.

This remains PR #25-only evidence. PR #25 and PR #26 are still separate, open drafts. No combined candidate, full API-CALC-T01–T14 financial acceptance suite, independent security certification, production deployment, customer pilot or G5 GO is evidenced. Payroll ingestion remains disabled pending privacy-safe mapping and reviewer workflow.


## PR #25 calculation-basis integration regression — 17 November 2026

PR #25 head `ce168020eb49667616e5c36f1cc9b324f92c22b5` passed CI run #43974141222. Both Node.js 22 and PostgreSQL 16 jobs passed on the exact head. New authenticated API integration fixtures provide complete, reconciled synthetic invoice and payroll evidence and confirm that contract/invoice tax-basis mismatches and payroll/contract currency mismatches are blocked with 422 responses. This is additional branch-specific regression evidence, not the full API-CALC-T01–T14 suite or independent accounting validation. PR #25 and PR #26 remain separate drafts; G5 remains deferred/not authorised.

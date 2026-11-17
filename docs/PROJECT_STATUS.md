# ProfitPilot — Project Status

**Baseline:** V8.6.1 Master Product Blueprint, dated 16 November 2026  
**Repository:** public working project repository; synthetic fixtures only  
**Status:** unreleased prototype with a partial API/database implementation, a synthetic local dashboard and a substantial product/security/financial specification; not a complete or deployed customer application

## Current product decision

ProfitPilot's overall vision is a business operations and customer transaction-management platform. Its initial beachhead remains contract economics reconciliation and exception control for Australian independent commercial cleaning contractors with recurring multi-site B2B contracts.

The first delivery mode is concierge validation using authorised data and an approved secure handling route. The initial analysis unit is contract × site × service period × calculation version.

## Current verified repository position — 17 November 2026

- PR #25 and PR #26 are historical source/review branches.
- PR #27 is the combined integration candidate containing the security implementation and product blueprint.
- PR #28 (`hardening/financial-security-followup`) is the active hardening branch based on PR #27. It remains open, draft and unmerged.
- PR #28 exact head `e6fde42e3808cd5c269768c35619ede6d1361ecc` passed GitHub Actions run **#43988234834 (run #773)**. Node.js 22 reported 70 tests, 67 passed, 0 failed and 3 database-dependent skips; the PostgreSQL 16 job passed migrations through 014, 20-table tenant/FK audit, restricted-role RLS, authenticated API integration, production image build, trusted-CA acceptance, untrusted-CA rejection and production-mode database health.
- Dashboard work corrected the synthetic fixture's explicit currency/tax/period basis, removed floating-point currency display, made aggregation validity distinct from unverified source completeness, rejects empty/malformed aggregation inputs and uses null rather than NaN for invalid money. Browser-script syntax/local imports, basic keyboard focus, labelled CSV input, active navigation state and report limitations are covered by regression checks.
- An acquisition-readiness plan now defines the product, financial, security, IP, handover and commercial evidence required for a potential sale. The AUD 30,000–50,000 objective remains an aspiration, not a valuation.
- No PR is merged. No production environment or customer pilot is established. No deployment, real-data intake, payment activity or external buyer outreach is authorised.

The repository's current development objective is to produce a demonstrable, financially disciplined, security-conscious and transferable software asset. The owner's AUD 30,000–50,000 sale objective is a commercial target only, not an appraisal or guaranteed valuation. See [Acquisition Readiness Plan](ACQUISITION_READINESS_PLAN.md).

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

Owner instruction dated 17 November 2026 authorises continued code-level engineering hardening and synthetic prototype development in the repository. This does not constitute a signed G5 release GO.

Production customer-data features, secure live-data intake, merge to the protected release branch, deployment, customer pilot and payments remain gated until G0–G4 and competitive preconditions are evidenced and G5 records explicit signed GO with named technical ownership, legal/privacy plan, delivery capacity and approved budget.

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


## Superseding combined integration verification — 17 November 2026

The earlier repository-position sections above are historical snapshots and are superseded by this exact combined-candidate evidence:

- Repository: `luxhustle01-ux/Profitpilot` (public; synthetic fixtures only).
- PR #25 security implementation and PR #26 product blueprint remain separate open draft branches.
- Combined candidate: PR #27, branch `integration/pr25-pr26-validation`, exact head `47f0a5c3dc5a1e4f85b565b27195e5d217195c0a`.
- Branch-push CI run #43975153600 and pull-request CI run #43975210049 both passed on that exact head. The PR-triggered run's two jobs—Node.js 22 verification and PostgreSQL 16 migrations/tenant RLS—both completed successfully. The PostgreSQL job applied migrations 008–012, ran the tenant/FK catalogue audit, restricted-role RLS checks, authenticated API integration tests, production image build and restricted-container health check. The Node job completed locked dependency install, production dependency audit, syntax checks and unit tests (45 passed, 1 skipped, 0 failed).
- PR #27 has no submitted reviews or inline review threads at the time of this check. It remains draft and unmerged.

This closes the previously open **combined automated CI** checkpoint only. It does not close the full financial acceptance plan, independent penetration/security review, finance/accounting review, privacy/legal review, operational recovery exercises, customer validation or release gates.

### Current technical status and remaining work

- The row-level payroll evidence ledger is present in migrations 010/011, including tenant-scoped source provenance, append-only allocation lines, per-row limits and confirmation-time reconciliation. The pure payroll normalizer is present, but the end-to-end privacy-safe payroll ingestion, mapping, allocation-review and reviewer workflow is not implemented; payroll ingestion remains disabled.
- Contract-version tax-basis metadata is present in migration 012. Legacy `unknown` tax basis and invoice/contract mismatches are blocked; approved GST/tax policy and conversion rules still require qualified review.
- The calculation route uses decimal-string parsing and BigInt cents for its revenue/cost difference. It returns `completeness: incomplete`, `contribution: null` and `marginPercent: null`, with a separately named `indicativeContribution`. This is not a complete cost model or statutory/audited profit. Source completeness, supplier/non-site costs, credits/reversals, source manifests and restatement workflow remain open.
- Additional code-review finding: `normalizePayrollRows` accepts finite JavaScript-number amounts as well as strings, then converts numbers to strings. Because numeric values may already have lost decimal precision before this helper receives them, the exact-money boundary should be tightened to accept canonical decimal strings only, with a regression test. This is a remediation item, not a claim that the complete payroll pipeline exists.
- The configured CI runs do not execute the complete DEC/TAX/PAY/PAYLED/INV/CON/VAR/IMP and property-based acceptance plan. The financial acceptance suite remains NOT RUN as a complete suite.
- Private original-file storage/upload, quarantine and malware scanning, retention/deletion and backup deletion verification, managed production secrets/KMS, production identity/MFA/provisioning/recovery, shared distributed rate limiting, database TLS, backup/restore, monitoring and incident response remain unimplemented or unverified.

### Release gates

G0–G4 customer/data/commercial/usability evidence remains NOT EVIDENCED. G5 remains DEFERRED / NOT AUTHORISED: the signed decision, budget, delivery capacity, legal/privacy plan and accountable specialist approvals are absent. G6 has not started. No merge, deployment, real-data intake, customer pilot or payment activity is authorised. Preserve the public-repository synthetic-data-only rule.


## Latest combined-candidate documentation CI — 17 November 2026

The documentation reconciliation advanced PR #27 branch `integration/pr25-pr26-validation` to exact head `688d50bb5e3b45479f48f9cf7bb20e5897750291`. CI run **#43980939798** completed successfully on that exact head. Both configured jobs passed:

- **Verify (Node.js 22):** locked dependencies, production dependency audit, syntax checks; 46 tests total, 45 passed, 1 skipped, 0 failed. The skipped test is the authenticated API integration test in this job; that integration suite runs in the PostgreSQL job.
- **PostgreSQL migrations and tenant RLS:** completed successfully, including migration application, tenant/FK catalogue audit, restricted-role RLS checks, authenticated API integration, production image build and restricted-container health check.

This verifies the current combined candidate plus documentation reconciliation on its exact head. It does not execute the full financial acceptance plan or satisfy independent assurance, customer validation or G0–G5 release gates. PR #27 remains draft and unmerged.

 
## Hardening follow-up — 17 November 2026

Draft PR #28 `hardening/financial-security-followup` is correctly based on the combined PR #27 branch `integration/pr25-pr26-validation`, preserving PR #27 as the combined review candidate and isolating follow-up changes. It remains draft and unmerged.

Implemented on the hardening branch:
- exact decimal-string-only parsing/formatting in the prototype financial engine, including numeric(14,2) bounds and rejection of JSON numeric amounts;
- production database TLS fail-closed configuration with verified certificate validation;
- migration 013 database-enforced reviewer authority and signed-actor payroll confirmation identity;
- direct SQL role-boundary tests, payroll actor-substitution tests, and 500 deterministic property cases with seed 0x5eed1234;
- PostgreSQL CI now enables TLS on its ephemeral server, verifies a trusted CA, rejects an untrusted CA, and runs the API container in production mode against verified TLS;
- OpenAPI schemas and response contracts now describe exact money strings and the current partial API surface.

CI run **#43983253747** passed on exact implementation/documentation head `30f0c9fa8937eea5fed537162750a5b7caafeb40`. Node.js and PostgreSQL jobs both succeeded, including migrations 002–013, 20-table tenant/FK audit, restricted-role RLS, authenticated API integration, production image build, TLS trust/rejection tests and production-mode health check. The latest OpenAPI error-schema correction is commit `c031d73b89961c520df68ad33a82db388694d847`; its exact-head CI is pending.

The product remains **NOT COMPLETE**. Payroll ingestion stays disabled; the full financial acceptance plan, private file lifecycle, production operations, independent security/accounting/legal reviews, customer validation G0–G4 and signed G5 build approval remain outstanding. No merge, deployment, real-data intake or payment activity is authorised.

 
### Latest exact-head verification

GitHub Actions run **#667** passed on exact PR head `6b98299006d9aa620f494ec4fe52d095e82947c4`, including migrations through 014, reviewer decision immutability and same-transaction audit tests, PostgreSQL tenant/RLS checks, verified TLS trust/rejection and production-mode API health. The draft PR remains unmerged. Product completion and all external release approvals remain outstanding.

 
## Latest hardening CI — 17 November 2026

Draft PR #28 `hardening/financial-security-followup` targets the combined PR #27 branch. Latest verified head: `6b98299006d9aa620f494ec4fe52d095e82947c4`. CI run **#43983962328** passed both Node.js 22 and PostgreSQL 16 jobs.

PostgreSQL CI applied migrations through 014 and passed the tenant/FK catalogue audit across 20 protected/root tables, restricted-role RLS, authenticated API integration, production image build, verified TLS with a trusted CA, rejection of an untrusted CA and production-mode database health. Integration tests cover database-enforced reviewer roles, signed actor binding, immutable evidence/final decisions, mandatory audit reason and same-transaction audit events. Node.js job reported 56 passed, 0 failed, 3 database-dependent skips (executed in PostgreSQL job).

The complete product is still not ready for pilot or production. Payroll ingestion remains disabled; full financial acceptance, private file lifecycle, production identity/operations, independent penetration/accounting/legal review, G0–G4 customer evidence and signed G5 GO remain open. PR #28 remains draft and unmerged.


### Current PR #28 head — 17 November 2026

Exact head `5988ba408eae176cf5c69def1a9b5f4106e954c1` passed GitHub Actions run **#43984181421 (run #684)**. Both Node.js 22 and PostgreSQL 16 jobs succeeded, including migrations through 014, tenant/FK and restricted-role RLS checks, authenticated API reviewer/audit tests, production image build, trusted/untrusted TLS verification and production-mode database health. Product and production readiness remain NOT COMPLETE; all financial acceptance and external release gates remain open.


## Owner strategic direction update — 17 November 2026

The owner's primary commercial objective is to develop ProfitPilot into a complete, coherent, buyer-ready and reproducible software asset, with a preferred sale target of AUD 30,000–50,000. This is a target, not an appraisal, guaranteed valuation or ceiling on product ambition. Preserve the option to sell outright, license or pursue a strategic partnership; do not assume an operating launch is mandatory or that it has been permanently ruled out.

The build objective is to maximise evidence-backed strategic value through a polished synthetic demonstration, credible engineering and financial evidence, documented limitations, IP/licence diligence and a practical transfer/handover package.

**Financial authority remains constrained:** the owner's stated maximum initial budget is AUD 500 and comfortable recurring monthly budget is AUD 100. These limits remain in force unless the owner explicitly changes them. No purchase, subscription, contractor engagement, cloud commitment or other paid action is authorised by this strategy update. Engineering ambition is not spending authority.

A live owner-operated production launch, live customer pilot or recurring revenue is not a prerequisite for exploring a sale. Buyer confidence, reproducible setup, working synthetic demonstration, financial correctness, security architecture, transferability and credible market/buyer evidence remain priorities. No merge, deployment, real-data intake, buyer outreach, sale or transfer of ownership is authorised by this direction.

# ProfitPilot — Project Status

**Baseline:** V8.6.1 Master Product Blueprint, dated 16 November 2026  
**Repository:** working public project repository  
**Status:** product validation specification plus a partial API/database implementation scaffold; not a production application

## Current product decision

ProfitPilot's overall vision is a business operations and customer transaction-management platform. Its initial beachhead remains contract economics reconciliation and exception control for Australian independent commercial cleaning contractors with recurring multi-site B2B contracts.

The first delivery mode is a concierge validation service using secure, authorised data and manual/scripted reconciliation. The initial analysis unit is contract × site × service period.

## Current repository contents

- Product overview and scope
- G0–G6 validation gates
- Architecture and data-control principles
- Staged roadmap and initial risk register
- Static landing-page HTML concept
- Express API scaffold with JWT/JWKS authentication, tenant membership and role checks
- PostgreSQL schema, tenant RLS migration and ordered initialization scripts
- Import row persistence, invoice validation decisions, human-reviewed match decisions and evidence-gated calculation endpoints
- Node.js 22 engine tests and GitHub Actions CI
- PostgreSQL 16 schema/migration execution and HMAC-signed tenant RLS tests
- Authenticated HTTP API tests for membership, role restrictions, date validation and import idempotency
- Cross-tenant contract read/write negative tests, raw-GUC spoof rejection, HMAC signature/expiry/membership negative tests, private-key access denial, same-tenant actor foreign-key enforcement and pooled tenant-context cleanup test
- Production Docker image build and running-container database health smoke test
- Migration 008 narrows runtime writes to current endpoint operations, removes automatic grants on future tables and prevents runtime modification/deletion of raw evidence, calculation snapshots and audit events. Expanded tenant-table and foreign-object regression tests passed CI #2944 (commit bad8319).

- Import integrity: contiguous chunks, atomic conflict rejection, exact replay, serialized ingestion/validation and preserved review decisions; calculations use a consistent snapshot, full-period contract coverage and payroll currency checks. Regression tests passed CI #2945 and #2946. Legacy JSON ingestion remains client-declared; the new original-file route verifies actual bytes independently.

- Payroll prototype: structural validation, reviewer-attested controls, exact decimal whole-row allocations, residuals, tenant-scoped source lineage and duplicate reference rollback (migration 009). CI #2947 passed. Migration 010 introduces v0.2 split-source allocations, source-record foreign keys, reviewer-only write policies, draft-to-confirmed database validation and post-confirmation insertion protection. CI #2948 passed. Legacy/manual and v0.1 runs are not retrospectively validated; statutory payroll compliance remains outstanding.

- Migration 011: bounded UTF-8 CSV upload, server and PostgreSQL SHA-256 checks, metadata-only source receipts, original byte retention, atomic ingestion and post-receipt sealing. CI #2963 passed at cba35f2. Byte integrity is distinct from source issuer identity. No malware scanner, production encryption/retention or issuer signature claim.

## What is not established

- Customer demand or willingness to pay
- Repeatable lawful access to customer data
- Production-grade native application implementation
- Production deployment, exhaustive tenant-isolation assessment and independent security certification
- Excel or Google Sheets equivalence for the audit workbook
- Live integrations
- Legal/privacy clearance
- Payment-provider approval or safeguarded-funds structure
- Production security or operational readiness

## Build-control rule

Do not treat repository setup, HTML concepts, documentation, or technical preparation as authorisation to build the SaaS.

Software build remains blocked until G0–G4 and competitive preconditions pass and G5 records an explicit signed GO with named technical ownership, legal/privacy plan, delivery capacity and approved budget.

G6 is a post-build paid software-pilot exit gate.

## Immediate next work

1. Prepare and run G0 data-feasibility and competitive-proof work.
2. Obtain at least five complete, authorised export sets from at least three unrelated businesses.
3. Use the G0 pilot pack to control scope, permissions, data minimisation, source lineage and effort measurement.
4. Produce one-site contract variance bridges and record pass/fail evidence.
5. Stop or pivot if no lawful, repeatable source path exists.

## Repository safety

This repository is public at the time this status file was written. Never commit customer exports, employee-identifiable records, confidential contracts, credentials, API keys, payment secrets or private source documents. Keep any real pilot data in an appropriately authorised, secure environment under documented terms.

## Synthetic invoice identity rehearsal

The tenant-authorized synthetic preview is non-persistent and unauthenticated as to issuer identity. The conflict-classifier update holds every member of exact and alias conflicts without first-row preference. New unit/API regression tests require CI confirmation. Cross-batch database canonical identity enforcement and representative authorized source-owner validation remain outstanding.

## A1 architecture and specification baseline

Detailed internal design package and requirement catalogue added at [specification/README.md](specification/README.md). Design coverage is distinct from verified feature implementation and external approval. CI #2964 passed at 93acd20; new specification catalogue tests require current CI confirmation.

## Invoice identity reservation registry
Migration 012 introduces tenant-scoped, reviewer-only persistent identity reservations with unique exact/alias identities across batches, source-row/receipt lineage, immutable runtime records and review-only conflict reporting. Legacy invoice constraints are unchanged; no automatic promotion into financial calculations. API and database regression tests added; CI pending.

## Security hardening S1
Migration 013 independently restricts runtime roles and actor attribution, removes unused mapping mutation authority, and adds negative tests. HTTP authentication now requires bounded lifetime/subject and TLS JWKS outside tests; APIs use no-store and reject compressed JSON; imports use per-source scalar field allowlists. CI adds dependency audit and hardened container smoke. No live identity-provider MFA, production privacy assessment, recovery evidence or independent penetration test claimed. New CI pending.

S1 follow-up adds a runtime database field guard and a synthetic CI backup/restore rehearsal. Actual environment retention, subject access/erasure, key escrow and live disaster recovery remain unresolved.

## S2 privacy workflow
Migration 014 adds tenant-scoped self-service access/correction/erasure/restriction case tracking, with independent administrator review, audited transitions and idempotency. Closed-attested means externally attested, not independently verified fulfilment; no automatic deletion or data export. CI pending.

S2 introduces an explicit deployment profile, mounted-secret support, trusted MFA assurance and verified database TLS configuration. Protected profile requires enabled local scanning; actual deployments remain gated. Exact dependency lock generated by npm in CI #2973 and adopted with npm ci and lifecycle scripts disabled. Verification pending.

S2 migration 015 adds scanner-reported receipt status. A fixed local ClamAV executable consumes an exact bounded upload before storage; errors, infection and protected unscanned receipts fail closed. Protected profile uses MALWARE_SCAN_MODE=clamav. Actual scanner installation/signature verification remains an external deployment gate. Unit tests simulate process results, not live malware detection.

S2 privacy cases, lock and protected scanner changes passed CI #2975. S3 introduces encrypted synthetic recovery (wrong-key test and restored source hashes), optional native scanner image with harmless custom-signature rehearsal, pinned GitHub actions, CycloneDX dependency inventory, signed and independently verifiable GitHub build provenance for a source evidence package. This is not a signed production container release or a DAST/independent security assessment. CI results pending.

S4 migration 016 adds a narrow privileged disposal procedure with default hold, independently reviewed erasure case, scope/reference checks, known downstream-reference exclusion and atomic primary-database deletion verification. Self-access export is limited to own identity, current membership and own case metadata. CI pending; broader data-subject fulfilment, backup expiry and legal retention remain operational controls.

S4 adds pinned CodeQL static JavaScript analysis and Trivy container vulnerability reports with critical and fixable-high release gate. All severity reports retained, including unfixed findings; CodeQL analysis results require explicit review. Provenance depends on these jobs. CI pending.

CI #2978 passed application/privacy integration, encrypted recovery, native scanner and CodeQL, but failed before container scanning due to Trivy installer download failure. A checksum-pinned Grype release replaces the installer, in a dedicated no-database-secrets job; the same severity gate and full reports remain. Generated ephemeral CI secrets are now masked. New CI pending.

S5 addresses CI #2979 blocking container findings through patched Alpine packages and removal of npm/yarn/corepack from runtime images; exact app dependency lock remains. Added container tool absence, non-root and module-loading regression verification. New full CI pending; no release approval until verified.

S6 remediation targets remaining CI #2980 medium findings (single BusyBox wget CVE replicated across packages/images). Introduces Debian trixie-slim minimal runtime matched to Node builder, no BusyBox/npm/Yarn/Corepack, signed APT security updates, regular ClamAV packages and real dpkg inventory, with explicit absence/non-root/trust-store/module tests. CI pending; scan may reveal new distribution issues. Existing severity policy unchanged.

S6 Debian base experiment (#2981) produced an unacceptable vulnerability regression (9 critical, 265 high matches across images). Rejected; restore Alpine protected image and use signed minimal rootfs from scratch for prototype, preserve genuine package inventory. Also correct potential CodeQL type-confusion and path check/read race, add regression tests. Current workflow verification pending. Protected BusyBox update remains dependent on upstream or an independently validated alternative; no finding suppression.

S7 attempts removal of the last protected-image BusyBox findings using minimal signed clamav-scanner package closure, same Alpine rootfs as prototype, genuine inventory, absence checks and explicit missing-signature fail-closed testing. No gate weakened. New CI pending.

CI #2983 rejected clamav-scanner because the signed dependency chain pulled BusyBox. Replace CLI with a small bounded native stdin adapter compiled against signed Alpine clamav-dev, using only installed clamav-libs and clamav-libunrar in the final image. Preserve full real inventory, no shell/dependency bypass, native detection and missing-definitions tests. New CI pending.

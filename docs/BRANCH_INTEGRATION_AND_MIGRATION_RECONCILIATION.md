# Branch Integration and Migration Reconciliation

**Review date:** 16 November 2026  
**Repository:** `luxhustle01-ux/Profitpilot` (public)  
**Status:** review findings only; no merge, deployment, production code, schema migration or live-data operation authorised  
**Scope:** PR #25 security-hardening branch versus `main`, and PR #26 product-blueprint branch versus `main`.

## 1. Executive decision

**Do not merge either PR yet.** Both pull requests are open, draft and unmerged. Their latest reviewed CI runs passed, but the branches are independent siblings based on the same `main` commit. PR #26 therefore does not contain or validate PR #25's security and schema changes.

The next safe integration step is a controlled, reviewable integration branch or a deliberate rebase/stacking plan after the blockers below are resolved. This document does not create that branch and does not authorise a merge.

## 2. Exact branch and CI evidence

| Item | Reviewed revision | CI evidence | Result |
|---|---|---|---|
| `main` base | `55d1403c0dc34ac26a9bdb58107662754f34a8e3` | — | Common base |
| PR #25 `security/exhaustive-hardening` | `17178768002b978d6f5bd76f0192b2bbff7a4355` | Run #310 | Node.js 22 and PostgreSQL/RLS jobs passed |
| PR #26 `product/six-differentiators-blueprint` | `4a0ef298234f721531e476e81dbcfc3bd7c27d0d` | Run #337 | Node.js 22 and PostgreSQL/RLS jobs passed |

These are automated CI results on their respective branch revisions. They are not independent penetration-test evidence, accounting approval, privacy/legal sign-off, production deployment evidence or proof that the two branches work together.

PR #25 changes application, database, CI, dependency and security files. PR #26 changes documentation only (14 documentation files). The PR #26 PostgreSQL job validates the database state on its own branch/base; it does **not** exercise PR #25's new migrations or runtime role.

## 3. Dependency and integration map

1. PR #25 is the security/schema prerequisite for any later work that relies on its HMAC tenant context, runtime-role grants, JWT validation, revised import status or exhaustive RLS tests.
2. PR #26 is a documentation and product-definition layer. Its financial design documents are proposals and acceptance specifications, not implementation.
3. The two branches must not be treated as a single tested release. A combined candidate must include both exact reviewed revisions (or reviewed successor commits) and run the complete CI suite against the combined tree.
4. The public repository constraint remains in force: synthetic fixtures only. No real customer, employee, payroll, invoice, identity or confidential commercial data may be added.

## 4. Material technical findings from static branch review

### INT-01 — API/schema contract mismatch: allocation lines

**Severity: Critical integration blocker.**

The PR #25 API calculation route queries `allocation_lines` (including `allocation_run_id`, `tenant_id`, `site_id`, `bucket_type` and `amount`). The reviewed `database/schema.sql` defines `allocation_runs` but does not define an `allocation_lines` table, and the reviewed changed-file list contains no migration creating it.

The route therefore has an unresolved database dependency. The existing PR #25 CI passing does not establish that this calculation path works: the integration suite's success must not be extrapolated to unexercised route paths. Confirm by a direct schema/catalogue assertion and an authenticated calculation-route integration test on the combined candidate.

**Required resolution:** either implement and migrate the intended row-level allocation ledger with tenant-scoped keys, constraints, RLS, grants and tests, or remove/disable the route until that model exists. Do not fabricate aggregate allocation rows to satisfy the query.

### INT-02 — Financial arithmetic still crosses the JavaScript Number boundary

**Severity: Critical financial-release blocker.**

Although PR #25's `src/engine.js` introduces BigInt cent parsing for its `money()` helper, the API calculation route still converts PostgreSQL numeric aggregates with `Number(...)`, subtracts JavaScript numbers and uses `toFixed(2)`. This means the authoritative calculation path is not consistently using exact decimal arithmetic end to end.

The PR #25 engine parser also accepts exponent notation in its decimal helper; source parsing policy still needs to distinguish a canonical internal decimal from source-specific locale parsing. The existing route's use of Number is sufficient on its own to keep financial release blocked.

**Required resolution:** route all authoritative monetary values through the approved decimal abstraction as decimal strings/NUMERIC values, with explicit currency, tax basis, scale and operation-specific rounding policy. Add end-to-end tests proving no JS Number conversion occurs between source parsing, database retrieval, calculation, persistence, API response and export.

### INT-03 — Schema tenant relationships need a complete composite-FK audit

**Severity: High; security/data-integrity blocker until verified.**

Migration 006 adds tenant-membership composite foreign keys for actor/reviewer references. However, the base schema still contains several ordinary single-column references between tenant-scoped records (for example invoice lines to invoices; match reviews to invoice lines/contracts/sites; variations to contracts/sites; calculation runs to contracts/sites). A globally unique UUID primary key does not by itself prove that a row's `tenant_id` agrees with the tenant of its referenced row.

The security PR body describes tenant-to-tenant FK coverage checks. The combined candidate must demonstrate the exact intended invariant for every relationship, not merely that IDs are globally unique or that RLS hides rows.

**Required resolution:** enumerate every FK touching a tenant-scoped table from PostgreSQL catalogue output; add composite `(tenant_id, referenced_id)` constraints where the relationship is tenant-bound; explicitly document any intentional global reference. Add negative tests attempting cross-tenant references using privileged setup and runtime roles.

### INT-04 — Payroll allocation schema remains aggregate-oriented

**Severity: High financial-model blocker.**

The reviewed schema has aggregate amount columns on `allocation_runs`, but no row-level allocation ledger in the schema reviewed. The product blueprint and financial remediation design require source-row lineage, per-row caps, duplicate-allocation prevention, evidence, reviewer decisions and immutable restatements.

This is related to INT-01 but broader: creating a table solely to satisfy the API query is not sufficient. The ledger must reconcile to the authoritative payroll pool and preserve direct-coded, approved allocation, non-site, excluded and unallocated residual categories without double counting.

**Required resolution:** approve a canonical row-level allocation model and test source-row-level reconciliation, over-allocation, duplicate assignment, reviewer authority, tenant scope and restatement behaviour.

### INT-05 — Import metadata is not binary upload

**Severity: High product/security boundary; correctly disclosed but remains a blocker.**

PR #25 changes import status from `uploaded` to `registered` and accurately documents that the API stores metadata and parsed JSON rows, not original binary files. This is the correct representation. It also means there is no secure original-file upload/storage, quarantine, malware scanning, retrieval, retention or deletion pipeline.

**Required resolution:** keep the product/API wording truthful. Before real sensitive files are accepted, implement and independently test private object storage, authenticated upload/download, quarantine and malware scanning, retention/deletion, backup expiry/deletion replay and access auditing.

### INT-06 — Rate limiting is not horizontally shared

**Severity: High production operations blocker.**

PR #25 explicitly uses the in-process default rate-limit store. This is acceptable only as a limited prototype control. It does not provide a coherent shared limit across multiple API instances and needs trusted-proxy configuration before deployment behind a proxy.

**Required resolution:** select and test a shared store, configure trusted proxy hops explicitly, and test distributed limits and failure behaviour.

### INT-07 — Calculation completeness is not yet a reliable gate

**Severity: High financial-release blocker.**

The API currently requires at least one confirmed invoice line and one confirmed allocation line, but a non-empty pair of inputs is not proof that all material revenue and cost categories are complete. The route also records the calculation as `incomplete`, which is appropriately cautious, but still returns a contribution and margin figure. The UI/API must ensure such values cannot be mistaken for a complete result.

**Required resolution:** implement the documented completeness policy, required source coverage, exclusions and missing-category states. If the result is incomplete, label it as provisional/partial and suppress definitive margin claims where material inputs are unknown. Preserve the management-contribution-only boundary.

### INT-08 — RLS CI is not a substitute for full workflow coverage

**Severity: High assurance gap.**

The passing PR #25 CI is valuable evidence for its exercised migrations, tenant isolation fixtures, authenticated API cases and container checks. It does not automatically prove every route, every FK relationship, all import lifecycle states, financial calculation paths, object-storage paths, backups, exports, AI/OCR processing or support access are safe.

**Required resolution:** maintain a route × role × tenant × data-object test matrix; add the missing calculation/schema assertions; run the complete suite on the combined candidate; retain independent penetration testing and operational exercises as separate release gates.

## 5. Migration and integration sequence

The following is the recommended order, not an executed migration:

| Stage | Work | Exit evidence |
|---|---|---|
| A | Resolve INT-01 to INT-04: allocation ledger, exact decimal path, tenant-bound FKs and financial completeness | Reviewed logical schema, migration plan, rollback plan, executable negative and golden tests |
| B | Reconcile PR #25 migrations 008/009, runtime grants, import status, API/OpenAPI contract and CI order | Clean database from empty state; upgrade-path test from prior supported schema; grant/catalogue assertions |
| C | Create a combined candidate containing the reviewed security changes and product documentation | Exact base/head SHAs recorded; no accidental public sensitive data; deterministic dependency lock |
| D | Run all CI against the combined candidate | Both jobs pass on the combined SHA; calculation route and every migration exercised |
| E | Independent review | Security review/penetration test, accounting policy review, privacy/legal review, backup restore and incident exercise |
| F | Reassess G0–G5 and explicit approval | Named owner, legal/privacy plan, delivery capacity, approved budget and signed GO before any production feature build |

Do not reorder or squash migrations casually. Migration history, existing deployed schema assumptions, database-init ordering and rollback/forward-fix strategy must be checked against the exact target database state. No production database currently has been established by this review.

## 6. Required combined-candidate acceptance tests

- Build a database from an empty state using the exact combined migration sequence.
- Upgrade a database from the prior supported schema state and verify data-preserving migration behaviour.
- Assert every tenant-owned table has forced RLS and expected policies; assert every tenant-bound FK is composite or explicitly justified.
- Assert runtime grants for every table and sequence; verify no accidental write privilege appears for future tables.
- Exercise all authenticated API routes with owner, admin, analyst, reviewer and read-only roles.
- Exercise cross-tenant IDOR and cross-tenant FK attempts for contracts, sites, imports, payroll pools, allocation runs/lines, invoices/lines, match reviews, variations, calculations and audit events.
- Execute the calculation route against the actual migrated schema; fail the test if any referenced table/column is absent.
- Prove exact decimal outputs and negative rounding boundaries through API and persistence; prohibit Number-based authoritative money arithmetic.
- Test import metadata registration separately from binary file handling; do not describe parsed-row ingestion as original-file upload.
- Test idempotent imports, duplicate rows, concurrent decisions, replay, restatement and immutable audit history.
- Test backup restore, deletion replay, object storage and shared rate limiting when those systems exist.
- Run the entire suite on one recorded combined commit SHA.

## 7. Current recommendation and approval boundary

**Recommendation:** retain PR #25 and PR #26 as separate draft review branches. Resolve the critical integration and financial blockers before preparing a combined candidate. Do not merge either PR on the strength of separate green CI runs.

No merge, deployment, production feature build, live-data access, payment activity or external customer operation is authorised by this review. The G0–G5 validation and explicit G5 signed GO remain binding.


## 8. Updated PR #25 evidence — 17 November 2026

PR #25 has advanced to `ce66bcf6f9a705532313ce6e71892839a3b55344` and passed CI run #43971209376. The tested branch now contains migrations 010/011 for source-row payroll provenance and confirmation integrity, the calculation route's migrated allocation-line query and decimal-cent arithmetic, and explicit blocking of partial payroll and invoice service-period overlaps. Payroll row ingestion remains deliberately disabled; the API does not yet expose the complete payroll mapping/allocation/reviewer workflow.

This supersedes the earlier static description of the missing allocation_lines ledger and Number-based calculation arithmetic for the PR #25 head. It does not supersede the combined-candidate requirements in this report. PR #25 and PR #26 remain separate draft branches, and no full financial acceptance suite, combined-branch test, independent security review or production operation has been completed.



## 9. PR #25 latest migration and ingestion evidence — 17 November 2026

PR #25 head `ff354de4418b4d471ca0e8cd881af4f9acf5ef78` passed CI run #43973502209, including migrations 002–012, tenant/RLS/FK catalogue audit, restricted runtime role, authenticated API integration, production image build and restricted-container health check.

Migration 012 introduces explicit contract-version tax-basis metadata and defaults legacy versions to `unknown`; calculation creation blocks unknown or invoice-mismatched tax basis. Local Compose initialization now mounts migrations 010–012, and CI applies migration 012. Import registration and parsed-row ingestion now reject conflicting checksum metadata and changed row replays, support stable row offsets across chunks, and serialize writes per batch.

This is a PR #25 branch result only. It does not establish that the two PR branches compose cleanly. Keep the combined-candidate requirements above: one reviewed commit SHA, migration execution, full RLS/IDOR/FK suite, full financial acceptance suite, role matrix and independent security/accounting review. Both PRs remain separate drafts; no merge or deployment is authorised.


## 10. Calculation currency and tax-basis regression evidence — 17 November 2026

PR #25 head `ce168020eb49667616e5c36f1cc9b324f92c22b5` passed CI run #43974141222. The authenticated API integration suite now constructs complete synthetic source evidence and confirms calculation creation rejects both invoice tax basis mismatched to the approved contract version and payroll allocation currency mismatched to the contract currency. Node.js 22 and PostgreSQL 16 jobs passed on the exact head.

The combined-candidate requirement remains open. This is not the full API-CALC-T01–T14 suite, not a financial/accounting signoff, and not production certification. PR #25 and PR #26 remain separate drafts; no merge or deployment is authorised.

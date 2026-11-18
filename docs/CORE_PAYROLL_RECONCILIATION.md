# Core payroll reconciliation — engineering increment

**Version:** payroll-reconciliation-1.0.0. **Status:** synthetic-data domain implementation; not a live payroll ingestion or approval service.

The planner in `src/payroll-reconciliation.js` extends the existing decimal engine and source-row ledger design. It accepts an authoritative pool with period/currency/total, pre-minimised source rows and candidate allocation lines. All amounts are decimal strings. Stable source keys and SHA-256 values must match the existing normalizer's canonical row representation.

## Invariants
- Exact integer-cent arithmetic; every row and the whole pool must reconcile.
- Unknown rows, duplicate keys or row/bucket/site combinations, mixed currencies, malformed decimals, missing evidence references and over-allocation are held without a proposal.
- Site buckets require site references; non-site/excluded buckets cannot have one. Remaining value is emitted as explicit unallocated lines and prevents review readiness under the current database confirmation gate.
- Coverage uses direct plus proposed allocated site value divided by the authoritative pool, floor-rounded to basis points. A zero denominator gives null. This is a proposed allocation statistic, not validated evidence coverage.
- Order-independent canonical proposal SHA-256 binds version, pool, source rows, allocations, site totals and reconciliation totals. It is a content digest, not a signature or proof of source authenticity.
- No automatic approval, financial effects, database writes, or changes to role/tenant/security policy. The bucket label "approved_allocated" follows the database vocabulary but remains a proposal until a separately authorised reviewer confirms it.

Inputs are limited to opaque pre-minimised references and allowed fields. An identifier matching the syntax could still contain personal information; upstream mapping and privacy review must ensure actual opacity. Unknown input columns are rejected, not stored or echoed. Use synthetic fixtures only.

## Before integration
A trusted tenant-scoped service must resolve source and site references against persisted authorised evidence, enforce the existing import-intake and session controls, verify permission lineage, reject cross-tenant references, and require explicit reviewer approval bound to a persisted immutable proposal. Any mismatch, cancellation or revision requires a new version and an audit event. Production payroll ingestion remains disabled. No deployment, real data, release or merge is authorised by this change.

Tests: `node --test tests/payroll-reconciliation.test.js` (also discovered by npm test). Full branch CI must pass before marking the increment verified.


## Private persisted review ledger (migration 045)
- Submission references a pre-existing, accepted payroll batch, pool and complete unconfirmed allocation run. The database recomputes its own versioned evidence digest from persisted source and allocation records; the JS proposal digest is deliberately a separate format and cannot substitute for it.
- Checks require canonical minimal source rows, one-to-one raw/source linkage, a single pool per batch, reconciled per-row amounts, matching currency/period, valid allocation references, and no unallocated residual. An active hold blocks review.
- Same digest submission is idempotent. Reviewer must be a different active member of the same signed tenant with owner/admin/reviewer authority. The reviewed decision rechecks the current evidence digest under locks. Rejection records the historical proposal, not current evidence.
- Both records are append-only; audit events use the existing audit chain. A review receipt is **not** a confirmed allocation and has no financial effect.
- Private functions have no runtime EXECUTE grants and no new tables are readable by the application role. Hosted CI and local bootstrap include migration 045 in their ordered inventories; the security-catalog baseline advances to revision 45 only after verifying revision 44.
- The SQL acceptance test uses synthetic data and rolls back. CI execution is required before calling the database behavior verified.

**Remaining integration:** implement a dedicated least-privilege service and session/MFA-bound API, privacy-approved import mapping, evidence authenticity/permission review, final allocation confirmation bound to a fresh reviewed receipt, and concurrency tests before enabling any real data. The present database functions are administrator-only build candidates, not customer-facing operations. Do not deploy until retention, recovery and operational testing are complete.

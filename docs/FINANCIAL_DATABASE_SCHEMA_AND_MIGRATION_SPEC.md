# Financial Database Schema and Migration Specification

**Status:** proposed target schema and migration plan; not executable SQL and not an approved migration.
**Reviewed security baseline:** branch `security/exhaustive-hardening`, commit `17178768002b978d6f5bd76f0192b2bbff7a4355`.
**Reviewed product design:** branch `product/six-differentiators-blueprint`, commit `2343ec362b8080f5a40c7076da31c4738775356f`.
**Execution status:** static schema review only. No database was changed and no migration or SQL test was run.
**Build authority:** implementation remains blocked pending G5 signed GO and named owners.

## 1. Executive assessment

The existing `database/schema.sql` is a useful prototype scaffold, not yet a sufficient financial ledger schema. It has a tenant foundation, imports, payroll pools, aggregate allocation runs, invoice records, match reviews, variations, calculation runs and audit events. The most important gaps are:

1. Money columns are fixed at `NUMERIC(14,2)` and several records default currency to AUD. Neither precision nor default currency has been approved for every source/workflow.
2. Payroll allocation is stored as aggregate bucket totals; there is no source-row allocation ledger to enforce per-row caps, provenance or duplicate-allocation protection.
3. Invoice, invoice-line, match, variation and calculation relationships do not consistently use composite tenant foreign keys. A tenant ID on a row does not by itself guarantee its referenced parent belongs to the same tenant.
4. Raw import payload is stored as JSONB in the database scaffold. A production design needs explicit sensitivity controls, restricted raw-data storage, retention and deletion.
5. Mapping decisions, match reviews and calculation outputs need stronger immutable history/version semantics.
6. Calculation run inputs/outputs are JSONB and the completeness state is too coarse to establish financial reproducibility or explain included/excluded sources.
7. The schema does not yet represent the complete canonical source reference, policy registry, exact decimal contract or immutable restatement graph.

The design below is additive in concept. It does not prescribe a blind rewrite or assume historical data can be safely converted.

## 2. Reviewed current schema inventory

The security branch currently defines:
- Identity/tenancy: `tenants`, `users`, `tenant_memberships`.
- Master data: `businesses`, `sites`, `contracts`, `contract_versions`.
- Import: `import_batches`, `raw_import_rows`, `mapping_decisions`.
- Payroll: `payroll_pools`, `allocation_runs`.
- Invoices: `invoices`, `invoice_lines`, `match_reviews`.
- Variations: `variations`.
- Results/audit: `calculation_runs`, `audit_events`.

Migration 008 restricts runtime DML to the currently implemented API operations. Migration 009 corrects metadata-only import status from `uploaded` to `registered`; the API does not store binary file bytes. The security branch's later actor-reference integrity work is described in its implementation audit; confirm the exact composite foreign keys in the migration chain and catalogue tests rather than inferring them from the base `schema.sql`. These migrations are branch-specific until PR #25 is merged.

## 3. Schema audit — findings and proposed treatment

| ID | Current design issue | Risk | Proposed treatment |
|---|---|---|---|
| DB-01 | Monetary fields use `NUMERIC(14,2)` without approved maximum/scale policy | Overflow or premature precision loss; unsupported source precision silently excluded | Finance/technical owner approves bounds; store exact source decimal text and validated canonical numeric value |
| DB-02 | Currency defaults to AUD in contract versions, payroll pools and invoices | Missing source currency may be silently treated as AUD | Remove defaults on monetary source entities; require explicit validated currency or HELD state |
| DB-03 | Payroll allocation run stores aggregate amounts only | Cannot prove per-row eligibility/caps or prevent one source row being allocated twice | Add immutable payroll source rows and allocation lines keyed to source row |
| DB-04 | Invoice and child references lack consistent composite tenant keys | Cross-tenant parent references may be representable at schema level | Add tenant-scoped unique keys and composite foreign keys for every tenant-owned relationship |
| DB-05 | Mapping decisions can be updated in place | Historical mapping/approval rationale may be lost | Append-only decision events with version/supersedes linkage |
| DB-06 | Match review has a mutable decision row and sparse evidence model | Confirmation can overwrite history; evidence provenance and concurrent review need controls | Separate immutable candidate snapshot from append-only review decisions |
| DB-07 | Variation evidence and approval stored in JSONB/single row | Cannot robustly preserve evidence lineage, approver authority and price/scope revisions | Separate evidence, approval and billing records |
| DB-08 | Calculation run stores JSONB inputs/outputs and only complete/incomplete | Hard to query or reproduce input set; status cannot express held/unknown/rejected | Typed immutable run metadata, source links, policy links, output rows and richer status |
| DB-09 | No policy registry | Historical result may not identify exact tax, rounding, parser or allocation policy | Versioned immutable policy registry and run-policy references |
| DB-10 | Raw import payload in JSONB | Excess sensitive data, broad access and deletion complexity | Separate restricted raw source storage and controlled references; minimise database payload |
| DB-11 | Audit events use a polymorphic target UUID without a target-table FK; the base schema's actor FK is not visibly composite | Target existence/tenant consistency needs an explicit design; actor integrity may be added by later migrations | Preserve polymorphic targets with an allowlisted target-type strategy and verify actor composite-FK migrations/catalogue tests on the exact branch; append-only grants/triggers |
| DB-12 | No explicit restatement graph or source checksum lineage on each source row | Cannot demonstrate historical reproducibility or safe correction | Import/file/row manifests, canonical source refs and immutable restatement links |

These are static design findings, not evidence of an observed breach or financial loss.

## 4. Target schema principles

1. Tenant identity is part of every tenant-owned primary/unique relationship and every foreign key between tenant-owned tables.
2. Monetary source values preserve the original raw text, declared source format, exact parsed decimal string, currency, tax basis and parser version.
3. No currency default. Missing currency is unknown/held, never assumed AUD.
4. Monetary database values use PostgreSQL `NUMERIC` only after supported precision/scale and bounds are approved. Never use floating point.
5. Source rows, mapping decisions, approvals, calculation runs, outputs and audit events are append-only or versioned. Corrections create new records.
6. Payroll pool source totals remain authoritative; site allocations are management allocations unless source evidence is direct-coded.
7. Candidate match/variation states do not affect confirmed financial totals.
8. Unknown is not zero. Incomplete/held results cannot be presented as definitive margin.
9. Every calculation output is linked to exact source rows, import versions, policy versions and engine commit.
10. RLS, composite tenant FKs and application authorization are complementary controls; none replaces the others.

## 5. Proposed logical relational model

This is a logical model, not migration-ready SQL. Names and exact column types remain subject to source and policy review.

### 5.1 Tenant and master data

Retain existing `tenants`, `users`, `tenant_memberships`, `businesses`, `sites`, `contracts` and `contract_versions`, subject to these changes:

- Add tenant-scoped unique keys on every parent referenced by tenant-owned children, for example `UNIQUE (tenant_id, id)`.
- Every tenant-owned child references parent via `FOREIGN KEY (tenant_id, parent_id) REFERENCES parent(tenant_id,id)`.
- Add a site/contract relationship or contract-site association table if one contract can cover multiple selected sites; validate that selected site belongs to the contract's business.
- Contract versions remain immutable after approval. Effective periods must not overlap for the same contract unless the domain explicitly supports parallel versions.
- Currency is mandatory and explicit; remove `DEFAULT 'AUD'` from financial source records and approved contract versions unless an explicit product policy is later approved.

### 5.2 Source manifests and imports

Proposed entities:
- `source_systems`: tenant, system type, source identity and declared locale/profile.
- `import_batches`: tenant, source system, source type, permission reference, source period, file checksum, import status, idempotency key, creator and timestamps.
- `source_file_manifests`: batch, checksum, byte size, media type, original filename, received timestamp, storage object reference, malware scan state and retention class.
- `raw_import_rows`: file manifest, stable source row identity/number, restricted raw payload reference, row checksum and source metadata.
- `mapping_decision_events`: raw row, proposed target, method/version, evidence, actor, decision, reason, timestamp and superseded event reference.
- `import_exceptions`: row, exception code, severity, state and resolution event.

Binary storage, malware scanning, retention and deletion are not implemented in the current scaffold. Do not store or describe a metadata record as an uploaded binary. Storage provider and retention design require separate security/privacy approval.

### 5.3 Money and financial source facts

For each monetary source record retain:
- `amount_raw` (exact original source text);
- `amount_decimal` (canonical exact decimal text, validated);
- typed numeric amount only after precision/scale policy is approved;
- `currency_code` (explicit ISO currency);
- `tax_basis` (including UNKNOWN);
- `source_precision`;
- `parser_version` and `source_profile_version`;
- source row/file/import references;
- status VALID/HELD/UNKNOWN/REJECTED.

Do not store only a rounded two-decimal amount if the source contains more precision. The canonical decimal and approved rounding policy determine downstream values. Retain source precision even if the business operation later rounds.

### 5.4 Payroll ledger

Proposed entities:
- `payroll_pools`: authoritative source total, pay period, currency, cost basis, import reference and reconciliation status.
- `payroll_source_rows`: immutable payroll row source, raw amount reference, eligible amount, cost category and source identity.
- `allocation_runs`: method/policy version, status, creator, reviewer, period and immutable run metadata.
- `allocation_lines`: allocation run, source row, destination site or bucket, exact amount, allocation basis, evidence and decision state.
- `allocation_decision_events`: reviewer, decision, reason, role evidence, timestamp and superseded decision.
- `allocation_reconciliation`: source pool total, direct, approved allocated, non-site, unallocated residual, excluded, difference and status.

Constraints:
- Per-source-row total allocation must not exceed the eligible source-row amount.
- Same source row cannot be counted twice within the same confirmed allocation scope.
- Bucket types are mutually exclusive by policy.
- A confirmed run reconciles exactly to the authoritative pool under the approved policy.
- Residual remains explicit; never distribute residual automatically.
- Enforce row caps transactionally in application service and with database constraints/locking where possible; a simple CHECK on one row is insufficient to enforce aggregate caps across many allocation lines.

### 5.5 Invoice and match evidence

Proposed entities:
- `invoices`: direction, supplier/customer identity, invoice number/date, explicit currency/tax basis, source references and source total.
- `invoice_lines`: source row, line identity, raw description, quantity/price/tax/amount and canonical exact money.
- `match_candidates`: candidate invoice line, contract/version/site/service period, evidence snapshot, score/version, conflict state and candidate status.
- `match_decision_events`: candidate, reviewer, decision, reason, timestamp and expected version.
- `invoice_eligibility_events`: include/exclude decision for denominator, reason, policy version and source evidence.

A confirmed match requires an authorised human decision. Confidence and authority are distinct. Credits, duplicates, cancellations and conflicting candidates remain traceable. The denominator is versioned and must not silently change between reports.

### 5.6 Variations

Proposed entities:
- `variations`: observed/requested change and current lifecycle projection.
- `variation_evidence`: source references and evidence type.
- `variation_decision_events`: requested/approved/rejected/withdrawn event, authorised actor, reason, timestamp and approved scope/price snapshot.
- `variation_billing_links`: approved variation to invoice line and billed/reconciled status.

A candidate or observed extra task is not approved billable revenue. Approval must be role-checked and append-only.

### 5.7 Calculation runs and restatements

Proposed entities:
- `calculation_runs`: tenant, contract/version, site, service period, engine commit, formula version, status, created by/time and run hash.
- `calculation_run_sources`: run, source row, role (included/held/excluded), inclusion reason and source checksum.
- `calculation_run_policies`: run, policy type, immutable policy ID/version/hash.
- `calculation_outputs`: run, metric code, exact decimal value, currency, tax basis, unit and display metadata.
- `calculation_exceptions`: run, exception code, severity and resolution state.
- `restatement_links`: prior run, replacement run, reason, approver and timestamp.

Statuses should distinguish VALID, INCOMPLETE, HELD, REJECTED and RESTATED/SUPERSEDED. A restatement creates a new run; never update a historical output in place. Store output decimal strings or NUMERIC columns, not JSON numeric money.

### 5.8 Audit and policy registry

Proposed:
- `financial_policy_versions`: immutable policy type, version, content/hash, effective dates, approver and review evidence.
- `audit_events`: append-only event, tenant, actor/service identity, target reference, action, reason, timestamp, correlation ID and redacted metadata.

The runtime role must not update/delete audit history or policy versions. A privileged controlled process may append new policy versions but not rewrite prior ones.

## 6. Tenant integrity and access-control requirements

For every tenant-owned relation:
- include tenant_id in the child record;
- parent has a unique (tenant_id,id) key;
- child uses composite FK (tenant_id,parent_id);
- unique keys include tenant_id where uniqueness is tenant-local;
- RLS is enabled and forced where supported;
- runtime DB role cannot bypass RLS or alter policies;
- all API object-ID routes verify tenant ownership in SQL and application authorization;
- tests seed at least two tenants and prove both positive same-tenant access and negative cross-tenant access.

The current PR #25 security branch includes extensive RLS and API tests, but it remains a separate draft PR. Schema changes in this document must be reconciled with that exact branch before implementation; do not weaken or bypass its signed tenant-context controls.

## 7. Index and uniqueness plan

Candidate indexes, to be confirmed using query plans and realistic synthetic volumes:
- `(tenant_id, created_at DESC)` on import batches, audit events and calculation runs;
- `(tenant_id, source_system_id, checksum)` for import replay;
- `(tenant_id, batch_id, row_number)` unique on raw rows;
- `(tenant_id, payroll_pool_id, status)` on allocation runs;
- `(tenant_id, source_row_id, allocation_run_id)` on allocation lines;
- `(tenant_id, invoice_id, line_number)` unique on invoice lines;
- `(tenant_id, invoice_line_id, candidate_version)` on match candidates;
- `(tenant_id, contract_id, site_id, period_start, period_end)` on calculation runs;
- `(tenant_id, prior_run_id)` unique where a restatement policy allows only one direct successor.

Do not create indexes speculatively on every JSONB field. Define query patterns first. Partial unique indexes can enforce one confirmed decision per candidate or one confirmed allocation run per scope, but must reflect explicit business lifecycle rules.

## 8. Migration sequence and rollback strategy

No migration should be written until G5 and the policy decisions are approved.

### M0 — branch and schema reconciliation
- Decide PR #25 disposition and intended base SHA.
- Compare its exact schema and migration chain to current main.
- Resolve the current API/schema status vocabulary, including migration 009's registered-not-uploaded semantics.
- Record the source-of-truth migration chain and run checksums.

### M1 — additive source lineage
- Add source system, source file manifest and source-row reference structures.
- Add tenant composite unique keys/FKs to existing relationships.
- Backfill only relationships that can be proven.
- Quarantine unresolved/orphaned rows; do not invent tenant ownership.

### M2 — money contract
- Add raw source text, canonical decimal string, currency/tax basis/status/parser version fields.
- Do not backfill missing currency to AUD or tax basis to GST inclusive/exclusive.
- Mark unproven records UNKNOWN/HELD and exclude from authoritative aggregation.
- Choose NUMERIC precision/scale only after owner-approved limits and test vectors.

### M3 — payroll source-row ledger
- Add payroll source rows, allocation lines and decision history.
- Existing aggregate allocation runs cannot be expanded into source-row allocations without original row evidence. Preserve them as legacy aggregate records, mark provenance limitations and prevent them from satisfying new row-level acceptance criteria.

### M4 — invoice/match and variation histories
- Add line-level source links, candidate evidence snapshots and append-only review/approval events.
- Preserve existing decisions as legacy snapshots with unknown/missing provenance clearly identified.
- Do not infer reviewer evidence or authority where not recorded.

### M5 — calculation run provenance and restatements
- Add run-source links, policy versions, exact output rows, run hashes and restatement links.
- Existing JSONB outputs remain legacy snapshots. Do not recast floating-point serialized values as exact source amounts.
- Recompute only from source-exact inputs and approved policies; label reconstructed runs accordingly.

### M6 — enforcement and retirement
- Enable stricter NOT NULL, FK, CHECK, uniqueness and RLS requirements only after all records are reconciled or quarantined.
- Deploy dual-read/compare only in a controlled non-production environment.
- Remove legacy fields only after verified usage analysis, backup and rollback window.

### Rollback
- Prefer additive migrations and forward fixes over destructive rollback after data has been written.
- Every migration has a down/recovery strategy, but destructive down migrations must not discard new evidence.
- Take a verified backup and restore-test before production migration.
- Run migration against a disposable copy and test tenant isolation, constraints, query plans and API compatibility.
- Stop on any unexplained row loss, orphan, control-total mismatch or cross-tenant FK failure.

## 9. Required database acceptance tests

| ID | Test | Pass condition |
|---|---|---|
| DBT-001 | Tenant composite FK | Tenant-A child cannot reference tenant-B parent |
| DBT-002 | Tenant uniqueness | Same external ID may exist in two tenants only where policy permits; collision within tenant is rejected |
| DBT-003 | Explicit currency | Missing currency cannot be silently defaulted |
| DBT-004 | Decimal precision | Values at max bounds persist exactly; overflow/excess scale held/rejected |
| DBT-005 | Unknown semantics | UNKNOWN remains distinct from zero |
| DBT-006 | Payroll row cap | Concurrent allocations cannot exceed eligible source row |
| DBT-007 | Allocation idempotency | Duplicate command/import cannot create duplicate confirmed allocation |
| DBT-008 | Decision immutability | Review correction appends event and preserves prior decision |
| DBT-009 | Match tenant integrity | Candidate cannot reference another tenant's invoice, contract or site |
| DBT-010 | Variation authority | Unapproved variation cannot enter approved billing link |
| DBT-011 | Calculation source closure | Every output traces to run source and policy records |
| DBT-012 | Restatement | New run preserves prior run and links reason/approver |
| DBT-013 | Audit immutability | Runtime role cannot update/delete audit events |
| DBT-014 | RLS exhaustive | Every tenant table passes two-tenant positive and negative access checks |
| DBT-015 | Migration rollback | Restore/rollback preserves all pre-migration data and source checksums |
| DBT-016 | Replay reproducibility | Same source/policies/engine produces same exact output and run hash |

Each executed result must record commit SHA, migration version, PostgreSQL version, role, fixture version, seed, test counts and reviewer. No case is passed by this specification.

## 10. Open decisions requiring accountable owners

1. Maximum amount and numeric precision/scale for each money domain.
2. Supported currency codes and source-specific currency mapping.
3. Source locale profiles and whether source precision beyond currency minor units is retained.
4. GST/tax basis taxonomy and transaction-specific treatment.
5. Rounding mode and line-versus-total boundary per operation.
6. Payroll cost basis, inclusions/exclusions and pay-period rules.
7. Contract revenue basis and invoice coverage denominator.
8. Retention/deletion rules for raw payroll, invoice and employee data.
9. Storage provider, malware scanning and file access architecture.
10. Audit retention and privileged policy-change process.
11. Whether parallel contract versions/sites are valid business cases.
12. Named technical owner, finance/accounting reviewer and privacy/legal approver.

## 11. Current readiness decision

**Schema design:** proposed; ready for owner review, not migration authorisation.  
**Database implementation:** not authorised.  
**Data migration:** not authorised.  
**Customer data:** prohibited in public repository and current demo.  
**Pilot/production:** not approved.

The immediate next decision is to reconcile PR #25's security branch with PR #26's design branch and obtain accountable owners for the open financial, privacy and retention policies. Do not implement SQL or backfill financial values before those decisions are recorded.

# Payroll Source-Row Allocation Ledger — Detailed Design

**Status:** proposed domain and persistence design; not executable SQL and not an approved accounting/payroll policy.  
**Repository:** public; synthetic examples only.  
**Implementation authority:** blocked until G5 signed GO, named domain/technical owners and approved policies.  
**Purpose:** resolve the aggregate-only payroll allocation model and the missing `allocation_lines` API dependency without introducing a misleading table that merely makes the existing route compile.

## 1. Design decision

ProfitPilot should use a **source-row allocation ledger** as the authoritative record of how an imported payroll pool is classified and, where evidence supports it, attributed to sites.

The ledger must preserve five mutually exclusive accounting/management buckets:

1. `DIRECT_CODED` — source row itself identifies the site under an approved source mapping.
2. `APPROVED_ALLOCATED` — a human-approved allocation to one or more sites under a versioned allocation method.
3. `NON_SITE` — supported central or non-site cost.
4. `UNALLOCATED` — unresolved residual or insufficient evidence.
5. `EXCLUDED` — explicitly excluded from the defined eligible pool, with a reason and policy basis.

A bucket is a classification of source value, not a second copy of the payroll expense. Every cent of the authoritative pool must be represented exactly once across these buckets. A site-level allocation remains a management allocation unless the source itself directly codes the site.

Do not reuse the current aggregate `allocation_runs.direct_amount / allocated_amount / non_site_amount / excluded_amount / residual_amount` as if it were row-level evidence. Legacy aggregate runs may be retained for historical display with a visible provenance limitation; they must not pass the new row-level acceptance criteria.

## 2. Core invariants

For a payroll pool (P), let (E_r) be the eligible exact amount for source row (r), and (A_{r,b}) the amount assigned from row (r) to bucket/destination (b).

### 2.1 Source-row cap

For every source row:

[
sum_b A_{r,b} = E_r
]

when the row is fully classified, or:

[
0 leq sum_b A_{r,b} leq E_r
]

while the row is under review. The unclassified remainder must be represented as `UNALLOCATED`; it must not disappear.

No allocation may exceed the row's eligible amount. Negative source rows, credits, reversals or corrections require an explicitly modelled signed-value policy; do not silently clamp them to zero or treat them as positive allocations.

### 2.2 Pool reconciliation

The confirmed classification must reconcile exactly to the authoritative payroll source total, subject to a documented and approved treatment of source-level adjustments and precision:

[
DIRECT + APPROVED + NON_SITE + UNALLOCATED + EXCLUDED = SOURCE_POOL
]

If imported source rows do not reconcile to the payroll export control total, the pool remains `UNRECONCILED` or `HELD`. Do not make the difference disappear through a balancing allocation. Any source-level adjustment must itself be an evidenced, typed ledger item.

### 2.3 No double counting

A source-row amount can be split across multiple legitimate destinations, but the sum of all active allocation lines for that source row and allocation-run version cannot exceed its eligible amount. Replaying an import or confirming a run twice must not duplicate value.

### 2.4 Authority and provenance

- Direct-coded classification requires a source reference and versioned mapping rule.
- Approved allocation requires method version, evidence, reviewer identity, role/authority check, reason and timestamp.
- Candidate suggestions never enter confirmed site totals.
- A later correction creates a new allocation-run version and supersession/restatement link; it does not rewrite prior decisions.
- Every line links to tenant, payroll pool, source row, run, bucket, amount, currency, tax/cost basis, method and decision provenance.

### 2.5 Exact monetary representation

Use canonical decimal strings at API/domain boundaries and PostgreSQL `NUMERIC` only after precision/scale limits are approved. Do not convert authoritative amounts to JavaScript `Number`. Currency is explicit; never infer AUD from a missing source field. Unknown cost/tax basis is held from incompatible aggregation.

## 3. Proposed logical entities

Names are illustrative and require naming reconciliation against the existing schema.

### 3.1 `payroll_pools`

One authoritative imported payroll control total for a defined tenant, source, pay period and cost basis.

Required logical attributes:
- `tenant_id`, stable pool ID and import batch/source manifest reference;
- source period start/end and declared timezone semantics where relevant;
- exact source control-total amount and explicit currency;
- source row count, imported row count and checksum/control-total evidence;
- cost-component inclusion policy/version and exclusions;
- source reconciliation status: `UNRECONCILED`, `RECONCILED`, `HELD`, `SUPERSEDED`;
- created timestamp and source provenance.

A pool must not silently combine different pay periods, currencies, payroll entities or incompatible cost bases.

### 3.2 `payroll_source_rows`

Immutable representation of each source row in the pool.

Required logical attributes:
- `tenant_id`, pool ID, stable source row ID and source row number/identity;
- import batch and raw source reference/checksum;
- raw amount text, canonical exact amount, currency, source precision and parser/profile version;
- source earning/cost code and description as minimised/restricted data;
- direct site reference only where supported by source evidence and approved mapping;
- eligible amount and explicit inclusion/exclusion treatment;
- row validation state and exception references.

The source row is immutable. Corrections to parsing or mapping produce a new source interpretation/version linked to the original raw row; do not overwrite source facts.

### 3.3 `allocation_runs`

An immutable allocation attempt/version against one payroll pool.

Required logical attributes:
- tenant and payroll pool;
- run sequence/version and optional `supersedes_run_id`;
- allocation method and policy version/hash;
- status: `DRAFT`, `REVIEW`, `CONFIRMED`, `REJECTED`, `SUPERSEDED`, `HELD`;
- created by/time, confirmed by/time, decision reason and run hash;
- control totals and reconciliation status.

There may be one current confirmed run per pool under the chosen lifecycle policy, but historical confirmed runs remain available as superseded history. If parallel scenarios are needed, model them as explicitly non-authoritative scenario runs, not competing confirmed states.

### 3.4 `allocation_lines`

The ledger lines that classify source-row value.

Required logical attributes:
- tenant, allocation run, payroll pool and payroll source row;
- bucket type: `DIRECT_CODED`, `APPROVED_ALLOCATED`, `NON_SITE`, `UNALLOCATED`, `EXCLUDED`;
- site ID only for site-attributed buckets; null for non-site, unallocated and excluded;
- exact amount, currency and declared cost/tax basis;
- allocation basis/method version and evidence references;
- line state: `CANDIDATE`, `APPROVED`, `HELD`, `REJECTED`;
- source-to-destination explanation and timestamps.

A direct-coded line must be consistent with the source-row site evidence. An approved allocation line must not be labelled direct-coded. A non-site or excluded line cannot carry a site ID. Exclusion requires a controlled reason code and policy reference.

A single source row may be split into multiple lines where justified (for example, 60.00 to Site A and 40.00 to Site B from a 100.00 eligible row), but the aggregate cap is enforced at the source-row/run level.

### 3.5 `allocation_decision_events`

Append-only human authority history:
- tenant, run and allocation line/source-row scope;
- actor identity and role snapshot/reference;
- decision, reason, timestamp and expected prior version;
- evidence references and policy version;
- superseded event reference.

Do not store only the latest reviewer and decision on a mutable row. A current-state projection may be materialised for efficient reads, but the event history remains authoritative.

### 3.6 `allocation_reconciliation`

A reproducible summary per run:
- authoritative pool total;
- source-row total;
- direct-coded total;
- approved allocated total;
- non-site total;
- unallocated total;
- excluded total;
- unresolved/held total;
- arithmetic difference and status;
- source row count and classified row count;
- policy/method version and calculation timestamp.

The summary is derived from ledger lines and stored for audit/performance only if it can be recomputed and verified. It is not a substitute for source-row detail.

## 4. Tenant-safe relational constraints

Every tenant-owned parent has a unique key on `(tenant_id,id)`. Child relationships use composite foreign keys, including at minimum:

- `payroll_source_rows(tenant_id,payroll_pool_id)` → `payroll_pools(tenant_id,id)`;
- `allocation_runs(tenant_id,payroll_pool_id)` → `payroll_pools(tenant_id,id)`;
- `allocation_lines(tenant_id,allocation_run_id)` → `allocation_runs(tenant_id,id)`;
- `allocation_lines(tenant_id,payroll_pool_id,source_row_id)` → source row with matching tenant and pool;
- `allocation_lines(tenant_id,site_id)` → `sites(tenant_id,id)`;
- `allocation_decision_events(tenant_id,allocation_line_id)` → allocation line with matching tenant.

The exact key shape must be designed to prevent a line from referencing a source row in a different pool even within the same tenant. Do not rely on UUID opacity alone.

Add row-level checks:
- amount is representable under the approved precision/scale and sign policy;
- bucket is in the controlled enum;
- site nullability is consistent with bucket type;
- approved lines have required evidence and decision linkage;
- excluded lines have a reason and policy reference;
- period and currency match the pool/source row.

RLS must be enabled and forced for all tenant-owned tables. Runtime grants must be explicit. The API must independently verify tenant and role authority. Database constraints, RLS and application authorization are complementary.

## 5. Aggregate-cap enforcement and concurrency

A simple row-level CHECK constraint cannot enforce the sum of many allocation lines against one source-row cap. The design therefore needs a transactionally serialized confirmation path.

Recommended confirmation transaction:

1. Begin transaction at an isolation level selected and tested for this invariant.
2. Lock the target allocation run and all affected payroll source rows in deterministic ID order using row locks.
3. Re-read the current run state, source-row eligible amounts, existing lines and prior confirmed-run state inside the transaction.
4. Validate tenant scope, source pool identity, currency, cost basis, actor membership and reviewer role.
5. Recompute the sum of all candidate lines for each source row using exact database numeric arithmetic.
6. Reject if any row is over-allocated, any bucket/site combination is invalid, or the pool reconciliation does not meet policy.
7. Append decision events and transition the run to confirmed with an optimistic version/state check.
8. Commit atomically. On any failure, roll back all changes.

All code paths that create, amend or confirm lines must acquire compatible locks in the same deterministic order. If multiple runs can be confirmed concurrently for one pool, the pool itself must also be locked and the active-confirmed-run rule checked in the same transaction. A unique partial index can enforce one current confirmed run per pool only if the lifecycle model explicitly supports it.

A deferred constraint trigger or equivalent database-enforced procedure may be considered, but it must be reviewed for transaction semantics, deadlock behaviour, RLS interaction and privilege boundaries. Do not assume a trigger alone is correct without concurrency tests.

## 6. API/domain service contract

The API must call a domain service; routes must not implement payroll arithmetic or bypass the ledger.

Proposed operations (not implemented):
- preview an import pool and its source-row control totals;
- create an allocation run from a named pool and method version;
- add/update candidate allocation lines before confirmation;
- request approval with evidence;
- confirm/reject a run with reviewer authority;
- retrieve a run with line-level provenance and reconciliation;
- create a restatement/superseding run.

All monetary inputs/outputs are exact decimal strings. No `Number()`, `parseFloat()`, implicit coercion or `toFixed()` in the authoritative money path.

Candidate API actions must be idempotent and use explicit request IDs/version preconditions. Concurrent stale updates return a conflict requiring refresh; they must not silently overwrite another reviewer's decision.

## 7. Worked synthetic example

Authoritative pool: AUD 1,000.00. The source rows are:

| Source row | Eligible amount | Evidence |
|---|---:|---|
| PR-001 | 500.00 | Direct-coded Site A |
| PR-002 | 200.00 | Approved allocation method ALLOC-01 |
| PR-003 | 100.00 | Central office/non-site code |
| PR-004 | 150.00 | Site not established |
| PR-005 | 50.00 | Explicitly excluded under approved policy |
| **Total** | **1,000.00** | |

Expected ledger totals:
- Direct-coded: AUD 500.00
- Approved allocated: AUD 200.00
- Non-site: AUD 100.00
- Unallocated: AUD 150.00
- Excluded: AUD 50.00
- Difference to authoritative pool: AUD 0.00

The Site A direct-coded and approved allocated totals are distinguishable in reporting. The 150.00 residual is not spread over Site A or other sites. Excluded cost remains visible in the reconciliation.

Negative variant: split PR-002 into Site A 120.00 and Site B 80.01. Expected: reject confirmation because total allocation 200.01 exceeds the eligible source-row amount by 0.01.

## 8. Required executable acceptance tests

All tests below are proposed and **NOT RUN**. They require synthetic fixtures and a named combined application/database commit.

| ID | Scenario | Expected result |
|---|---|---|
| PAYLED-001 | Fully classified source row | Exact source-row equality; run can proceed to review |
| PAYLED-002 | Partially classified row | Remainder explicitly unallocated; no disappearance |
| PAYLED-003 | Over-allocation by 0.01 | Confirmation rejected; row and excess identified |
| PAYLED-004 | Same source row split across two sites within cap | Allowed only with approved method and reviewer decision |
| PAYLED-005 | Duplicate identical allocation line | Idempotent replay or explicit duplicate conflict; never double count |
| PAYLED-006 | Direct-coded row changed to another site | Rejected unless source mapping is corrected in a new version with evidence |
| PAYLED-007 | Unallocated/non-site/excluded line carries site ID | Constraint/service rejects |
| PAYLED-008 | Excluded line has no reason/policy reference | Confirmation rejected |
| PAYLED-009 | Source row from another tenant or pool | Composite FK/RLS/API deny |
| PAYLED-010 | Missing currency or mismatched currency | HELD; no assumed AUD or mixed-currency aggregation |
| PAYLED-011 | Source rows fail payroll control total | Pool held/unreconciled; no balancing line invented |
| PAYLED-012 | Two reviewers confirm concurrent runs for one pool | At most one active confirmed run; deterministic conflict outcome |
| PAYLED-013 | Two transactions allocate the same row concurrently | Aggregate cap remains satisfied; one transaction retries/fails safely |
| PAYLED-014 | Reviewer lacks approval role | Server and database authority deny; audit attempt without raw payroll payload |
| PAYLED-015 | Rejected allocation proposal | Decision retained; no effect on confirmed site totals |
| PAYLED-016 | Restatement after approved mapping correction | New run linked to prior; prior lines and outputs remain unchanged |
| PAYLED-017 | Negative credit/reversal row | Sign policy applied explicitly; no silent absolute value or clamping |
| PAYLED-018 | Duplicate import checksum replay | No duplicated source rows or pool value |
| PAYLED-019 | Null amount versus 0.00 | Null held/unknown; numeric zero preserved distinctly |
| PAYLED-020 | Row order permutation | Same exact totals and logical source lineage |
| PAYLED-021 | Rounding boundary and excess source precision | Exact canonical value retained; policy boundary applied only at approved stage |
| PAYLED-022 | Cross-tenant site reference | Rejected by composite FK and runtime isolation |
| PAYLED-023 | Historical run superseded | Old run read-only; current projection points to successor |
| PAYLED-024 | Audit history update/delete by runtime role | Permission denied |

### Required evidence for a pass

For each test retain:
- fixture ID/version and synthetic source manifest;
- exact engine/database commit SHA and migration chain;
- runtime and PostgreSQL versions;
- input row values as strings, currency and cost/tax basis;
- expected and actual exact decimal strings;
- row-level cap and pool reconciliation output;
- actor role and tenant scope;
- transaction/concurrency evidence where relevant;
- test result, logs with sensitive values absent, reviewer and timestamp.

A design table or green unrelated CI run is not a pass. The executable suite must run against the exact schema and API that will be evaluated.

## 9. Migration and legacy-data handling

No migration is authorised by this specification.

When implementation is eventually approved:
1. Reconcile PR #25's branch/migration chain with the approved base.
2. Add source-row structures additively; preserve existing aggregate runs as legacy records.
3. Do not manufacture source-row allocations from aggregate totals.
4. Backfill only where the original payroll source rows and mapping evidence can be proven.
5. Mark legacy aggregates with an explicit provenance status such as `LEGACY_AGGREGATE_UNVERIFIED`.
6. Quarantine orphaned, ambiguous, over-allocated or non-reconciling rows; do not guess tenant, site, currency or cost basis.
7. Validate source-row and pool control totals before enabling confirmation constraints.
8. Run rollback/restore tests on a disposable copy; prefer forward fixes after any evidence is recorded.

## 10. Decisions still requiring named owners

| Decision | Required owner | Why unresolved |
|---|---|---|
| Payroll components included in pool | Qualified payroll/accounting owner | Wages, super, leave, payroll tax and on-cost treatment varies by source and intended view |
| Eligible versus excluded row rules | Product/domain owner plus finance reviewer | Must not silently alter source total |
| Negative values, credits and reversals | Finance/domain owner | Sign and correction semantics |
| Source-row identity and duplicate detection | Data/technical owner | Different payroll systems export different identifiers |
| Allocation method catalogue and approval thresholds | Domain owner and customer policy | No universal site allocation method |
| Precision, scale and rounding | Finance + technical owner | Must be grounded in source formats and operations |
| Active confirmed run/restatement lifecycle | Product + data owner | Determines uniqueness and historical semantics |
| Reviewer roles and separation of duties | Security/product owner | Approval authority and conflict controls |
| Retention, minimisation and raw payroll access | Privacy/legal/security owner | Highly sensitive employee/payroll information |

## 11. Release boundary

This design resolves the logical gap between the product's payroll reconciliation requirements and the aggregate-only prototype schema. It does **not** resolve the business policy decisions, prove data availability, implement the ledger, or authorise real payroll data.

No application code, SQL migration, production database change, customer data access or deployment is part of this document. G0–G5 remain binding; implementation remains blocked until the explicit G5 signed GO and all named-owner approvals are in place.

# Financial Engine Test-to-Requirement Traceability Matrix

**Status:** proposed verification artefact; documentation only. No executable tests, database constraints or API controls are created by this document.  
**Repository data policy:** public repository; synthetic fixtures only.  
**Implementation authority:** blocked pending G5 signed GO and named-owner decisions.  
**Execution status:** every case in this matrix is **NOT RUN** unless a separate execution record identifies the exact engine commit, fixture version and environment.

## 1. Purpose and evidence rules

This matrix connects the financial requirements to executable acceptance cases, required persistence/API/domain controls, expected outcomes and release gates. It is intended to prevent a green CI run for the current scaffold from being mistaken for financial correctness.

The acceptance IDs below refer to `docs/FINANCIAL_ENGINE_EXECUTABLE_ACCEPTANCE_TEST_PLAN.md`; PAYLED IDs refer to `docs/PAYROLL_SOURCE_ROW_ALLOCATION_LEDGER_DESIGN.md`. They are specifications, not evidence that the tests exist or have passed.

**Evidence vocabulary**
- **PROPOSED** — design requirement only.
- **NOT IMPLEMENTED** — required control is absent from the reviewed scaffold or has not been demonstrated.
- **NOT RUN** — no execution evidence for the named acceptance case.
- **BLOCKED** — implementation or acceptance cannot proceed until a policy, dependency or authorisation is resolved.

A test is only PASS when its exact expected output and state are captured on a named commit, with the fixture bundle, runtime, environment, test counts, property seeds (where relevant), reviewer and defect references retained.

## 2. Requirement-to-control matrix

### 2.1 Decimal parsing and monetary arithmetic

| Requirement | Acceptance coverage | Required domain/API behaviour | Required persistence/control | Expected result | Gate / current status |
|---|---|---|---|---|---|
| Parse source amounts without guessing locale | DEC-001–005, DEC-010 | Parser requires declared source format; malformed/ambiguous values become HELD/REJECTED; zero remains distinct from missing | Preserve raw text, canonical decimal string, locale/parser version, currency, source precision and status | Exact canonical value or explicit held reason; never coerce to zero | G5 + financial acceptance; PROPOSED / NOT IMPLEMENTED |
| Explicit rounding and negative midpoint behaviour | DEC-006–008 | Each operation declares mode, scale and rounding boundary; negative ties tested | Versioned rounding policy and calculation-run reference | Exact approved result; line-rounding and aggregate-rounding remain distinct | Finance owner approval required; BLOCKED / NOT RUN |
| Preserve signs, bounds and deterministic output | DEC-009–012, PROP-003, PROP-012–013 | Credits remain negative; reject unsupported scale/overflow; deterministic serialisation | Decimal strings end-to-end; immutable input and policy versions | No binary-float drift; identical inputs/policy produce identical output | G5 + financial acceptance; NOT IMPLEMENTED / NOT RUN |
| No JS Number in authoritative money path | DEC-011 | Reject/avoid Number conversion in parser, domain services, routes, persistence and exports | API contract uses decimal strings; DB uses approved NUMERIC precision/scale only | No authoritative monetary value passes through binary floating point | Critical release blocker; NOT IMPLEMENTED |

### 2.2 GST, currency and FX

| Requirement | Acceptance coverage | Required domain/API behaviour | Required persistence/control | Expected result | Gate / current status |
|---|---|---|---|---|---|
| Preserve declared GST basis | TAX-001–005, PROP-009 | Separate GST-inclusive, GST-exclusive, no-GST, other and unknown; block unlike/unknown bases from incompatible aggregation | Tax basis and policy version stored with each amount and run | Correct synthetic tax bridge only under declared fixture policy; otherwise HELD/BLOCKED | Finance/tax owner approval; BLOCKED / NOT RUN |
| Prevent mixed-currency aggregation | TAX-006, PROP-008, CON-004 | Reject aggregation absent explicit reviewed FX conversion | ISO currency on every amount; no implicit AUD default | Mixed AUD/NZD totals cannot be combined | Critical; NOT IMPLEMENTED / NOT RUN |
| FX conversion provenance | TAX-007 | Require rate, source, direction, method, effective/retrieved timestamps and reviewer | Retain original and converted amounts plus all FX metadata | Missing mandatory metadata blocks conversion | G5 + finance review; PROPOSED / NOT RUN |

### 2.3 Payroll source-row allocation ledger

| Requirement | Acceptance coverage | Required domain/API behaviour | Required persistence/constraint | Expected result | Gate / current status |
|---|---|---|---|---|---|
| Pool reconciles across five mutually exclusive buckets | PAY-001, PAY-006–008, PAYLED-001–005, PAYLED-018, PROP-001, PROP-014 | Direct-coded, approved allocated, non-site, unallocated and excluded are separately represented; incomplete sources remain incomplete | Pool, source rows, allocation run/lines, reconciliation and decision events; exact decimal totals | Sum of buckets equals authoritative source pool; residual is visible and never silently spread | Critical; PROPOSED / NOT IMPLEMENTED |
| Per-row allocation cap and no duplicate attribution | PAY-002–003, PAYLED-006–010, PAYLED-019–020, PROP-002 | Sum of allocations for a source row cannot exceed its eligible amount; duplicate/replayed assignments held | Row identity, tenant-scoped uniqueness, allocation-line constraints and transactional recheck | Over-allocation rejected/held with row and excess identified | Critical; PROPOSED / NOT IMPLEMENTED |
| Candidate versus approved allocation | PAY-004–005, PAYLED-011–014 | Candidate has no effect on confirmed totals; only authorised reviewer can approve | Append-only decision event with actor, role, reason, evidence, method version and timestamp | Unapproved candidate excluded; unauthorised approval denied and audited | Critical; PROPOSED / NOT IMPLEMENTED |
| Negative rows, nulls, split allocations and determinism | PAYLED-015–017, PAYLED-021–022, DEC-005, DEC-009, PROP-003, PROP-005, PROP-013 | Signed-value policy required; split lines sum within row cap; null is not zero; stable output under row permutation | Decimal strings, source row lineage, policy version | No clamping, sign loss, hidden residual or order-dependent result | Finance policy BLOCKED; NOT RUN |
| Concurrent confirmation and immutable restatement | PAY-009, PAYLED-023–024, PROP-010 | Lock/re-read/validate/append/transition atomically; correction creates new run | Tenant-scoped constraints, append-only decision events, unique active confirmed run rule, old/new run links | No double approval; previous run remains reproducible | Critical; PROPOSED / NOT IMPLEMENTED |

### 2.4 Invoice evidence and approval

| Requirement | Acceptance coverage | Required domain/API behaviour | Required persistence/control | Expected result | Gate / current status |
|---|---|---|---|---|---|
| Evidence-backed candidate, not amount-only match | INV-001–003, INV-007, PROP-006 | Require customer, contract, site, service period, amount, currency, tax basis and conflict assessment; confidence is evidence quality, not truth | Candidate evidence dimensions and source references | Amount-only or conflicting candidate cannot become high-confidence/confirmed | High; NOT IMPLEMENTED |
| Human authority and duplicate protection | INV-004, INV-008, INV-002, PROP-006 | Confirmation is a separate authorised action; replay/duplicate is preserved and not counted twice | Unique tenant-scoped source identity; append-only reviewer decision; role enforcement | Duplicate detected; unauthorised confirmation denied; candidate remains unconfirmed | Critical for pilot; NOT IMPLEMENTED |
| Coverage numerator and denominator | INV-005, INV-009, CORE Calculation Spec §5 | Only eligible invoice lines with medium/high evidence and human-confirmed contract/site/period mapping enter numerator; denominator policy explicit | Versioned eligibility/exclusion policy and line-level source lineage | Coverage is reproducible and exclusions carry reasons | G0 evidence gate + finance review; PROPOSED / NOT RUN |
| Credits and partial/period mismatches | INV-006–007 | Credit remains linked but distinct; period conflict visible | Separate source records and decision history | Gross, credit and net traceable; no silent period reassignment | High; NOT RUN |

### 2.5 Contribution, variations and imports

| Requirement | Acceptance coverage | Required domain/API behaviour | Required persistence/control | Expected result | Gate / current status |
|---|---|---|---|---|---|
| Contribution completeness and basis | CON-001–005, PROP-005, PROP-008–009, PROP-011 | Require explicit revenue/cost policy, period, currency, tax basis and material-input completeness; suppress definitive margin if incomplete | Versioned policies, coverage/completeness fields, provenance closure | Complete synthetic fixture yields management contribution; missing material input yields unavailable/incomplete, not zero or definitive margin | Critical; NOT IMPLEMENTED |
| Variation authority | VAR-001–005, PROP-007 | Requested/observed/candidate values are not approved or billable; only authorised approval changes approved view | Immutable state-transition events, actor, approved scope/price, evidence, event and approval times | Unapproved value contributes zero approved variation; rejected remains traceable | High; NOT IMPLEMENTED |
| Import lineage, controls and replay | IMP-001–007, PROP-003–004, PROP-014 | Checksum-based idempotency; reconcile row counts and monetary totals; hold unknown aliases/timezone ambiguity; safe exports | Import batch, source manifest/checksum, raw row identity, mapping/parser version and control totals | Exact replay adds no duplicate facts; mismatch blocks reconciled status | High; NOT IMPLEMENTED |
| Calculation run reproducibility | DEC-012, PAY-009, PROP-010–012 | Every output tied to engine commit, source versions, mapping and policies; correction creates restatement | Immutable run snapshot and old/new links | Same inputs/policies reproduce same result; prior output never overwritten | High; NOT IMPLEMENTED |

### 2.6 Cross-cutting security and tenant isolation

| Requirement | Required tests | Required API/domain behaviour | Required DB/infrastructure control | Expected result | Gate / current status |
|---|---|---|---|---|---|
| Tenant isolation for every financial object | Cross-tenant adversarial tests; PROP-011 | Every lookup, mutation, export and calculation is tenant-scoped server-side | Composite tenant FKs, RLS, restricted runtime role, exhaustive table/route tests | Tenant A cannot read, infer, mutate or export Tenant B data | P0 before any live data; partial scaffold evidence only |
| Reviewer role and separation of duties | PAY-005, INV-008, approval adversarial tests | Server-side role/ownership check on every decision endpoint | Explicit grants, membership constraints, append-only audit | Denied action leaves safe audit event; no sensitive row payload leakage | P0; NOT fully demonstrated |
| Idempotency and concurrency | IMP-001, PAYLED-023, INV-004 and concurrent decision tests | Idempotency keys and atomic state transitions | Tenant-scoped unique constraints and transactional locking | No duplicate financial posting/approval under retries or races | P0; NOT IMPLEMENTED |
| Private source-file lifecycle | Import/storage security tests | Upload is not considered complete until bytes are privately stored, scanned and validated | Quarantine, malware scan, private object store, retention/deletion and backup controls | No public/raw payroll file exposure; deletion and restore semantics proven | P0 before real data; NOT IMPLEMENTED |
| Audit, export and operational recovery | Provenance, formula-injection, backup/restore and incident tests | Log access/decisions without leaking sensitive payloads; safe export | Tamper-evident audit, monitoring, restore and deletion replay | Reconstructable decision history and tested recovery | P1/P2; NOT IMPLEMENTED |

## 3. Current implementation gap register

The following are known from static review of the current prototype/security branch; they are not newly executed findings from this matrix.

| ID | Finding | Severity | Consequence | Required closure evidence |
|---|---|---|---|---|
| GAP-01 | API calculation route references `allocation_lines`, but reviewed schema does not define it | Critical | Route/schema contract mismatch; a superficial table would not supply row-level evidence | Approved source-row ledger model, migration, API contract and integration tests |
| GAP-02 | API calculation path uses `Number(...)` and `toFixed(2)` for money | Critical | Binary-float arithmetic and implicit rounding remain in an authoritative path | Decimal-string end-to-end tests and static/code-path audit |
| GAP-03 | Payroll persistence is aggregate-oriented | Critical | Cannot prove per-row caps, duplicate prevention or provenance | PAYLED suite passes on implemented ledger |
| GAP-04 | Contribution can still be emitted when required inputs are incomplete | Critical | Incomplete data may be mistaken for a reliable margin | CON-002–005 and incomplete-state API assertions |
| GAP-05 | Tenant-bound relationships require complete composite-FK/catalogue verification | High | RLS alone does not prove relational tenant integrity | Full schema catalogue audit and adversarial cross-tenant tests |
| GAP-06 | Import metadata registration is not binary file upload/storage | High | No secure original-file custody, scanning or lifecycle proof | Private storage lifecycle and malware-scan evidence |
| GAP-07 | In-process rate limiter is not a shared multi-instance control | High | Rate-limit bypass/inconsistency under horizontal scaling | Shared store and trusted-proxy tests before scaled deployment |
| GAP-08 | Existing CI does not execute the proposed financial acceptance matrix | Critical | Green CI cannot be interpreted as financial-engine acceptance | Named executable suite, fixture review and run evidence |

## 4. Traceability completeness and execution ledger

| Suite | Specified cases | Implemented by this matrix? | Executed? | Evidence required |
|---|---:|---|---|---|
| Decimal | DEC-001–012 (12) | Mapped | NOT RUN | Exact outputs, negative ties, parser and no-float audit |
| GST/currency | TAX-001–007 (7) | Mapped | NOT RUN | Approved tax/FX policies and exact results |
| Payroll | PAY-001–009 (9) | Mapped | NOT RUN | Source-row reconciliation and approval evidence |
| Payroll ledger | PAYLED-001–024 (24) | Mapped | NOT RUN | All 24 cases, including race and restatement tests |
| Invoice | INV-001–009 (9) | Mapped | NOT RUN | Evidence and decision-state assertions |
| Contribution | CON-001–005 (5) | Mapped | NOT RUN | Completeness, tax/currency and management-view assertions |
| Variations | VAR-001–005 (5) | Mapped | NOT RUN | Authorisation and temporal history assertions |
| Imports | IMP-001–007 (7) | Mapped | NOT RUN | Checksum, row/amount controls and safe export |
| Properties | PROP-001–014 (14) | Mapped | NOT RUN | Seeds, generated case counts and failing-case retention |
| Security/integration | Cross-tenant, role, concurrency, storage, restore | Requirements mapped | NOT RUN / PARTIAL EXISTING CI | Exact route/table/object coverage and environment evidence |

The case counts above are counts of specified identifiers, not tests executed, not coverage percentages and not pass rates.

## 5. Financial-engine acceptance exit criteria

Do not declare the financial engine accepted until all of the following are evidenced:

1. All mandatory DEC, TAX, PAY, PAYLED, INV, CON, VAR and IMP cases pass on a named implementation commit.
2. All 14 property invariants pass with recorded generator version, seeds and run count.
3. Independent reviewer approves every expected financial result and fixture version.
4. Finance/payroll/tax owners approve source inclusions, denominator, GST, currency, FX, precision, rounding, negative-value and materiality policies.
5. Payroll pool and source-row control totals reconcile exactly; no row exceeds its eligible amount.
6. Invoice coverage uses the approved denominator and only human-confirmed evidence-qualified matches.
7. Contribution is withheld when material inputs are unknown, incomplete or incomparable.
8. Restatement, provenance, tenant isolation, role, idempotency and concurrency tests pass.
9. No unresolved Critical or High financial defects remain.
10. CI run identifies exact commit, runtime, environment, fixture hash, test counts, seeds and results.
11. Qualified finance/accounting review and security/privacy/legal reviews are separately recorded.
12. Project-level G0–G5 gates remain satisfied; G5 requires explicit signed GO before implementation, and separate pilot approval before real customer data.

## 6. Current CI evidence — scope carefully limited

At documentation commit `5ad37b15cdefb6976f1b86957cb72edc424bbc64`, CI run **#341** completed successfully:
- **PostgreSQL migrations and tenant RLS:** success.
- **Verify (Node.js 22):** success, including syntax checks and existing unit tests.

This is evidence that the repository's configured checks passed for that exact commit and its branch contents. It is **not** execution of the proposed DEC/TAX/PAY/PAYLED/INV/CON/VAR/IMP/property suites, does not reconcile the sibling security branch into this branch, and is not an independent security or accounting certification. The PR branches remain separate.

## 7. Governance and implementation boundary

This matrix authorises no code changes, SQL migrations, dependency additions, data backfills, production configuration, customer-data access, merge or deployment. The public repository must continue to contain synthetic fixtures only.

Before implementation: reconcile the PR #25 security branch with the product branch; obtain named technical, finance/payroll, privacy/legal and security owners; resolve policy decisions; complete G0–G4 evidence; and obtain explicit G5 signed GO. A green CI run or a completed design document cannot substitute for those approvals.

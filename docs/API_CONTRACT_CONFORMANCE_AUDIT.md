# ProfitPilot — API Contract Conformance and Route-Surface Audit

**Review date:** 17 November 2026  
**Reviewed implementation ref:** PR #25 security branch, \`17178768002b978d6f5bd76f0192b2bbff7a4355\`  
**Reviewed specification:** \`api/openapi.yaml\` at the same branch  
**Method:** static comparison of Express route declarations, route middleware, request validation and OpenAPI paths/responses. No endpoint was deployed or called.  
**Status:** review findings; proposed corrections and tests only.

## 1. Executive assessment

The OpenAPI document and Express route surface broadly describe the same initial endpoint set. The route inventory is:

| Method | Express path | OpenAPI path | Purpose |
|---|---|---|---|
| GET | /health | Not specified (operational endpoint) | Database health check |
| GET | /v1/me | /me | Authenticated identity |
| GET | /v1/tenants/:tenantId/contracts | /tenants/{tenantId}/contracts | Tenant contract list |
| POST | /v1/tenants/:tenantId/imports | /tenants/{tenantId}/imports | Register import metadata |
| POST | /v1/tenants/:tenantId/imports/:batchId/rows | /tenants/{tenantId}/imports/{batchId}/rows | Persist parsed row objects |
| POST | /v1/tenants/:tenantId/imports/:batchId/validate | /tenants/{tenantId}/imports/{batchId}/validate | Validate invoice rows |
| POST | /v1/tenants/:tenantId/matches/:matchId/decision | /tenants/{tenantId}/matches/{matchId}/decision | Human match decision |
| POST | /v1/tenants/:tenantId/calculations | /tenants/{tenantId}/calculations | Create calculation run |
| GET | /v1/tenants/:tenantId/calculations/:runId | /tenants/{tenantId}/calculations/{runId} | Retrieve calculation run |

The OpenAPI server URL is explicitly a placeholder and the file states that no server is deployed. Route presence must not be interpreted as production availability.

## 2. Findings

### API-SPEC-01 — OpenAPI responses do not fully match observed route outcomes

**Severity: Medium / integration risk**

Several route handlers have explicit status branches that are not fully enumerated in the OpenAPI response set. Examples include conflict/not-open import batch states, unsupported payroll validation, empty import rows, and calculation precondition failures. Some handlers also return a successful idempotent response for an already registered checksum.

**Risk:** generated clients and future UI code may treat an outcome as impossible, retry incorrectly or display an unsafe generic state.

**Required correction:** enumerate every observed status and response body schema, including:
- registered vs idempotent existing batch;
- invalid source metadata;
- batch not found;
- batch not open for ingestion;
- unsupported payroll validation;
- no rows available for validation;
- validation held/review outcome;
- already-finalised match decision;
- calculation incomplete/unavailable vs invalid request vs missing contract/site baseline;
- permission denial and authentication failure.

Do not collapse \`INCOMPLETE\`, \`HELD\`, \`CONFLICT\`, \`UNAVAILABLE\` and \`REJECTED\` into one generic 4xx/5xx response.

### API-SPEC-02 — Import rows endpoint accepts parsed JSON rows, not original files

**Severity: High data-governance and product-language risk**

The OpenAPI description correctly states that the endpoint accepts 1–200 parsed JSON row objects and does not upload/store original binary files. The initial metadata endpoint also records caller-supplied checksum and filename; it cannot independently prove that the caller's file bytes match the declared checksum.

**Required correction:** retain the exact distinction in every UI, API response, support guide and audit record:
- \`registered\`: metadata and caller-provided checksum recorded;
- \`rows_ingested\`: parsed row objects persisted;
- \`binary_received\`: only after a private object store confirms bytes and checksum;
- \`scanned\`: malware/content checks completed;
- \`validated\`: parser and source-control checks completed;
- \`ready_for_review\`: explicit workflow state after all prerequisites.

These are proposed lifecycle names, not current enum values or implemented behaviour. Do not label the current process "file uploaded" or "secure import".

### API-SPEC-03 — No explicit response schemas for financial and import payloads

**Severity: High contract-quality risk**

The OpenAPI file describes endpoints and response intent but provides few reusable response schemas. The financial response is especially important: it must define exact decimal strings, ISO currency, tax basis, completeness state, calculation version, source coverage, exclusions, policy versions and provenance. It must never imply a definitive contribution when material source coverage is incomplete.

**Required correction:** add reusable schemas for:
- error envelope with stable code, safe message, correlation ID and optional field/record reference;
- import registration and row-ingestion state;
- source row and parse result with raw/canonical values;
- match candidate, evidence dimensions, confidence policy version and reviewer decision;
- calculation run, result state, source coverage, missing categories and restatement links;
- exact MoneyValue using decimal string, currency, tax basis, source precision and value status.

No API schema should use JSON number for authoritative monetary amounts.

### API-SPEC-04 — Pagination and bounded response behaviour are not specified

**Severity: Medium**

The contracts list and calculation retrieval are bounded by query shape, but the OpenAPI does not define pagination, maximum result counts, stable cursors, sort ordering or response-size limits for future list endpoints. The current contract-list route returns all matching contracts.

**Required correction:** define cursor pagination and maximum page size before real tenants can accumulate large record sets. Add deterministic ordering and tenant-scoped cursor validation. Never silently truncate financial result sets.

### API-SPEC-05 — Idempotency and concurrency contracts are incomplete

**Severity: High for financial workflow**

The import registration endpoint uses a tenant/checksum uniqueness conflict as an idempotency guard. Other state-changing endpoints need explicit idempotency and concurrency semantics. A retry after a network timeout must not create a second approval, decision or calculation run.

**Required correction:** define:
- idempotency key scope, retention and request-body hash;
- behaviour when a key is reused with a different payload;
- expected-version/ETag or equivalent optimistic concurrency;
- duplicate/replay response semantics;
- append-only decision event identity;
- transactional calculation-run creation and restatement behaviour.

### API-SPEC-06 — Error disclosure and observability contract needs formalisation

**Severity: Medium**

The route handlers use generic errors in several places and the API contract does not define correlation IDs or stable machine-readable error codes.

**Required correction:** provide safe, stable error codes and correlation IDs; keep SQL, token, tenant-secret, stack-trace and source-payload details out of client errors. Log only the minimum diagnostic metadata under the approved data classification policy.

### API-SPEC-07 — Route authorisation matrix is not expressed in the API contract

**Severity: High assurance gap**

The implementation applies tenant membership middleware and role middleware to state-changing endpoints. The OpenAPI mostly describes generic 403 outcomes but does not give a complete role × operation matrix.

Observed route intent:
- contract list: authenticated tenant membership;
- import metadata and row ingestion: owner/admin/analyst;
- import validation: owner/admin/analyst/reviewer;
- match decision: owner/admin/reviewer;
- calculation create: owner/admin/analyst/reviewer;
- calculation read: authenticated tenant membership.

**Required correction:** make the role matrix explicit, confirm whether analyst/reviewer overlap is intentional, define read/export permissions separately, and test every route × role × tenant combination. The server remains authoritative; OpenAPI documentation and UI controls are not authorization.

## 3. Required API acceptance suite

All tests below are **PROPOSED / NOT RUN**.

| ID | Scenario | Expected result |
|---|---|---|
| API-CONF-001 | Compare Express route/method inventory with OpenAPI | Exact parity except explicitly documented health/operational routes |
| API-CONF-002 | Each handler's success and error branches | OpenAPI enumerates every stable status and response schema |
| API-CONF-003 | Import registration response | Clearly says metadata registered; never claims binary uploaded |
| API-CONF-004 | Caller supplies checksum not matching source bytes | Current API does not claim independent verification; future binary pipeline verifies bytes |
| API-CONF-005 | Malformed, duplicate and over-limit row payloads | Stable validation errors; no partial ingestion |
| API-CONF-006 | Retry same import checksum | Idempotent same-batch result; no duplicate rows/value |
| API-CONF-007 | Reuse idempotency key with changed payload | Conflict; no second financial event |
| API-CONF-008 | Concurrent decision submission | One valid final decision; second request conflicts safely |
| API-CONF-009 | Each role against each route | Only documented roles/actions succeed |
| API-CONF-010 | Cross-tenant IDs in every route | No disclosure; 404/403 policy consistent and audited |
| API-CONF-011 | Monetary values in request/response | Decimal strings only; currency and tax basis explicit |
| API-CONF-012 | Incomplete calculation response | No definitive contribution/margin scalar; coverage and missing categories explicit |
| API-CONF-013 | Large contract/import/report collection | Stable cursor pagination and bounded response |
| API-CONF-014 | Unexpected internal exception | Generic client error, correlation ID, no stack/SQL/secret disclosure |
| API-CONF-015 | Schema and generated client validation | OpenAPI parses and matches tested implementation |
| API-CONF-016 | API version compatibility | Breaking changes versioned; clients can detect supported contract version |

## 4. Recommended remediation order

1. Resolve G5 and assign technical/security/product owners before implementation.
2. Freeze the canonical domain and error-state vocabulary.
3. Reconcile schema/API financial defects recorded in the financial-engine and branch-integration audits.
4. Add complete response/request schemas and role matrix to OpenAPI.
5. Define idempotency, concurrency and pagination semantics.
6. Add contract conformance tests that compare live route behaviour to OpenAPI.
7. Generate/validate a client from the contract and test critical iPhone workflows.
8. Run all tests on the combined PR #25 + PR #26 candidate SHA, then obtain independent review.

## 5. Evidence limitations

This audit is static. No OpenAPI parser, generated client, endpoint request, load test, deployed server or live database was exercised for this review. The existing CI success on PR #25 is not evidence that every API-SPEC test above passes.

No application code, OpenAPI contract, schema, migration, customer data or production configuration was changed by this audit. Synthetic fixtures only. G5 remains binding.

 
## OpenAPI exact-money and response-schema reconciliation — 17 November 2026

The draft hardening branch updates `api/openapi.yaml` to document:
- the operational `/health` endpoint and authenticated identity response;
- contract list, import registration/idempotent replay, row ingestion, validation, match decision and calculation response shapes;
- the explicit 422 payroll-ingestion-disabled state and 413 body-limit outcome;
- a reusable `MoneyDecimal` schema: JSON string only, no exponent notation or binary floating-point number, maximum PostgreSQL `numeric(14,2)` magnitude and scale;
- calculation output fields with contribution and margin nullable while the result is incomplete, and the separately labelled indicative value.

The OpenAPI server URL remains a placeholder and no service is deployed. This is contract documentation, not evidence that all proposed product endpoints exist. Payroll ingestion, variation management, export, membership discovery and private binary upload remain unimplemented.

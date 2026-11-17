# Payroll source validation — core milestone

This is an API prototype, not a payroll processor. Only synthetic data is permitted.
Authorized tenants can persist payroll rows and validate their structure with POST /v1/tenants/{tenantId}/imports/{batchId}/validate.

## Source row contract

- source_ref: nonempty source evidence identifier, maximum 120 characters
- cost_component: nonempty source cost category, maximum 120 characters
- amount: positive decimal string without currency marks, separators, scientific notation or more than two decimal places
- currency: explicit AUD only
- period_start and period_end: real ISO dates within the declared import batch period

Records failing these checks are held with a reason. Passing records become candidate mapping decisions with LOW confidence. Neither case constitutes a human financial approval. Revalidation does not change already accepted or rejected decisions and cannot automatically allocate payroll or create payroll pools.

No currency conversion, award interpretation, superannuation/tax calculations, secure file upload or production retention certification is supplied. Human approval and authoritative payroll total reconciliation remain separate work.

## Review decision endpoint

GET /v1/tenants/{tenantId}/imports/{batchId}/review?offset=0&limit=100 exposes aggregate counts (candidate, held, accepted, rejected, unvalidated) and a paginated list of row numbers, decisions and held/rejected reasons. It requires imports.validate and never returns raw payloads, source references, amounts or worker identities. Page size is capped at 100. A foreign batch ID returns 404. No financial decisions are automated.


## Human-approved source reconciliation and site allocation

This repository implements a staged decision flow, not payroll statutory processing.

1. Validate payroll JSON rows. An independent reviewer with fresh provider MFA accepts valid candidates or rejects held records, with an audit reason. The importer cannot approve their own rows.
2. A separately authorised, freshly authenticated member supplies a source-declared total and evidence reference. The API requires all rows decided, unique accepted source references, identical pay periods, and a cent-exact match to the accepted source amounts. The pool is saved once per batch and the batch is sealed. The declared source total has NOT been externally verified.
3. An authorised maker prepares site-based direct and approved-allocated lines or non-site/excluded amounts with evidence references. The API calculates any unallocated residual, disallows cross-tenant sites, and rejects allocations above the pool total. All draft costs remain excluded from contribution calculations.
4. A different authorised reviewer with fresh MFA confirms only when the database line amounts reconcile exactly to the pool and bucket totals. Confirmation is logged in the append-only audit chain. Only one confirmed allocation per pool is possible; immutable confirmed runs/lines cannot be changed by runtime operations.

No employee-level wage or award interpretation, statutory payroll, external source verification, GST handling or production data storage is provided. Financial figures are illustrative management contribution and may be incomplete. Do not use real customer or worker data in the repository or prototype.

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

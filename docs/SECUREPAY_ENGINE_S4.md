# SecurePay SP-S4 — append-only reviewer conflict self-declarations

**Scope:** authenticated, tenant-scoped, synthetic-only operator workflow. This is not independent conflict screening, a verified-party dispute service, escrow, arbitration, payment execution or legal authorisation.

## API

- `POST /v1/tenants/:tenantId/prototype/securepay-cases/:caseId/reviewer-declarations`
- `GET /v1/tenants/:tenantId/prototype/securepay-cases/:caseId/reviewer-declarations` (100/page cursor)
- Updated `POST .../reviewer-assessments` now requires a third input: `declarationId` (UUID).

POST self-declaration accepts **exactly** `clientRequestId` (UUID), `declarationStatus`, `conflictCode` and `disclosureReference`. For `no_conflict_declared`, the latter two must be null. For `potential_conflict`, an allowed reason code and an opaque reference are required; do not submit personal data. The database actor is taken from a verified JWT + signed tenant context; caller-supplied reviewer ID is forbidden. Replays with the same ID and values return the original row; conflicting replays return HTTP 409.

Reviewer assessments are now blocked without an existing same-case, same-tenant, same-reviewer `no_conflict_declared` record. A **recorded potential conflict blocks every later assessment from that actor on that case**, even if a subsequent no-conflict declaration is added. The PostgreSQL policy and foreign key independently enforce these requirements, including for direct runtime-role SQL writes. Case-openers and evidence reporters remain barred from assessments. The database rows are append-only and tenant RLS is forced. New rows link their declaration; historical S3 assessments created before migration retain NULL links and must never be interpreted as cleared.

**Limitations:** all conflict declarations are self-reported. There is no verified beneficial interest screening, independent approval, reviewer appointment, actual customer/tradesperson/job binding, source-document custody or insurer/payment-provider clearance. The earlier operator evidence reports have opaque references only and can be wrong. Historical assessments cannot be revoked, and a later conflict does not modify an older snapshot. API response flags deliberately remain false for independently screened, identity verified, decision and payment authority. Protected profile continues to block all prototype routes.

**Future gates:** independently verified parties and job authority; source-provenance attestations and trusted evidence receipts; independent conflict review/adjudicator appointments; transactional event journal with concurrency tests; Australian legal/provider review. No real money or binding decision until the required approvals exist.

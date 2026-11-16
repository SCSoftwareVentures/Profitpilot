# ProfitPilot — Implementation Audit and Defect Register

**Audit date:** 16 November 2026  
**Scope:** repository source review of the prototype implementation. This is not an independent security audit, executed integration test, penetration test or production certification.

## Work included in this pass
- Authenticated Express API scaffold using JWT verification against a configured JWKS endpoint.
- Tenant membership checks executed in transaction-scoped PostgreSQL context.
- PostgreSQL schema and ordered local initialization migrations.
- Forced row-level security policies for tenant-owned tables.
- Restricted non-superuser runtime database role for local Compose.
- Persistent JSON row ingestion and invoice-row validation decisions.
- Human-reviewed invoice-match decision endpoint with audit event.
- Evidence-gated contract/site/period calculation endpoint and calculation retrieval.
- Duplicate confirmation safeguards for invoice matches and allocation runs.
- Node unit-test suite and GitHub Actions workflow.
- Dockerfile and local Compose configuration.

## Defects found and corrected during review
| Finding | Correction |
|---|---|
| Tenant membership middleware initially queried RLS-protected rows without tenant transaction context | Membership lookup now uses transaction-scoped tenant context and verifies the authenticated subject |
| /v1/me claimed membership discovery despite no safe cross-tenant discovery function | Response and API specification now explicitly avoid exposing membership discovery |
| Composite foreign key to invoice lines lacked a matching composite unique key | Added tenant-scoped unique key before dependent foreign key |
| Runtime API container initially shared the database superuser | Local Compose now uses a separate non-superuser runtime role |
| Calculation retrieval route was duplicated | Removed duplicate route |
| CSV parser accepted inconsistent row widths and blank headings | Parser now rejects malformed row widths and empty headings |
| Invoice date validation accepted impossible calendar dates | Requires a real ISO calendar date |
| Calculation could select overlapping contract versions ambiguously | Calculation now rejects multiple effective versions |
| Calculation could silently include a partial payroll period | It now rejects partial overlaps instead of prorating |
| Calculation could combine unknown or mismatched currency/tax bases | It now rejects unknown, mixed or contract-currency-mismatched invoice basis |
| Repeat confirmations could double-count a match or allocation run | Added partial unique indexes for confirmed records |
| CI setup expected an npm lockfile that is not present | Removed the npm cache dependency; dependency installation remains unpinned pending lockfile generation |

## Current automated test coverage
The Node test suite covers money rounding, CSV parsing, quoted fields, escaped quotes, CRLF, malformed row widths/headings, invalid dates, invoice validation, payroll reconciliation, over-allocation, negative allocation, human confirmation and contract aggregation.

**Execution status (16 November 2026):** GitHub Actions run **#34** completed successfully on Node.js 22 for PR #3 before merge. Dependency installation, syntax checks and unit tests all passed. The test suite now contains **22 cases**, including strict ISO calendar-date and leap-year regression coverage. The PR was merged to `main` as commit `41d43b79dffccfa5e95455d99cb63e34406a828c`. A duplicate unique-constraint declaration was removed from migration 002; this corrects a deterministic migration failure found by source inspection. The migration has **not** yet been executed against PostgreSQL, so database initialisation remains unverified. Hosted CI success is not evidence of database integration, tenant-isolation correctness or production security.

## Known implementation limits — not defects to conceal
1. No production environment, API host, database instance or identity provider is configured.
2. JWT authentication will reject requests until issuer, audience and JWKS URL are configured.
3. There is no production user/tenant provisioning flow.
4. The API accepts JSON row payloads; secure binary file upload, private object storage, malware scanning and retention/deletion are not implemented.
5. Payroll import validation is not implemented. The current validator supports invoice rows only.
6. The browser demo does not call the API and stores no server-side state.
7. The match decision endpoint assumes candidate rows already exist; candidate generation and evidence scoring are not fully implemented.
8. The calculation endpoint includes confirmed customer invoice lines and confirmed site labour allocation lines only. Other costs are excluded; output is explicitly marked incomplete and is not audited profit.
9. Calculation source selection and approval lifecycle need further review, including credit notes, invoice reversals, tax conversion, currency conversion, restatements and duplicate source data.
10. The 22-case Node.js 22 engine test suite passed in GitHub Actions run #34, including dependency installation and syntax checks. No real PostgreSQL migration execution, Docker build, browser test, native Excel/Sheets test or security test has been performed.
11. The local Compose runtime role uses a fixed development-only password. Do not deploy this configuration to a shared or production environment. Change the role bootstrap and secret handling before any shared deployment.
12. API CORS, identity configuration, TLS, backups, monitoring, secrets, data retention, incident response and operational controls require environment-specific setup.

## Required next verification
- Run npm install, npm run check and npm test in a Node 22 environment; commit a lockfile and pin dependencies.
- Build the container and start a fresh PostgreSQL instance; execute every init script in order.
- Run positive and negative tenant-isolation tests under the actual non-owner runtime role.
- Test membership revocation, role escalation, token expiry, JWKS rotation and rate limiting.
- Test import replay, row-number conflicts, malformed payloads, large payloads and CSV formula injection.
- Test match decision races and calculation reproducibility/restatement.
- Add a secure upload provider and privacy-controlled file lifecycle before customer data.
- Complete independent penetration test and Australian legal/privacy review before any live pilot.

## Release decision
**Prototype engineering foundation: partially implemented.**  
**Private customer pilot: not approved.**  
**Production: not ready.**

No customer data should be entered into the public repository or current browser demo.

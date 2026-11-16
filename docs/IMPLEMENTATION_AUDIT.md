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

**Execution status (16 November 2026):** GitHub Actions run **#34** passed the 22-case Node.js 22 engine suite after the strict calendar-date correction (PR #3, merged as `41d43b79dffccfa5e95455d99cb63e34406a828c`). PostgreSQL 16 migration and basic RLS integration passed in run **#41** (PR #4, merged as `4c785b6fa5ad3868c1c872d2085141238d6fdd66`). Authenticated HTTP API tests passed in run **#50** (PR #5, merged as `83eacd800ccc2523e31447b5a46e476244ae9548`): missing bearer token rejection, same-tenant access, cross-tenant membership denial, invalid tenant/date rejection, import idempotency and read-only write denial. The production Docker image built and its running container returned a healthy database-connected response in run **#54** (PR #6, merged as `2834543476b4957210902df4560e2e8d68035ba6`). Expanded cross-tenant tests passed in run **#58** (PR #7, merged as `a92e915f87ec62c0fb74e3774f6cb7f364e5177a`): contract rows for another tenant were hidden under RLS, cross-tenant writes were rejected by `WITH CHECK`, and client-supplied tenant IDs could not override the authenticated tenant. Tenant context cleanup after a transaction returned its pooled connection passed in run **#62** (PR #8, merged as `47e77f61530e575998a6b83f3188ccfd700c1d45`). These are ephemeral CI results, not production deployment, independent security certification or proof against a compromised application runtime. Signed tenant-context hardening passed in hosted CI run **#87** (PR #10, merged as `1e940123873b24a8163ce6420ce1608771234dc6`): migration/bootstrap succeeded, raw `app.tenant_id` spoofing returned no tenant rows, the signed API context passed membership checks, cross-tenant read/write negatives passed, and the production Docker image/runtime health smoke test passed. Signed-context negative-case tests passed in CI run **#98** (PR #12): forged HMACs, expired contexts and valid signatures for non-members all returned no protected rows; the runtime role could not read the private signing-key table and was confirmed neither superuser nor `BYPASSRLS`. Runtime DB credential externalisation then passed CI run **#112** (PR #15, merged as `33eefce82e52ce83e561399c9f8ec01a1ab3aa6d`): a fresh ephemeral app-role password was used to bootstrap a `LOGIN`, `NOSUPERUSER`, `NOBYPASSRLS` role; PostgreSQL migrations, authenticated API integration, Docker image build and container health checks all passed. Signed tenant-context hardening passed in hosted CI run **#87** (PR #10, merged as `1e940123873b24a8163ce6420ce1608771234dc6`): raw tenant-GUC spoofing was denied, signed API context and membership checks passed, cross-tenant read/write negatives passed, and Docker runtime health passed. Signed-context negative-case tests passed in run **#98** (PR #12): forged HMACs, expired contexts and valid signatures for non-members were denied; the runtime role could not read the private signing-key table and was confirmed neither superuser nor `BYPASSRLS`. Runtime DB credential externalisation passed run **#112** (PR #15, merged as `33eefce82e52ce83e561399c9f8ec01a1ab3aa6d`): a fresh ephemeral app-role password bootstrapped a `LOGIN`, `NOSUPERUSER`, `NOBYPASSRLS` role; PostgreSQL migrations, authenticated API integration, Docker image build and container health checks passed. HMAC key rotation/revocation passed run **#115** (PR #16, merged as `b14e15d74d8e76337d64f96b55b3b9a842400186`): both keys worked during overlap, old-key revocation denied access, and the replacement key remained valid; all CI jobs passed. Same-tenant actor-reference integrity then passed PostgreSQL 16 CI run **#147** (PR #21, merged as `ad2c07ba60017b4653653ac8c248db400fcb58c3`): eight composite foreign keys now tie creator, reviewer and approver columns to tenant memberships, and the integration suite confirms a tenant-B-only user cannot be recorded as the creator of a tenant-A import. Global identity-table protection passed in hosted CI run **#161** (PR #23, merged as `5126704e001f37e98585af14f009a5e5ee38df2b`): the runtime role saw only its own identity row under a valid signed context, saw no users without context, and was denied identity updates; migrations, API tests, Docker build and container health all passed.

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
10. The 22-case Node.js 22 engine suite, PostgreSQL migration/RLS checks, authenticated API integration tests, expanded cross-tenant negative tests, transaction-context cleanup check, Docker image build and container health smoke test have passed in hosted CI. No production deployment, complete all-table/all-endpoint adversarial isolation suite, browser end-to-end test, native Excel/Sheets equivalence test or independent security test has been performed.
11. Compose and CI now require a separate random hex `POSTGRES_APP_PASSWORD`; the runtime role bootstrap enforces `LOGIN`, `NOSUPERUSER` and `NOBYPASSRLS`. The `.env.example` contains placeholders only. Production still needs managed secret storage, rotation/recovery, TLS and a formal deployment configuration.
12. API CORS, identity configuration, TLS, backups, monitoring, secrets, data retention, incident response and operational controls require environment-specific setup.

## Required next verification
- Run npm install, npm run check and npm test in a Node 22 environment; commit a lockfile and pin dependencies.
- Build the container and start a fresh PostgreSQL instance; execute every init script in order.
- Expand positive and negative tenant-isolation tests to every tenant-owned table, relationship and API object under the non-owner runtime role; current contract-row, actor-membership foreign-key and global-user self-only tests are not exhaustive.
- Test role escalation, token expiry, JWKS rotation, HMAC key rotation/recovery and rate limiting (membership revocation and read-only role denial now have initial integration coverage).
- Test import replay, row-number conflicts, malformed payloads, large payloads and CSV formula injection.
- Test match decision races and calculation reproducibility/restatement.
- Add a secure upload provider and privacy-controlled file lifecycle before customer data.
- Complete independent penetration test and Australian legal/privacy review before any live pilot.

## Release decision
**Prototype engineering foundation: partially implemented.**  
**Private customer pilot: not approved.**  
**Production: not ready.**

No customer data should be entered into the public repository or current browser demo.

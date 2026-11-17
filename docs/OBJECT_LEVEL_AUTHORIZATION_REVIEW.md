# ProfitPilot — Independent Object-Level Authorization Review Package

**Prepared:** 17 November 2026  
**Engineering branch:** `security/comprehensive-hardening`  
**Assessment status:** Engineering regression suite; **independent assessment not yet commissioned or performed**.

## Scope for external reviewer
- BOLA/IDOR: arbitrary foreign IDs for imports, invoice match reviews, calculations, privacy requests, member permission overrides, exports, redactions and closures.
- Both cross-organization and same-organization/other-subject access tests, including different tenant memberships, roles, revoked accounts, step-up and legal holds.
- PostgreSQL RLS and direct restricted-role SQL, row ownership, SECURITY DEFINER functions, audit trails, and composite foreign keys.
- Tenant context HMAC signing and issuer binding, key compromise, connection-pool isolation, concurrency and transaction rollback.
- JWT validation, provider MFA assurance, session renewal and revocation; explicit administrator and backup/restoration boundaries.
- Re-run with both authenticated request paths and deliberately manipulated identifiers or request bodies. Record each HTTP status, response body, database delta and audit event.
- Manually review the discovered route list, non-tenant `/v1/me` endpoints, scheduled jobs and each privileged definer function for overlooked paths.

## Current regression evidence
- `tests/tenant-isolation-catalog.integration.test.js`: public-table inventory, RLS, unscoped and unsigned-context denial, runtime grants.
- `tests/route-tenant-isolation.integration.test.js`: cross-tenant route gates and authenticated foreign-record-ID probes.
- `tests/api.integration.test.js`: endpoint-specific privacy and step-up cases, including isolated account exports.
- `tests/account-closure.integration.test.js`: closure and session revocation.
- `tests/import-retention.integration.test.js`: retention, hold and deletion enforcement.
- PostgreSQL 16 and Node.js 22 CI, with real restore drill and container smoke test. Exact current commit/run must be captured from CI before updating evidence status.

## Review acceptance and evidence format
For each route/object/function, reviewer records tenant, user role, legitimate baseline result, attempted forbidden action, expected denial, actual result, leaked fields, state changes, audit impact and reproducible request. **Any unauthorized data disclosure or modification is a blocking finding**. Distinguish `404`, `403`, validation errors and `500`; verify that errors do not leak sensitive existence metadata.

## Explicit limitations
These tests do not demonstrate a live provider MFA ceremony, production deployment hardening, real backup storage, complete legal retention compliance or independent penetration testing. Security audit pass is not an assurance certificate. Do not release sensitive customer data or claim an independent assessment until a qualified independent reviewer completes and signs the work.

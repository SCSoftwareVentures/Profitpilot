# Local development setup — ProfitPilot

This guide is for a developer with Node.js 22, Docker Compose and a local terminal. It is not an iPhone-only deployment path.

## Before starting
- Clone the repository.
- Install Node.js 22 and Docker Compose.
- Configure a real OIDC identity provider that issues RS256/ES256 JWTs and exposes a JWKS endpoint.
- Do not use production/customer data.
- Database passwords and the tenant-context HMAC key are supplied through environment variables; never commit `.env` or reuse development credentials in shared environments.

## Local database and API
1. Copy `.env.example` to `.env`.
2. Generate three independent random values, each at least 32 bytes encoded as hexadecimal: `POSTGRES_ADMIN_PASSWORD`, `POSTGRES_APP_PASSWORD` and `TENANT_CONTEXT_HMAC_SECRET`.
3. Set `DATABASE_URL` to use the same `POSTGRES_APP_PASSWORD` for local Node.js execution.
4. Configure `AUTH_ISSUER`, `AUTH_AUDIENCE`, `AUTH_JWKS_URL` and `CORS_ORIGIN` for your identity provider and local client.
5. Review the SQL schema and ordered initialization/migration scripts. The migration creates a `NOLOGIN BYPASSRLS` context-validator owner and therefore requires a privileged database administrator.
6. Start the database and API using Docker Compose.
7. Check the health endpoint at `/health`.
8. Provision a user and tenant membership using a reviewed administrative process before making authenticated requests.

The Compose database initialization scripts run only when the named database volume is first created. Existing volumes are not automatically migrated. Back up data and apply migrations deliberately; never delete a volume containing data to force a reinitialisation. The runtime database password and HMAC key are passed to both database bootstrap and API processes from `.env`; the database key table is not readable by the runtime role.

## API boundaries
- The API is not deployed by this repository.
- The placeholder API URL in OpenAPI is not a real service.
- Browser prototype imports are local-only and do not call the API.
- JSON row ingestion is implemented; raw file upload and secure object storage are not.
- Invoice and payroll structural row validation are implemented; no payroll pool or financial allocation is created automatically. Payroll source rows require source_ref, cost_component, a positive decimal-string amount, currency AUD and valid period_start/period_end within the import period.
- Do not use real personal, payroll or customer information in this prototype.

The fresh local Compose volume applies migrations through 027. A Node.js regression test compares every ordered migration and bootstrap script in Docker Compose with GitHub CI, so a new migration cannot silently be omitted from local initialization. Compose is development-only; the local database connection uses no TLS and must never be exposed or used with real customer data. Existing volumes require an explicit, reviewed migration with a backup and rollback plan; do not erase them or assume editing Compose has upgraded an existing database. CI is the verification path, not a production deployment.

Provision synthetic users with the exact configured AUTH_ISSUER in auth_issuer. Existing users without a verified binding cannot authenticate; no automatic backfill is performed.

## Connected synthetic payroll workspace

For development or CI only, set ENABLE_SYNTHETIC_PAYROLL_UI=true before starting the API in a non-production environment. Open /dev/payroll on the same origin as the API. The exact page and three asset routes are explicitly allowlisted; production mode never serves them. Use only synthetic provisioned IDs and short-lived test-provider access tokens, one token entry per action. Fresh provider-issued MFA is required for sensitive actions; the page does not issue tokens or simulate MFA. The API independently enforces tenant and role permissions. Do not publish this development interface or enter live data. No token persistence, automatic financial mutation retries or demo data fallback. Tenant discovery, provider sign-in, account switching and browser E2E testing remain outstanding before a production UI is ready.

The synthetic payroll workspace also provides a versioned contribution report form and saved evidence retrieval by run ID. It refuses to display older formula versions as current and never treats partial contribution as profit. Exact AUD amounts and excluded whole-pool context are presented separately. Browser interaction testing is still outstanding.

Version 0.3.0 supports a synthetic supplier-match confirmation control using an existing candidate match ID, fresh MFA, explicit category and duplicate/payroll-overlap attestations. The report presents supplier, subcontractor and other direct costs and a clearly labelled included-cost ratio. It still requires upstream canonical invoice candidate preparation and full source coverage before any complete profit estimate; never enter real data in this workspace.

The synthetic workspace now supports invoice batch creation with source-declared SHA-256, JSON staging, independently declared manifest preparation, fresh-MFA candidate retrieval and specific match approval/hold/rejection. Change tenant or batch, clear the workspace, or reload candidate evidence before further decisions. Three distinct accounts remain required. No actual source-file hash verification, live data, production provider, or browser E2E testing is implied.

Shared overhead uses a canonical supplier candidate and a separately reviewed exact signed site-share vector. Migration 027 protects the confirmed match, source invoice line and invoice header from UPDATE/DELETE. Existing volumes must apply this migration explicitly. Shared cost allocation currently covers sites of one contract business only.

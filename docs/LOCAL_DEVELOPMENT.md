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

The Compose database initialization mounts now mirror migrations 002–033, with parity checked against CI by tests/bootstrap-parity.test.js. CI also syntax-checks Compose without starting containers. A real fresh-start Compose boot and an existing-volume upgrade test have **not** been performed. The Compose database initialization scripts run only when the named database volume is first created. Existing volumes are not automatically migrated. Back up data and apply migrations deliberately; never delete a volume containing data to force a reinitialisation. The runtime database password and HMAC key are passed to both database bootstrap and API processes from `.env`; the database key table is not readable by the runtime role.

## API boundaries
- The API is not deployed by this repository.
- The placeholder API URL in OpenAPI is not a real service.
- Browser prototype imports are local-only and do not call the API.
- JSON ingestion is client-declared. Original CSV ingestion supports bounded uncompressed UTF-8 files, checksum checks and metadata receipts. Original bytes stored in PostgreSQL; production encryption, retention and malware scanning are not established.
- Invoice and payroll structural validation and reviewed payroll reconciliation are implemented.
- Do not use real personal, payroll or customer information in this prototype.

## Profiles and dependency installation
Use npm ci --ignore-scripts with the committed lock. Compose defaults to the synthetic prototype. Protected images require an explicitly selected Docker target, verified database TLS, mounted secrets, trusted MFA assurance configuration and independently maintained ClamAV definitions. See SECURITY_PRIVACY_HANDOVER.md. No actual customer data until release approval.

# Local development setup — ProfitPilot

This guide is for a developer with Node.js 22, Docker Compose and a local terminal. It is not an iPhone-only deployment path.

## Before starting
- Clone the repository.
- Install Node.js 22 and Docker Compose.
- Configure a real OIDC identity provider that issues RS256/ES256 JWTs and exposes a JWKS endpoint.
- Do not use production/customer data.
- The local database role bootstrap contains a fixed development-only password and must be changed before any shared environment.

## Local database and API
1. Copy .env.example to .env.
2. Set a strong unique POSTGRES_ADMIN_PASSWORD.
3. Configure AUTH_ISSUER, AUTH_AUDIENCE, AUTH_JWKS_URL and CORS_ORIGIN.
4. Review the SQL schema and all migration scripts.
5. Start the database and API using Docker Compose.
6. Check the health endpoint at /health.
7. Provision a user and tenant membership using a reviewed administrative process before making authenticated requests.

The Compose database initialization scripts run only when the named database volume is first created. Existing volumes are not automatically migrated. Back up data and apply migrations deliberately; never delete a volume containing data to force a reinitialisation.

## API boundaries
- The API is not deployed by this repository.
- The placeholder API URL in OpenAPI is not a real service.
- Browser prototype imports are local-only and do not call the API.
- JSON row ingestion is implemented; raw file upload and secure object storage are not.
- Invoice row validation is implemented; payroll import validation is not.
- Do not use real personal, payroll or customer information in this prototype.

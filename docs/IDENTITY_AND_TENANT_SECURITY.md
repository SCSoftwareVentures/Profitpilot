# ProfitPilot — Identity, Tenant Isolation and Security Implementation Plan

**Status:** partial implementation scaffold. The API includes JWT/JWKS verification, tenant membership checks, role middleware, transaction-scoped tenant context and a PostgreSQL RLS migration. The schema and migrations were executed against an ephemeral PostgreSQL 16 service in GitHub Actions, and a basic RLS isolation check passed under the restricted runtime role. They have not been tested in a production environment or independently security-tested. Secure file storage is not implemented.

Tenant RLS now uses a short-lived HMAC-signed transaction context containing the tenant ID, verified identity subject, expiry, nonce and key ID. The API signs this context with `TENANT_CONTEXT_HMAC_SECRET`; PostgreSQL validates it in `private.current_tenant_id()` and independently checks active tenant membership. The validator is a locked-down `SECURITY DEFINER` function owned by a `NOLOGIN BYPASSRLS` role; its signing-key table is in a private schema inaccessible to `profitpilot_app`. CI proves that setting `app.tenant_id` alone does not grant rows, while a correctly signed context does, and verifies that cross-tenant reads/writes remain blocked and context is cleared after transaction completion. This improves protection against arbitrary SQL under the application database role **provided the signing secret remains confidential**. A compromised API process or leaked HMAC secret can still forge tenant contexts. The migration creates a `BYPASSRLS` role and therefore requires a suitably privileged database migration administrator; production key provisioning, rotation and recovery procedures remain to be operationalised.

## Identity boundary
Use a managed identity provider with OIDC/OAuth 2.0 Authorization Code + PKCE for browser clients. The application must not store raw passwords. Require MFA for privileged users; provide secure recovery, session revocation, rate limiting and account lifecycle controls.

The database user identity is mapped from a verified provider subject, never from a client-supplied user ID or email string alone.

## Tenant membership
A user may belong to multiple tenants. Every request resolves the active tenant from a server-verified membership record. A tenant ID supplied by the browser is only a requested context, never proof of access.

Roles proposed for the first release:
- owner: tenant ownership and membership administration;
- admin: configuration and user administration;
- analyst: imports and analysis;
- reviewer: approve/reject mappings and calculation outputs;
- read_only: view permitted reports.

Separate high-impact actions such as membership changes, exports, baseline approval and allocation confirmation. Require re-authentication or step-up MFA where risk warrants it.

## Server-side authorization requirements
- Deny by default.
- Check tenant membership and object ownership on every read/write.
- Never rely on hidden buttons or client-side route guards.
- Scope all database queries by verified tenant context.
- Validate object-level permissions, not only endpoint-level roles.
- Use parameterized SQL and schema validation.
- Log authorization denials and sensitive exports without logging secrets or unnecessary personal data.

## PostgreSQL row-level security deployment pattern
The tenant RLS migration enables and forces row-level security on tenant-owned tables using `private.current_tenant_id()`, which validates a short-lived HMAC-signed transaction context and active membership. PostgreSQL 16 CI tests passed for valid context, raw-GUC spoof rejection, cross-tenant row isolation, cross-tenant write rejection and pooled-context cleanup. Production deployment, key rotation/recovery and broader all-table adversarial isolation tests remain outstanding. Before any shared or production deployment:
1. Define a server-only transaction-local tenant context.
2. Set it only after verifying identity and membership.
3. Ensure pooled connections cannot leak context between requests.
4. Enable and FORCE ROW LEVEL SECURITY on every tenant-owned table.
5. Add both USING and WITH CHECK policies for tenant_id.
6. Ensure table owners and service roles cannot bypass policy unexpectedly.
7. Add negative tests for every table and relationship.

Illustrative policy pattern only:

```sql
ALTER TABLE sites ENABLE ROW LEVEL SECURITY;
ALTER TABLE sites FORCE ROW LEVEL SECURITY;

CREATE POLICY sites_tenant_isolation ON sites
USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);
```

Do not copy this blindly into production. Missing, expired, forged or membership-invalid context must deny access. Keep the signing key out of source control and inaccessible to the database runtime role. The API process is trusted with this secret; protect it accordingly.

## File and import security
- Private object storage, not public repository or browser local storage.
- Short-lived signed upload/download URLs.
- File size/type allowlist, malware scanning and isolated parsing.
- Content hash, source manifest and idempotency.
- Encrypt at rest and in transit.
- Access logging and retention/deletion workflow.
- CSV formula-injection protection on exports.
- Do not retain raw payroll/personnel files longer than necessary.

## Secrets and integrations
- Store secrets in managed secret storage, never source control or client JavaScript.
- Separate sandbox and production credentials.
- Rotate credentials and support immediate revocation.
- Verify webhook signatures, timestamps and replay protection.
- Idempotent event processing and daily provider reconciliation where applicable.

## Audit
Append-only events for login/security changes, membership, source upload/access, mapping, calculation, approval, export and any later payment-state transition. Audit logs must be access-controlled and tamper-evident.

## Required pre-production evidence
- Identity-provider configuration and recovery tests.
- Tenant-isolation negative test suite for all entities and API endpoints, including a reviewed decision on the trust boundary for application-set tenant context.
- RLS tests under the real application database role and connection pool.
- Independent penetration test and remediation retest.
- SAST, dependency and secret scanning.
- File malware/parser tests.
- Backup restore and incident-response exercises.
- Privacy impact assessment, retention schedule and verified deletion tests.

No production security certification is implied by this plan.

# ProfitPilot B16 — Protected identity preflight (draft)

**Purpose:** Refuse a protected API process before it binds a listener when its configured identity provider is malformed or points to an explicitly local endpoint. This change is a local security preflight, not real MFA enrolment, a pen test or live provider certification.

## Audited gap

Previously, protected configuration checked that a nonempty AUTH_MFA_ACR existed, and signed bearer requests used a JOSE JWKS configuration validator. However the validator only ran upon an authenticated API request. A protected instance could answer its database health endpoint and start listening with a malformed or local identity-provider endpoint. This could mislead deployment readiness checks and allow misconfigured outbound JWKS fetches once requests arrived.

## B16 implementation

- Execute the identity-provider validation synchronously during protected API startup, before constructing/listening on the Express app.
- Require nonempty, length-bounded and unambiguous audience strings.
- Retain HTTPS-only and credential/fragment rejection for issuer and JWKS endpoints, except the existing explicit non-protected, local-only test harness.
- For protected mode, reject IP-literal hosts (including private, loopback, link-local and IPv6), localhost, subdomains under .localhost, and .local domains for **both** OIDC issuer and JWKS URL.
- Regression tests cover acceptable public DNS hostnames, malformed audiences, localhost, literal IP/IPv6, local DNS suffixes, HTTP, URL credentials and fragments.

## What this does not verify

1. A public hostname can resolve to an internal address or change with DNS rebinding. The actual production egress policy must independently allowlist the approved OIDC/JWKS provider and block private/metadata endpoints.
2. The startup check validates syntax and scope, not the actual provider's availability, origin trust, MFA enrolment, revocation, step-up effectiveness, claim semantics, high availability or account recovery. Real provider integration tests and independent sign-off remain mandatory.
3. A database health check still proves only database connectivity, not full business or identity readiness. Production monitoring and release policy must not equate /health with authorisation.
4. The basic API prototype is not a production deployment; protected mode requires separate HTTPS edge, TLS database, mounted secrets, malware signature mount and identity operations.
5. Grype still reports 14 OpenSSL vulnerabilities in the protected scanner, with no verified fixed-version remediation in the latest retained artifact. Production and signed buyer dossier releases remain blocked.
6. This is a synthetic-only code change. No real identity provider has been connected, no keys provisioned, no deployment/merge, no purchases or customer data.

**Quality gate:** The Node.js, CodeQL, PostgreSQL and Compose tests must pass at the exact draft commit. The container security job must not be bypassed.

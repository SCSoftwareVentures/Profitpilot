# ProfitPilot — Permission and Step-Up Authentication Model

**Status:** Implemented enforcement foundation; identity-provider integration and permission-administration workflow remain release gates.  
**Scope:** API authorisation for tenant-scoped operations.

## 1. Authorisation decision

A protected request must pass all applicable layers:

1. A valid signed access token with configured issuer, audience, allowed signing algorithm, expiry, issue time and subject.
2. An active user and active membership in the requested tenant.
3. Database Row-Level Security using the verified, signed tenant context.
4. A named permission granted by the member's role or a tenant-specific member override.
5. Recent step-up authentication for designated sensitive actions.

A tenant ID, role, user ID, email address or permission supplied by the client is never evidence of authority.

## 2. Permission catalogue

Migration `008_granular_permissions.sql` creates a permission catalogue, role-to-permission defaults and tenant-scoped member overrides.

| Permission | Owner | Admin | Analyst | Reviewer | Read-only |
|---|---:|---:|---:|---:|---:|
| contracts.read | Yes | Yes | Yes | Yes | Yes |
| imports.create | Yes | Yes | Yes | No | No |
| imports.rows.write | Yes | Yes | Yes | No | No |
| imports.validate | Yes | Yes | Yes | Yes | No |
| matching.decide | Yes | Yes | No | Yes | No |
| calculations.create | Yes | Yes | Yes | Yes | No |
| calculations.read | Yes | Yes | Yes | Yes | Yes |
| security.permissions.manage | Yes | No | No | No | No |
| security.sessions.manage | Yes | Yes | No | No | No |
| privacy.requests.manage | Yes | Yes | No | No | No |

The API resolves permissions server-side. An explicit member denial takes precedence over an explicit grant; an explicit grant takes precedence over the role default. Overrides are tenant-scoped and protected by forced RLS. Runtime access is currently read-only for override records; a reviewed owner-only permission-administration API remains to be implemented.

## 3. Step-up authentication

Sensitive matching decisions require both:
- a recent `auth_time` claim; and
- an `acr` claim exactly matching `AUTH_STEP_UP_ACR`.

`AUTH_STEP_UP_MAX_AGE_SECONDS` defaults to 300 seconds and is constrained to 30–900 seconds. Missing configuration, missing claims, stale authentication or a mismatched assurance class fails closed.

This middleware verifies claims issued by the configured identity provider. It does not itself perform MFA. The selected provider must be configured to issue the required `auth_time` and assurance-level `acr` only after the approved MFA/passkey step-up flow. Provider configuration, recovery controls and phishing-resistant MFA remain production integration requirements.

## 4. Audit and operational requirements

Permission changes must eventually record actor, subject, tenant, permission, old value, new value, reason, timestamp and correlation ID. High-impact changes should require step-up authentication and separation of duties. Do not permit an administrator to grant permissions beyond their own authority.

## 5. Verification

CI exercises:
- role-based allow/deny behaviour for the current API routes;
- tenant-specific explicit grant and deny precedence;
- stale or missing step-up claims being denied;
- database migration and RLS for the override table;
- the existing tenant isolation and authenticated API suite.

CI success is evidence for the tested code and ephemeral environment only. It is not proof of production identity-provider configuration, MFA enrolment, independent penetration testing or certification.

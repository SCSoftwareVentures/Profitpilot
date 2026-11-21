# ProfitPilot B14 — Protected runtime startup hardening

**Status:** Draft application boundary enforcement and regression tests, not a production deployment or independent security sign-off.

## Why

The previous protected profile required mounted database/tenant secrets, database TLS, a scanner and MFA claim, but did not require that Node actually run in production mode. The authentication module previously allowed a test-only loopback HTTP JWKS URL whenever NODE_ENV=test, even if the protected profile was configured. An invalid browser-origin allowlist could also be passed directly to Express CORS.

## Implemented

1. A protected profile **requires NODE_ENV=production**, regardless of whether other protected settings exist. The profile remains fail-closed when prerequisites are absent.
2. The protected profile refuses HTTP, wildcard, malformed, path/query/fragment-bearing, credential-bearing, loopback, duplicated and overlarge CORS entries. Allowed entries are exact canonical HTTPS origins, maximum eight. Empty allowlist denies browser cross-origin requests.
3. The application uses the validated profile-specific allowlist, not a second unchecked parsing path. Local synthetic prototype workflows retain their existing explicit CORS behaviour.
4. The test-only local HTTP JWKS exception explicitly excludes protected mode; the protected profile's production-only requirement is the primary safeguard.
5. Node regression tests cover the rejected configurations and permitted HTTPS origins.

## Residual trust and release blockers

- CORS is **not authentication**. Bearer JWT validation, tenant-scoped RLS, strong MFA configuration and source-authority checks are separate requirements.
- A matching MFA acr string is not proof of genuine MFA enrolment, token revocation or that the issuer is trustworthy. A qualified deployment reviewer must validate the real identity provider and its claims.
- HTTPS CORS does not itself provide an HTTPS edge. The reverse proxy, certificates, HTTP security policy, actual TLS/storage key custody and request logging require independently reviewed runtime infrastructure.
- The existing Compose example remains **prototype-only** and is not an approved production configuration.
- The protected image still reports 14 blocked OpenSSL vulnerability findings in the current CI scanner database. All five engineering gates must pass at an exact candidate SHA before a release is considered.
- B13 signatures prove pinned-key possession, **not** independently completed review or permission to deploy.
- No live customer data, deployment, purchase, branch merge or public release is authorised or performed here.

## QA

CI Node checks include these startup and CORS tests. The full CI remains expected to fail closed on the unresolved protected-image vulnerabilities. Physical iPhone testing, independent penetration testing, Australian legal/privacy and operational recovery evidence remain outstanding.

# ProfitPilot B25 — independent isolated protocol staging and key-rotation review

**21 November 2026. No production systems, external IdP, paid service, deployment or merge.**

## Tested boundaries

B24 proved protected container startup with synthetic mounted secrets but used no network access. The B25 draft adds protocol-level evidence from two independently exercised areas.

### A. Real PostgreSQL over verified TLS

`scripts/rehearse-protocol-staging-b25.mjs` creates an ephemeral certificate authority and a signed server certificate. It launches a separate official PostgreSQL 16 Alpine container with a loopback-only host port, SCRAM authentication and a `pg_hba.conf` that rejects all plaintext TCP connections. Node's protected `databaseConfig()` reads a mode-0600 mounted-style synthetic database URL, requires `ssl.rejectUnauthorized=true` and connects to the database. It queries `pg_stat_ssl` to prove an actual negotiated TLS session.

Negative tests separately demand rejection of plaintext TCP and a certificate with the wrong hostname. The CA is added only to the test Node subprocess trust store; PostgreSQL and issuer certificate materials are ephemeral, not customer or production keys. The container, temporary files and child processes are removed after the check.

### B. Real HTTPS JWKS and signed JWT/MFA enforcement

The same ephemeral CA signs a local HTTPS issuer certificate. The staging process adds a synthetic `issuer-ci.invalid` DNS alias to the **disposable CI runner's** hosts file. No public DNS, real identity-provider account or production user is involved.

The protected `identityConfig()` and `authRequired()` paths are exercised with real signed RS256 tokens and an HTTPS remote JWKS response. The tests demand 401 for missing bearer JWT, wrong issuer, wrong audience, expiry and an unknown signing key; 403 for incorrect MFA claim and stale write-step-up `auth_time`; and success for valid read/write tokens and two overlapping issuer keys. This validates the cryptographic verification path, not the quality of the external issuer or revocation SLA.

### C. PostgreSQL RLS and mounted secret rollover

The existing three integration suites continue using the restricted application database role. B25 extends the authenticated API integration suite to test `withTenantUsingPool()` against **actual tenant RLS** while its signing key is supplied via mode-0600 mounted file and replaced atomically: active replacement allows tenant A, revoked primary must not allow tenant rows, restoring the correct replacement works, and tenant B access remains denied. This builds on existing key overlap, privileged rotation and rollback-safety tests rather than simulating a database policy.

## Security boundaries and limitations

- A loopback-only **synthetic TLS PostgreSQL** and HTTPS synthetic issuer prove real protocols, but they are **not** a live production-equivalent external staging account, identity provider, managed database, deployed edge, production egress allowlist or operational certificate authority.
- The JWKS validation checks supported overlapping keys, not immediate provider revocation or cache eviction. In-memory JWKS caching, stale keys, provider outage behaviour, full token revocation and MFA device/provider assurance still require live provider testing and independent assessment.
- Protected database URL identity, CA pinning strategy, server certificate renewal, least-privilege migration operator and production HBA/TLS policy still require independent operator verification with real staging ownership and audit trails.
- Mounted secret rotation test uses synthetic keys, not independent key custody, real secret-store rollout, emergency rotation or incident response. RLS validation applies to the separately exercised test database; it must not be called an end-to-end protected-mode production database test.
- OpenSSL 3.5.9-r1 in the protected scanner retains **14 blocking findings**; the full Grype scan and B19 patch-floor check remain unchanged, with no suppression, bypass, unsigned replacement or release approval.
- All secrets are generated only within the disposable runner, no external account actions, production changes, merges, deployments or additional purchases. Note that the hosts-file modification is confined to an ephemeral GitHub Actions runner.

**B25 acceptance:** exact-head GitHub Actions: all unit and three PostgreSQL integration suites pass with zero skipped; the new TLS and issuer protocol stage passes all positive/negative cases; B24 protected-container checks, ClamAV fail-closed checks, recovery/Compose and CodeQL pass; the independent protected OpenSSL/CVE gate remains hard-blocking until an actual signed vendor patch exists. CI must not claim live operational certification or production release approval from isolated testing.

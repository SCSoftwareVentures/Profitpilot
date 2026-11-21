# ProfitPilot B24 — Production-equivalent protected-container startup rehearsal

**Scope:** Isolated synthetic staging checks inside the actual protected image, executed by GitHub Actions. This is **not** a deployed production environment, external security sign-off, or real identity-provider/database integration.

## Threats and acceptance

Previously B22's mounted-secret security logic was covered in local Node tests. CI did not launch the actual protected container with runtime UID 1000, external read-only secret mounts, denied external networking and the complete protected-mode configuration. B24 closes that testing gap without weakening OpenSSL/CVE gates.

B24's `scripts/rehearse-protected-startup-b24.mjs` exercises:

- **Valid protected process**: actual `profitpilot-protected:ci` image, NODE_ENV=production, PROFITPILOT_PROFILE=protected, malware scan configured, database TLS required, HTTPS issuer/JWKS, synthetic mounted PostgreSQL URL, 32-byte random HMAC key, file modes 0400/0600, correct UID 1000. Root and mount read-only; cap-drop ALL, no-new-privileges, no host ports and `--network none`. Host-side `sudo` is limited to disposable fixture ownership preparation and cleanup; application containers run nonroot.
- **Effective host-confinement verification**: independently inspect Docker HostConfig for network mode `none`, read-only rootfs, no published ports, no privileged mode and all capabilities dropped. Attempt to open a UID-1000-owned mode-0600 secret for writing and require Linux `EROFS` to prove the mounted filesystem is actually read-only, rather than trusting command-line flags or restrictive file permissions alone.
- **HTTP probe within the network-isolated container**: unauthenticated `/v1/me` yields 401; an untrusted browser origin receives no CORS allow-origin; `/health` yields 503 because no database is connected. A synthetic offline environment must not represent itself as database-ready.
- **16 deliberately invalid protected startups**: missing DB secret, missing HMAC secret, file exposed through group/world permissions, symlinked parent, symlinked final file, writable parent, extra hardlink, wrong UID, weak key, embedded controls, DB URL TLS-override query, conflicting direct environment DB secret, conflicting direct environment HMAC secret, TLS disabled, scanner disabled and forbidden local/IP JWKS hostname. Each must exit nonzero promptly with the matching expected error; no timeout, unrelated Docker failure or default/prototype fallback is counted as a pass.
- Verify that startup logs do not contain synthetic mounted secret contents. No customer data or actual credentials are used; temporary fixtures are removed after the run.

## CI integration

The B24 step is included in the existing **PostgreSQL migrations and tenant RLS** job, *after* building the protected image, and is independent of the separate container-vulnerability job. The separate ClamAV positive/negative tests, unfiltered Grype security scan, independent B19 OpenSSL floor, CodeQL, backup/restore, RLS and no-skip test matrix are unmodified.

For reproducibility, CI invokes `node --check scripts/rehearse-protected-startup-b24.mjs` followed by `CI=true PROFITPILOT_B24_IMAGE=profitpilot-protected:ci node scripts/rehearse-protected-startup-b24.mjs`.

## Limits and mandatory independent security review

- No live PostgreSQL TLS server or failover exists in the B24 isolated startup check. Database authorization, HMAC/RLS and three integration suites remain tested separately using disposable PostgreSQL fixtures; do not equate the two environments with completed production-equivalent end-to-end TLS.
- No live OIDC/MFA provider, independently validated JWT claims, provider revocation, network egress/DNS policy, real malware-signature distribution, cloud secret manager, backup encryption custody or production secret rotation has been exercised.
- Runtime file checks cannot eliminate same-UID, privileged host or mount-namespace tampering; read-only mount provenance requires operator and independent review.
- Malicious-file rejection is tested separately with a harmless synthetic ClamAV signature. A scanner executable at startup does not imply real signatures are fresh.
- **OpenSSL 3.5.9-r1's 14 outstanding protected-image findings remain a hard release blocker**. B24 must not mark release ready or suppress an advisory to satisfy CI.
- No merge, real deployment, spending, network access by the tested container or release-signing action is authorised.

**Acceptance:** exact-head CI proof of B24 positive and 16 negative checks, clean separate Node/PostgreSQL/CodeQL/recovery jobs, and the existing CVE severity and package-floor checks continuing to fail appropriately until a signed vendor-fixed Alpine OpenSSL version is available.

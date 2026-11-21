# ProfitPilot B19 — OpenSSL security-patch readiness, fail-closed

**2026-11-21 — status: UPSTREAM BLOCKED, NOT PATCHED.**

## Explicit problem

The protected scanner runtime's `libcrypto3` and `libssl3` packages are `3.5.9-r1`. The exact-head B18 container scan (GitHub Actions #3201, commit `72e4185f14a889d86c8436feff7512bc59041690`) found fourteen unsuppressed matches: ten High and four Medium, across seven OpenSSL CVEs. The basic API image had zero matches. The ClamAV 1.4.7-r0 security update is already independently verified and retained.

OpenSSL's November security advisories specify that affected OpenSSL 3.5 series versions **before 3.5.10** are vulnerable. As of this audit the upstream source download and Alpine v3.24 signed stable x86_64 package still offer **3.5.9 / 3.5.9-r1**. Patch commits visible in Git are **not** a signed supported distro release. Do not substitute unreviewed self-compiled OpenSSL, a 4.1.0 release with known CVEs, incompatible old OpenSSL branches, Edge packages mixed into v3.24, or a scanner exclusion to claim this is fixed.

Supporting first-party sources:
- https://openssl-library.org/news/vulnerabilities-3.5/
- https://openssl-library.org/news/openssl-3.5-notes/
- https://www.openssl-library.org/source/
- https://pkgs.alpinelinux.org/packages?arch=x86_64&branch=v3.24&name=openssl&repo=main

## Implemented B19 security property

A testable, independently enforced **minimum upstream patch version** for the protected image:
- Parse the **actual signed APK installed ledger**, never only a Dockerfile comment or expected value.
- Require both `libcrypto3` and `libssl3` to be present **exactly once**, using a coherent identical 3.5.x `-rN` package version.
- Require **3.5.10-r0 or later in the supported 3.5 series**. Refuse the known vulnerable `3.5.9-r1` and all older versions, even if Grype loses its vulnerability database or returns a false negative.
- No auto-acceptance of a `3.5.9-rN` *backport*: a future vendor-repaired backport must be documented and independently reviewed against all seven CVEs before changing the gate.
- Run the installed-package verification in a **network-disabled, non-root, read-only** container after the complete Grype scan, with `if: always()`. The order preserves full, unfiltered vulnerability-report artifacts even on known-vulnerable images.
- Retain existing Grype severity and evidence gates unchanged. The new verifier's `vulnerabilityScanVerified` and `releaseApproved` always remain false; real proof is produced independently.

This change does **not** rewrite production dependency binaries or make the current `3.5.9-r1` image secure. The new CI step will **intentionally fail** until the actual vendor fix is present and rebuilt. Do not weaken the floor merely to produce green CI.

## Completion protocol when vendor package is actually available

1. Check vendor advisory, signature and supported Alpine v3.24 stable repository; verify the source/ABI and that the exact installed version resolves every blocking CVE. Record provenance.
2. Refresh the base-image and signed runtime packages using reproducible version pins/digests, without cross-repository mixing.
3. Rebuild **both** production profiles on a draft branch and inspect the exact installed APK inventory, including ClamAV 1.4.7+ and both OpenSSL libraries.
4. Re-run Node unit and integration checks, PostgreSQL/RLS, CodeQL, synthetic boot/recovery and the protected scanner negative/positive fixtures.
5. Run the **complete unsuppressed Grype scan** against both actual image identities and inspect CVE statuses and SBOM inventory.
6. Require a successful exact-head CI run and independent technical review. Only then allow authorised release-governance consideration; never auto-merge/deploy.

## Separate unsatisfied gates

Real cloud TLS and identity-provider/MFA verification, current vendor-signed ClamAV definition operation, independent penetration testing, independent legal/privacy assessment, physical iPhone accessibility/security checks, production-equivalent recovery and incident drills, intellectual-property chain of title and owner/independent-signer governance remain **not verified**.

**No spending, merge, protected deployment, payment processing or owner release approval was performed.**

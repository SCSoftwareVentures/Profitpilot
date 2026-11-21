# ProfitPilot B18 — ClamAV upstream security patch and uncompromised container gate

**Draft, 21 November 2026.** This is a vendor-supported dependency update in source code, not a release, independent native-code approval or full container-security pass.

## Evidence and decision

- Official ClamAV advisory, dated 18 November 2026: ClamAV 1.4.7 and 1.5.5 resolve multiple memory-corruption and denial-of-service vulnerabilities in earlier versions, including CVE-2026-76411 and CVE-2026-76422. https://blog.clamav.net/2026/11/clamav-155-147-security-patch-release.html
- Alpine v3.24/community/x86_64 mirror shows `clamav-libs-1.4.7-r0.apk` dated 19 November 2026. https://uk.alpinelinux.org/v3.24/community/x86_64/
- These are signed Alpine stable-channel packages. Do **not** mix Edge into the v3.24 rootfs, supply ad hoc binaries, use `--allow-untrusted`, or remove required libraries.
- OpenSSL upstream advisories dated 17 November 2026 identify issues affecting versions before 3.5.10; at this audit OpenSSL's official downloads still offer **3.5.9** for the supported 3.5 branch, while Alpine's latest stable and Edge package indices show **3.5.9-r1**. https://openssl-library.org/news/vulnerabilities/ ; https://openssl-library.org/source/ ; https://pkgs.alpinelinux.org/packages?branch=edge&name=openssl

## Implemented

1. Require **ClamAV 1.4.7-r0 or newer** for `clamav-dev` in the C adapter build stage and both `clamav-libs` and `clamav-libunrar` in the protected runtime. The exact vendor APK solver enforces these minima and fails the Docker build if the stable signed package source cannot resolve them.
2. Preserve the existing pinned Node Alpine base, signed APK keys, minimal scratch runtime, stripped unneeded tools, non-root execution, native scanner command and verified official ClamAV CVD signatures.
3. Independently parse the **built protected image's actual APK installed database** in CI. Both runtime scanner packages must be present once, with valid vendor versions >=1.4.7-r0. This is in addition to checking Dockerfile text.
4. Add tests that reject 1.4.6 and older scanner packages, missing/duplicate package entries, malformed version strings and unsafe repository-mixing commands.
5. Keep Grype's full, unfiltered, independently Docker-bound vulnerability gate for **both** API and protected images. All Medium/High/Critical/Unknown findings still block the release; there is no suppression or change in policy.

## Exact-head verification and residual blockers

The CI job must build both profiles, verify runtime package versions, execute the protected scanner fail-closed negative test, scan both actual images with a fresh Grype vulnerability DB and run the unsuppressed severity gate. Record exact head SHA and CI run URL in the draft PR when finished; do not infer success from an Alpine mirror listing alone.

**OpenSSL remains a hard release blocker until a trusted, supported, vulnerability-free package or independently reviewed comparable solution is built and scanned.** Some CVEs may have low upstream classifications, but this project deliberately retains its stronger policy, and no risk acceptance has been approved.

No live TLS edge, identity provider, real signature-update custody, independent native security audit, Australian privacy/legal review, customer access, production restoration, physical iPhone validation, buyer verification, merge, paid action or deployment is accomplished by this change.

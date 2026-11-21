# ProfitPilot B11 — OpenSSL runtime package reduction experiment

## Verified triggering event

The B10 Grype scan found seven distinct CVEs associated with Alpine OpenSSL packages libcrypto3 and libssl3 version 3.5.9-r1, repeated in both API and protected scanner images. Each image reported 10 High and 4 Medium findings. The scan's vulnerability database showed no fix versions. The policy correctly blocked the draft handover.

## Narrow experiment

Remove only the *explicit* libcrypto3 and libssl3 package declarations from the prototype-root APK setup. The Node runtime may bundle OpenSSL without needing the system shared libraries. The protected ClamAV image still resolves native scanner libraries normally. Preserve scratch/non-root runtime isolation, certificates, authentication and database semantics.

Container CI now checks that the basic API installed-package inventory omits these OpenSSL APKs, and exercises AES-256-GCM authenticated encrypt/decrypt, HMAC-SHA256, TLS secure-context creation, certificate store, module imports and existing runtime identity rules. The separate database integration CI tests the full API health route. Static tests ensure no reintroduction of explicit OpenSSL APKs or relaxation of scanner policy.

## Security limits

The Grype policy remains **unchanged**. Any Medium, High or Critical findings in either API or protected scanner image still block source dossier signing. The ClamAV native dependencies may continue to require OpenSSL, and this change does not assert the advisory risk is cleared or that upstream patches now exist.

Removing an APK package does not prove that the bundled Node.js/OpenSSL runtime has no vulnerabilities. CI image scans and an independent dependency/security review are still required. This branch is an experiment, not production remediation or a deployment. No suppressions, additional cost, merge, actual customer data or automatic notification.

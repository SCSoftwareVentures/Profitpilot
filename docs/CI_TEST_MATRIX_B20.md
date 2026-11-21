# ProfitPilot B20 — Explicit CI test matrix and zero-skip assurance

**Status: draft review gate.** Improves coverage transparency; does not alter authentication, tenant RLS, production security approval, malware scanning or the unresolved OpenSSL release hold.

## Why 3 tests appeared skipped

Prior `npm test` used `node --test` auto-discovery across every test file. Three integration tests intentionally used `{skip:!enabled}` when the local Node job lacked `TEST_ADMIN_DATABASE_URL` and `TEST_APP_DATABASE_URL`. The CI PostgreSQL job separately ran all three against a synthetic database, but the Node summary always displayed `3 skipped`. That made correctly separated coverage look incomplete and could conceal a future integration suite that was not registered in the PostgreSQL job.

## What B20 changes

- `npm test` now runs **only unit-test files**, automatically discovered recursively under `tests/` using `scripts/run-test-matrix.mjs unit`. It prints a machine-checked TAP summary requiring **zero skipped, zero failed** and all discovered tests passed.
- `npm run test:integration` runs the three database-dependent integration suites sequentially in isolated Node processes, using real synthetic CI PostgreSQL credentials. It rejects missing prerequisites, any failed or skipped test and an empty test suite.
- The required integration suites are explicitly registered and must **all exist**; adding an unregistered `*.integration.test.js` causes CI to fail until it is added to the integration execution inventory. The API integration suite remains **last**, because it rotates/revokes tenant context keys.
- The two jobs each append labelled results to GitHub's per-job `GITHUB_STEP_SUMMARY`: unit tests, and each of the three database-dependent suites. These summaries do not claim the unit job ran database tests.
- Node unit tests additionally cover matrix completeness, missing/extra integration tests, invalid discovery and duplicated test paths.
- Previous `npm test` unit summary: 194 discovered / 191 passed / 3 skipped; the 3 separately passed in PostgreSQL integration. New totals are assessed independently after CI runs. Do not claim a reduction in test coverage merely because the unit job no longer enumerates integration-only cases.

## Release evidence and remaining gates

Required review evidence is the exact-head GitHub Actions run showing:
1. Unit job executes all discovered unit tests with **zero skips**.
2. PostgreSQL job explicitly executes all three integration suites with **zero skips** and succeeds on migrations, access isolation and backup/restore.
3. CodeQL, synthetic Compose/recovery and full protected-image vulnerability scanning run unchanged.
4. OpenSSL's vulnerable Alpine `libcrypto3`/`libssl3` `3.5.9-r1` version is **still blocked** by both Grype's unsuppressed scan and the separate B19 patched-version check until a supported upstream fix is verified.

This does **not** authorize release, live deployment or production operation. All work remains on an unmerged draft PR with no spending.

# ProfitPilot — Security & Privacy Control Evidence Matrix

**Revision:** 17 November 2026  
**Purpose:** Buyer due-diligence index connecting control claims to code, tests and remaining evidence.  
**Status rule:** “Implemented / CI verified” applies only to the specific test scope and commit noted. It does not mean production operation or independent assurance.

| ID | Control area | Current implementation / evidence | Verification evidence | Status | Remaining work |
|---|---|---|---|---|---|
| IAM-01 | JWT/JWKS validation | `server/auth.js`; issuer/audience/JWKS configuration; restricted algorithms and claim checks | Node/API integration CI | Implemented in scaffold; config-dependent | Configure production identity provider; test provider rotation, recovery and operational MFA |
| IAM-02 | Step-up for sensitive actions | Middleware checks recent `auth_time` and required `acr` claim | Integration tests reject missing/stale claims | Claim enforcement implemented | Provider must enforce MFA/passkey before issuing claim; prove recovery and phishing resistance |
| IAM-03 | Tenant membership | API resolves active membership from verified subject and tenant | Authenticated API negative tests | Implemented / CI tested | Expand all-route/object coverage; production provisioning/deprovisioning |
| IAM-04 | Granular permissions | Permission catalogue, role grants, tenant overrides | Role denial and grant/deny integration tests | Implemented / CI tested | Periodic access review, admin UX, production monitoring |
| TEN-01 | Signed tenant context | HMAC-signed, transaction-scoped context; private key table unavailable to runtime | Forgery, expiry, revoked key, membership and pooled-context tests | Implemented / CI tested | Production KMS/secret custody, rotation and recovery; external review |
| TEN-02 | PostgreSQL RLS | Forced RLS and restricted runtime role | PostgreSQL migration/RLS tests; cross-tenant read/write negatives | Implemented for tested schema/routes | Exhaustive table, view, function, job and endpoint audit |
| PRIV-01 | Privacy request subject isolation | Migration 012 subject-level SELECT/INSERT/UPDATE policies | Direct runtime SQL tests and API integration tests in CI #1046 | CI verified in run #1046 | Expand tests for all roles and edge cases; independent review |
| PRIV-02 | Privacy request workflow | Submit, own-list, manager queue, identity review, legal hold, rejection, withdrawal | API integration tests in CI #1046 | Partially implemented / CI verified | Production privacy centre and verified requestor identity process |
| PRIV-03 | Prevent false fulfilment | Later API change returns 409 when fulfilment executor is absent | Authenticated API integration test and complete CI run #1058 passed | Implemented / CI verified in run #1058 | Build real export/correction/restriction/deletion executors and test them |
| PRIV-04 | Data access/export | Restricted requester-only, independent approval, fresh MFA, expiring one-use account/activity export | Migrations 014–015; authenticated API tests | Partial / CI tested | Full subject attribution, live provider testing, complete request fulfilment |
| PRIV-05 | Correction/restriction | No general correction or restriction executor established | Not implemented | Not implemented | Define field-level correction, downstream propagation, legal holds and proof |
| PRIV-06 | Deletion/de-identification | Controlled closed-request redaction, local account closure, session and discarded-import retention, disabled-by-default external erasure adapter | Migrations 016–024, account closure/import retention/restore tests | Partial / CI tested | Complete subject-level data deletion, approved retention policy, live provider erasure and backup lifecycle |
| AUD-01 | Tamper-evident audit chain | Per-tenant hash chain, append-only trigger, verification function | Audit integrity integration tests in CI #1046 | Implemented / CI tested | Independent design review, external anchoring/monitoring, retention and alerting |
| SES-01 | Session registry/revocation | Private session registry and scoped functions | Authenticated session tests | Implemented in scaffold | Production identity provider integration, refresh/recovery controls, alerting |
| API-01 | API hardening | Helmet, CORS allowlist config, body/rate limits, no-store, generic errors | API tests and CI | Partially implemented / CI tested | Production CSP, TLS, CSRF review if cookie auth, abuse monitoring and endpoint schema audit |
| API-02 | Database transport encryption | Production TLS guard, certificate verification, rejection of connection URL parameter overrides and global TLS bypass | CI #1138 configuration regressions | Configuration verified | Real handshake with production provider and certificate chain |
| DATA-01 | Data inventory | Schema-derived inventory in `PRIVACY_DATA_INVENTORY.md` | Static schema review | Preliminary document only | Reconcile all migrations, APIs, deployed services, logs, backups and subprocessors |
| DATA-02 | Encryption and key management | Production database TLS is required by startup guard and certificate verification is enabled in the PostgreSQL client; runtime secrets are externalised in CI | TLS configuration regression tests in CI #1066; ephemeral runtime DB credential bootstrap | Partially implemented / configuration CI verified | Complete real TLS handshake verification; prove at-rest encryption and production KMS custody/rotation/recovery |
| FILE-01 | Secure file handling | Current API persists JSON rows; no private binary storage or scanner established | Not implemented | Not implemented | Private object storage, upload validation, malware scanning, access logs and deletion lifecycle |
| SUP-01 | Dependency/supply chain | Dependencies declared in package manifest | Build and tests run in CI | Partial | Commit lockfile, pin/review dependencies, SCA, secret scanning, SBOM and container scanning |
| OPS-01 | Backups and recovery | Authenticated encrypted PostgreSQL dump and privacy checkpoint restore gate | Real disposable PostgreSQL backup/restore drill in CI #1138 | Synthetic recovery verified | Production scheduling, protected offsite storage, key custody, RPO/RTO and retention |
| IR-01 | Incident response | Requirements in threat/trust standards | No tabletop evidence | Not implemented | Named owner, escalation, containment, notification decision tree and exercise |
| ASSUR-01 | Independent security review | No independent test report | Not performed | Not performed | Independent penetration test, remediation and retest |
| LEG-01 | Privacy/legal assessment | Requirements documented | No completed PIA or legal sign-off | Not performed | Qualified Australian privacy/legal review; notices, contracts, processor and cross-border register |

## Evidence references

- CI run #1046 (privacy subject-isolation milestone): https://github.com/luxhustle01-ux/Profitpilot/actions/runs/44002838128
- CI run #1058 (fail-closed privacy fulfilment and current buyer-pack commit): https://github.com/luxhustle01-ux/Profitpilot/actions/runs/44004207499
- CI run #1066 (production database TLS fail-closed configuration and regression tests): https://github.com/luxhustle01-ux/Profitpilot/actions/runs/44005751530
- Threat model: [THREAT_MODEL.md](THREAT_MODEL.md)
- Trust/security/privacy standard: [TRUST_SECURITY_PRIVACY_STANDARD.md](TRUST_SECURITY_PRIVACY_STANDARD.md)
- Privacy engineering baseline: [PRIVACY_ENGINEERING_BASELINE.md](PRIVACY_ENGINEERING_BASELINE.md)
- Preliminary privacy data inventory: [PRIVACY_DATA_INVENTORY.md](PRIVACY_DATA_INVENTORY.md)
- Project status and release boundary: [PROJECT_STATUS.md](PROJECT_STATUS.md)

## Buyer interpretation

A control is not “production-ready” merely because code exists or a CI test passes. The evidence status must be upgraded only when the specific implementation, environment, operational process and independent review appropriate to that control are demonstrated. Do not market this matrix as certification or as a claim of full compliance.

## Current engineering evidence checkpoint
CI run #1138: https://github.com/luxhustle01-ux/Profitpilot/actions/runs/44055916897 — both jobs passed, including authenticated API integration, PostgreSQL tenant RLS, synthetic backup recovery, TLS configuration and dependency audit. This verifies the exact tested commit, not subsequent changes or production deployment. The newer source ingestion minimisation guard is an API-layer control, not full content redaction.

### Subsequent security branch implementation (CI unconfirmed)
Migrations 039–045 add transaction-bound session operations, database permission-read isolation, global revocation watermarks, signed restore evidence for global and individual token revocation, operator-separated account containment/recovery, and transaction/backend-bound tenant HMACs. Production explicitly distinguishes access-token JWTs from generic JWTs. Operator evidence digests are attestations, not automated provider confirmation. These are development changes, not a new verified CI checkpoint or production approval.

Security detection now has an allowlisted aggregate telemetry module and deterministic synthetic tests. It does not implement a live SIEM, incident delivery or account-attribution analytics; no such external service is configured.

Supply-chain update: resolved dependency lock, lifecycle-script suppression, npm ci, CycloneDX SBOM generation, existing dependency audit and Docker build-context/capability controls are now implemented. Registry provenance, image digest/scanner integration and ongoing dependency operations remain unverified. Current branch must pass the updated CI checks.

Runtime boundary update (migration 046): database/schema object creation and temporary tables are prohibited for the application role; production startup refuses elevated or misconfigured database connections and unsafe identity/CORS/secret configuration. Pool connections are reset or destroyed after work. Current commit-specific CI is required; new infrastructure and actual TLS provider handshake remain unverified.

Migration 047 adds operator-only audit prefix capture, restore validation of audit history and signed evidence of retired signing-key tombstones. No independently administered offsite custody service or live restore orchestration is configured.

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
| PRIV-04 | Data access/export | No automated export generator or secure delivery path established | Not implemented | Not implemented | Build field-scoped export, requester verification, expiry, access logging and secure delivery |
| PRIV-05 | Correction/restriction | No general correction or restriction executor established | Not implemented | Not implemented | Define field-level correction, downstream propagation, legal holds and proof |
| PRIV-06 | Deletion/de-identification | No verified deletion engine or dependency/backup propagation | Not implemented | Not implemented | Data map, retention schedule, legal exceptions, deletion executor, backup expiry and restore tests |
| AUD-01 | Tamper-evident audit chain | Per-tenant hash chain, append-only trigger, verification function | Audit integrity integration tests in CI #1046 | Implemented / CI tested | Independent design review, external anchoring/monitoring, retention and alerting |
| SES-01 | Session registry/revocation | Private session registry and scoped functions | Authenticated session tests | Implemented in scaffold | Production identity provider integration, refresh/recovery controls, alerting |
| API-01 | API hardening | Helmet, CORS allowlist config, body/rate limits, no-store, generic errors | API tests and CI | Partially implemented / CI tested | Production CSP, TLS, CSRF review if cookie auth, abuse monitoring and endpoint schema audit |
| DATA-01 | Data inventory | Schema-derived inventory in `PRIVACY_DATA_INVENTORY.md` | Static schema review | Preliminary document only | Reconcile all migrations, APIs, deployed services, logs, backups and subprocessors |
| DATA-02 | Encryption and key management | Requirements documented; runtime secret configuration externalised in CI | CI validates ephemeral runtime DB credential bootstrap | Partially implemented | Prove TLS/at-rest encryption and production KMS custody/rotation/recovery |
| FILE-01 | Secure file handling | Current API persists JSON rows; no private binary storage or scanner established | Not implemented | Not implemented | Private object storage, upload validation, malware scanning, access logs and deletion lifecycle |
| SUP-01 | Dependency/supply chain | Dependencies declared in package manifest | Build and tests run in CI | Partial | Commit lockfile, pin/review dependencies, SCA, secret scanning, SBOM and container scanning |
| OPS-01 | Backups and recovery | Requirements documented | No restore evidence | Not implemented | Define RPO/RTO, encrypted backups, restore drills, deletion interaction and evidence |
| IR-01 | Incident response | Requirements in threat/trust standards | No tabletop evidence | Not implemented | Named owner, escalation, containment, notification decision tree and exercise |
| ASSUR-01 | Independent security review | No independent test report | Not performed | Not performed | Independent penetration test, remediation and retest |
| LEG-01 | Privacy/legal assessment | Requirements documented | No completed PIA or legal sign-off | Not performed | Qualified Australian privacy/legal review; notices, contracts, processor and cross-border register |

## Evidence references

- CI run #1046 (privacy subject-isolation milestone): https://github.com/luxhustle01-ux/Profitpilot/actions/runs/44002838128
- CI run #1058 (fail-closed privacy fulfilment and current buyer-pack commit): https://github.com/luxhustle01-ux/Profitpilot/actions/runs/44004207499
- Threat model: [THREAT_MODEL.md](THREAT_MODEL.md)
- Trust/security/privacy standard: [TRUST_SECURITY_PRIVACY_STANDARD.md](TRUST_SECURITY_PRIVACY_STANDARD.md)
- Privacy engineering baseline: [PRIVACY_ENGINEERING_BASELINE.md](PRIVACY_ENGINEERING_BASELINE.md)
- Preliminary privacy data inventory: [PRIVACY_DATA_INVENTORY.md](PRIVACY_DATA_INVENTORY.md)
- Project status and release boundary: [PROJECT_STATUS.md](PROJECT_STATUS.md)

## Buyer interpretation

A control is not “production-ready” merely because code exists or a CI test passes. The evidence status must be upgraded only when the specific implementation, environment, operational process and independent review appropriate to that control are demonstrated. Do not market this matrix as certification or as a claim of full compliance.

# Three external security acceptance gates — closure register
18 November 2026. Status: first-party preparation only; no live-data or deployment permission.

| Gate | Verified first-party baseline | Latest additional implementation | External closure evidence |
|---|---|---|---|
| Penetration test | CI #1899 passed actual PostgreSQL valid-signature adversarial cases and all required checks | Independent engagement dossier, PT-01–PT-10 | Independent tester, actual test scope and report, remediation retest, no unresolved critical/high findings |
| Disaster recovery | CI #1899 encrypted synthetic database restore and security reconciliation passed | Actual confirmed payroll fixture retained through encrypted restore; private receipt and immutable evidence checked; backup and recovery duration measured in CI | Approved isolated production-like recovery target, authoritative offsite backup and external checkpoints, operator evidence, actual RTO/RPO and controlled recovery approval |
| Australian legal/privacy | First-party source review and PIA plus core supplement | Eight counsel decisions with explicit release consequences | Written qualified Australian counsel opinion on actual entity, product scope, processors, retention and draft published terms |

Exact latest CI still requires verification. Never treat a synthetic test or documentary review as the corresponding external acceptance. The production launch gate remains closed. Do not hire, purchase, deploy, contact a recipient, or disclose private material without separate owner authorization. No signed candidate provenance on this core development branch.

## Recovery exercise completion packet
Use the existing PRODUCTION_SECURITY_ACCEPTANCE and SECURITY_OPERATIONS_HANDOVER runbooks.
Record approved isolated target and source identity; tested signed candidate hash; archive hash and separately approved latest backup and audit checkpoint; independently controlled trust anchors; privacy and security inventory manifest identifiers; freeze and incident declaration timestamps; restore and reconciliation completion timestamps; latest acknowledged source record time; latest preserved target record time; observed data loss; measured RTO and RPO; verification of revocations, holds, disposal, confirmed financial records, TLS, scanner, identity provider, tenant fences, actual application flow and load; cleanup; named operator and reviewer; explicit release or continued isolation decision.
Reject on missing/incorrect evidence, incomplete inventory, unknown new authorization, resurrected data or privileges, unresolved integrity defect, unapproved configuration, or exceeded agreed objectives. Targets remain provisional 24-hour RPO and four-hour RTO until owner approval and actual measurement. CI durations are synthetic logical-backup timings, not production RTO/RPO.

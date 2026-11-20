# Quality, privacy, security and operations specification

Planning targets below are proposed engineering assumptions for buyer evaluation, not measured results or contractual promises.

## QO-01 — Security and privacy control model

Deny by default; verified OIDC subject, short token lifetime, issuer/audience/JWKS checks, PKCE and MFA/step-up for privileged actions. Tenant scoped object authorization at service and forced RLS layer. Runtime cannot read signing-key table or perform migration operations. Rotate/revoke credentials; separate environments; production requires keys in managed custody and tested emergency rotation. Compromised API/signing secret remains a critical threat. Separate customer job rights from tenant payroll/report data; no public data links. Support access requires reason, least scope, expiry, notification policy and audit.

Data classes: public product docs, internal operational metrics, confidential business/financial records, restricted personal/payroll/evidence, secrets/provider credentials. Document purpose, lawful authority, recipient, location, retention and deletion schedule before live data. No real customer data in repo, examples, tests or CI. Use minimum source fields, pseudonymise identifiers, suppress groups with fewer than three workers, no worker ranking. Restrict raw file access to authorised recovery/review path, log access. Retention duration and residency require owner/legal review; no unsupported legal claim. Legal holds are scoped, timed and reviewed; deletion workflow covers backups/replicas according to approved policy. Export includes authorised scope and safe CSV formula handling; never expose secrets or other participants' protected evidence.

Upload: allowlist type and encoding, bounded bytes and rows, digest over original bytes, quarantine, malware scanning, isolated parser, schema validation, receipt and no unverified promotion. Receipt currently verifies bytes, not malware scan or issuer. Reject archive expansion by default, unsafe filenames/URLs, malformed data. No active content execution. External AI receives only authorised minimised data, never autonomous authority or data retention assumption.

Audit: record actor, tenant, action, object, before/after version or safe digest, reason, correlation ID, UTC timestamp and outcome; no raw tokens, keys or unnecessary PII. Separate privileged audit read and write roles; tamper-evidence design and retention tested before production.

## QO-02 — Engineering targets and proof

| Attribute | Proposed target | Acceptance method |
|---|---|---|
| Core API latency | p95 <= 500 ms for representative indexed reads, excluding uploads and external calls, at 25 concurrent synthetic users | reproducible test with dataset, hardware, warmup and errors |
| Upload | current limit 512 KiB, 2,000 rows, 200 JSON rows/request; target p95 <= 5 s for max allowed valid CSV under same test profile | boundary, invalid input and concurrent replay tests |
| Availability | 99.5% monthly production target after ownership/hosting agreed | external monitoring, error budget; no current guarantee |
| Recovery | proposed RPO <= 24 h, RTO <= 4 h | encrypted backup and measured restore including access/audit reconciliation |
| Correctness | zero duplicate confirmed financial contributions; balanced allocation and ledger | concurrent transactional tests and reconciliation |
| Isolation | zero cross-tenant disclosures across test matrix | negative tests per endpoint/table/relationship, privilege and pool cleanup |
| Accessibility | WCAG 2.2 AA target | keyboard/screen reader, contrast, zoom and manual review |
| Reliability | bounded retry/backoff; no duplicate effects; explicit degraded states | fault injection, outbox retry/dead-letter and recovery |
| Audit | all defined consequential transitions produce audit event with reason/actor | transaction rollback and completeness tests |

No claim of meeting targets without retained test evidence. A buyer and operational owner must review workload, cost and SLOs.

## QO-03 — Operations, incident and deployment

Maintain dependency lockfile, pinned builds, SBOM, SAST/dependency/secret/container scanning and signed release provenance as targets. Deploy least-privilege service; TLS, private DB, encrypted storage and backup, separate environment credentials and feature flags. Migration owner executes reviewed plan, backup, compatible rollout, smoke test; rollback application if compatible or restore/correct schema explicitly. Check restore of data, identity, mappings, receipt hashes, audit and calculation reproducibility. Proposed backup restore drill before buyer operational handover and quarterly for a live system.

Monitor endpoint latency, errors, resource use, queue age, failed authentication, denied access, duplicate/conflict rates, provider reconciliation age and backup status without leaking PII. Support triage: critical security/financial integrity event immediately escalated to designated owner; suspend affected action, preserve evidence, rotate/revoke, contain, assess legal notification duties with counsel, recover and conduct post-incident review. Production support contact, on-call responsibility, notification requirements and operational costs are buyer decisions.

## QO-04 — Required external proof

Independent security assessment, representative authorised source sets, privacy/retention review, production identity/backup exercise, browser accessibility and load verification, provider/payment and Australian legal feasibility, and real customer acceptance remain external gates. Passing synthetic CI is not proof of those outcomes.

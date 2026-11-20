# Security and privacy acceptance register

Synthetic evidence only. No legal certification or production permission asserted.

| Control | Engineering evidence | Operational evidence required |
|---|---|---|
| Tenant and identity | Forced RLS, signed context, role/FK tests | Independent pentest and live IdP enrolment/revocation |
| Transport and secrets | HTTPS JWKS, verified DB TLS, mounted credentials, scanner isolation | HTTPS edge, key custody and rotation |
| Ingestion | Bounded parser, digest, signed CVD and freshness gate | Maintained full CVD set, real positive scan/performance, storage encryption |
| Supply chain | Lockfile, pinned base/actions, Grype/CodeQL gates, GCC analyzer, signed source | Update ownership, deployment-image attestation, licence review |
| Privacy requests | Scoped cursor access, independent review, restricted audit | Verified nonmember intake and complete cross-store search |
| Retention | Default hold and narrow disposal | Approved retention schedule, backup expiry, processor reconciliation |
| Recovery | Encrypted fixture backup, wrong-key rejection, restored hashes and RLS | Offsite storage, key custody and timed live restore |
| Incident response | Procedure below | Named accountable owner, tested contacts/tabletop |

## Data inventory and retention
Identity/membership: account administration, subject/role; no credentials in app DB. Import receipts/raw rows: purpose-bound reconciliation, minimise personal identifiers. Financial records: versioned evidence, lawful business purpose, preserve holds and reconciliation. Audit/cases: restricted evidence, opaque references. Backups: encryption, restricted keys, approved expiry and restoration/erasure reconciliation. Operational logs: error identifiers without bodies or credentials. For each store record accountable owner, purpose/authority, location, recipients, processors, approved retention, hold release and verified disposal before real data. No universal statutory duration assumed.

## Incident runbook
1. Restrict affected access, isolate service or suspend ingestion; preserve evidence under controlled custody.
2. Record time, scope, affected data categories and containment under opaque incident reference. No confidential payloads in public tickets.
3. Revoke/rotate credentials, verify role and session revocation, review receipts, audit and backups.
4. Engage authorised incident owner and qualified Australian privacy/legal reviewer to evaluate breach obligations, serious harm and notification requirements.
5. Remediate, independently retest, restore verified recovery material and obtain explicit reopening approval.

Independent security assessment, real IdP/TLS/storage/signature operation, complete cross-store privacy fulfilment, retention/processor register and qualified legal approval remain external blockers. G0–G6 unchanged.

## S9 verification scope
- Audit-event confidentiality: role- and actor-limited tenant audit SELECT, with requester access to own privacy-case reviews and tenant-independent negative tests.
- Runtime audit integrity: event vocabulary/object-type/source-existence gate, cannot forge nonexistent source receipt; no independent tamper-resistant log certification.
- Source privacy: runtime raw-row SQL rejects bidi controls and unsupported keys; HTTP minimisation remains.
- Mounted secrets: protected owner-only file permissions; O_NOFOLLOW rejects symlink final components, requiring regular-file mounts. Operational secret manager compatibility must be tested by buyer.

## S10 additional review checks
- Privacy closure: requester may not authorise own review; opener and closer are distinct currently authorised owner/admin/reviewer roles (HTTP requires owner/admin). Immutable opener reference and dual-review regression test. No automatic erasure/export or externally verified legal outcome.
- Privacy queue: tenant-scoped 200-row cursor pagination for admin and requester, with requester ID in administrative response. A case listing is not an exhaustive enterprise data-subject response.

## S11 signed audit checkpoint acceptance
- Internal: Ed25519 signature verification, hash-chain consistency, missing/changed record detection, duplicate and cross-tenant input rejection, offline CLI tests, privileged-source row loader checks.
- Unverified external: independent witness/time anchoring, production audit-export role, signing-key custody, tamper-resistant remote storage, automatic monitoring and legal acceptance. The application must not label these as certified.

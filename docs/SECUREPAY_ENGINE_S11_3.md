# SecurePay S11.3 — two-key approval and signed offline recovery audit (synthetic only)

## Security objective

S11.2 cryptographically verified encrypted evidence from a restored database but accepted a self-reported operator and unsigned local audit files. S11.3 *fails closed before database access* unless it can validate two different pinned Ed25519 keys, an explicitly scoped, short-lived synthetic recovery approval and a working local audit signer whose public key is separately configured. No HTTP route, decrypted file export, funds control, production recovery or real identity verification is enabled.

## Two independently keyed approval roles

Configure owner-only mounted files, not committed source code or environment inline JSON:

- SECUREPAY_RECOVERY_APPROVERS_FILE: JSON format profitpilot.s11.3.approvers.v1 with **exactly** two entries: roles custodian and privacy-reviewer, distinct key IDs, different Ed25519 public keys in SPKI PEM form. This is an operator-pinned truststore, **not** a credential authority.
- SECUREPAY_RECOVERY_APPROVAL_FILE: JSON with keys request and signatures. The request is version profitpilot.s11.3.request.v1 and includes tenantId, operatorId, ticketRef, unique requestId, issuedAt, expiresAt, purpose, legalHoldState, retentionStatus and syntheticOnly. Signatures are exact base64 Ed25519 values, one per pinned role/key ID.
- SECUREPAY_RECOVERY_AUDIT_PRIVATE_KEY_FILE and SECUREPAY_RECOVERY_AUDIT_PUBLIC_KEY_FILE: distinct offline audit signing key and independently pinned verification key (owner-only regular PEM files). Do not reuse approval keys or real production keys.

The only accepted request purpose is synthetic-offline-integrity-rehearsal, retentionStatus must be **unverified_review_only**, syntheticOnly true, and legalHoldState must be **no_declared_hold**. Active or unknown declared holds **block** the rehearsal; this is only a *declared* hold state, not independently checked against a records-retention system. A request expires after at most one hour, cannot be used before its issuance (with 30-second clock-skew allowance), and binds exact tenant, reported operator, ticket and unique request UUID. Approver signatures prove possession of *different pinned private keys*, not two legally authorised people or actual retention compliance. A compromised host containing both keys invalidates the independence assumption.

On each attempt, a serialised, private audit chain is verified before the restored database is queried. A requestId previously recorded in that chain is refused. With a legitimate signature from each role, and a pristine chain, S11.2's restricted offline restored-DB decryption-verification executes; success remains metadata-only. A failed approved attempt is still recorded as refused. No money movement, live dispute decision or real customer evidence is permitted.

## Tamper-evident signed audit

Every attempted operation reaching the authorised audit context produces a local 0600, exclusive-create numbered JSON receipt: s11-3-000001.json, s11-3-000002.json, etc. Each holds only synthetic outcome, recorded UTC time, tenant, *operator-reported* actor/ticket, approved request SHA-256/key IDs if available, constant false independence/financial flags and verified encrypted digest summary on success. No encrypted evidence bytes, plaintext, keys or DB passwords are stored in receipts.

Each receipt's Ed25519 signature covers a domain-separated SHA-256 body containing the complete event and prior receipt digest. Before append, the entire existing audit chain is verified against a separately configured public key, with strict sequential filenames, order and bounds (maximum 256 events). Missing, altered or unsafely permissioned local files halt new attempts. The local lock file serialises same-directory attempts. A refusal before required signer or directory preflight cannot be signed and is not represented as an audit record; the operation still fails closed.

An operator can independently check the signed chain using:
node scripts/securepay-restore-rehearsal.mjs verify-audit PRIVATE_AUDIT_DIR AUDIT_PUBLIC_KEY_FILE PREVIOUSLY_RECORDED_HEAD_SHA256

The final expected head must be recorded **outside** the mutable audit folder after each operation, ideally under an independent evidence-preservation procedure. **Without an external head checkpoint, removing trailing files can go undetected**. Same-host audit signing is tamper-evident only relative to the pinned verifier and external checkpoint; it is NOT an independent timestamping or external witnessing service. A privileged operator can still change or delete files, keys, lock and surrounding storage. Never claim legally certified chain of custody.

## CI and test scope

The CI restore job creates disposable test-only custodian, privacy and audit Ed25519 key pairs. Two independently signed, distinct approvals allow one legitimate synthetic restored database verification and one deliberately failed wrong-key rehearsal. After S11.2's AEAD/MAC checks, CI validates their signed outcomes, independent public-key verification, prior-digest chain and external-supplied head. Unit tests cover missing/duplicate/forged signatures, key reuse, mismatched tenant/operator/ticket, expiry, active/unknown legal hold, tampering, replay and edited audit-chain refusal.

## Unresolved gates

Independent key custody and human identity verification; true operator role authority; legal-hold registry integration and retention periods; legal/privacy approval; external append-only witness and sealed timestamps; out-of-process signing/HSM; OS-level audit tamper resistance; recovery-key escrow and secure retirement; live backup service, customer authorization and disaster-recovery RTO/RPO evidence all remain unvalidated. Release is **synthetic-only draft** and must not be merged or deployed without independent security review. S11.3 is not a real customer evidence recovery permission system.

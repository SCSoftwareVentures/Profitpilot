# SecurePay S10 — application-layer encrypted synthetic evidence custody

S10 supersedes S9's plaintext write path. **S9 plaintext records are legacy and require separate privileged offline migration/deletion decisions**: migration 033 revokes runtime INSERT permission on S9's plaintext table and drops its write RLS policy. Existing S9 rows are NOT silently encrypted, deleted, reclassified as safe or removed from backups. GET shows `legacy_plaintext_requires_review` for such rows, and POST to that evidence returns 409. The S9 original-byte download prohibition remains.

## New encrypted-only receipt path

The existing `POST /v1/tenants/:tenantId/prototype/securepay-cases/:caseId/evidence/:evidenceId/custody-file` now **fails closed** if the scanner or either encryption/attestation key is missing. Same bounded raw-byte transport (512 KiB), SHA-256 and shallow MIME checks, authenticated role, and synthetic-only case scope apply. After the local scanner reports clean, the server encrypts the exact bytes with **AES-256-GCM** and a fresh random 96-bit nonce; canonical AAD binds tenant, case, evidence, operator, request, byte count, claimed digest, MIME, scanner result and key ID. PostgreSQL stores ciphertext, nonce, authentication tag, ciphertext SHA-256, original-byte SHA-256 (operator-received digest claim), key ID and metadata; the database verifies ciphertext digest/length, but cannot decrypt it or independently verify original-byte hash. The runtime database account has **no SELECT permission** for ciphertext, nonce or tag.

The application also HMAC-SHA256-signs a domain-separated record of its observed scanner verdict, timestamp and ciphertext digest with an independently supplied attestation key. The MAC is verified using constant-time comparison on GET, subject to active key availability. **This is not an independent scanner signature**: the same application holding the key can generate the MAC, and a compromised application or malicious scanner can falsely state clean. Do not infer content is virus-free. GET and exact idempotent replay return metadata only; no file-byte download/decryption API exists. Token and signature metadata cannot authorize payments, legal decisions or real-world claims.

## Secrets and rotation limitations

S10 requires `SECUREPAY_CUSTODY_ENCRYPTION_KEY` and `SECUREPAY_CUSTODY_ATTESTATION_KEY`, each **exactly 64 hex characters** and different, and a bounded explicit `SECUREPAY_CUSTODY_KEY_ID`. The existing `readSecret` mechanism supports `*_FILE` mounted secrets. No default keys, provider credentials, external KMS or paid infrastructure are introduced. Replays and reads with a different key ID fail closed or report that MAC validation is unavailable. A true multi-key recovery keyring, lifecycle/rotation policy, KMS/HSM and validated key destruction still need engineering and operational approval. Raw keys must never enter the database or backups.

## Remaining gaps — not production evidence

- Existing legacy plaintext bytes and associated backups need controlled migration/recovery and deletion plans; S10 does not claim historical re-encryption.
- Retention/legal hold, Australian privacy/legal sign-off, external custodian attestation, actual issuer-backed customer/tradesperson job permissions, and storage-object encryption independent of database administration are missing. `retention_policy_enforced=false` is permanently enforced by schema.
- Scanner runs in the server process. The HMAC records a server claim, not externally verifiable scanning; independent signing in a scanner trust domain remains needed.
- Database admins can read encrypted payload and metadata but cannot decrypt without the encryption key; a compromised server holding keys can recover synthetic contents. PostgreSQL backup encryption is separate from this per-record AEAD.
- Synthetic test keys and test-only scanner replacements are used for CI; **do not upload real evidence**. Protected deployments still disable the synthetic namespace. iPhone upload behavior has not been tested.

# SecurePay S11.1 — encrypted evidence-key rotation and recovery-only validation

**Scope:** synthetic encrypted custody evidence only. S10 created immutable receipts with key IDs; S11.1 makes historical receipt verification possible after an explicitly configured key rotation. It does **not** rewrite ciphertext, decrypt evidence through the API, recover lost keys, transfer funds, enable adjudication, or establish external custody.

## Rotation contract

A new, owner-only *mounted* `SECUREPAY_CUSTODY_KEYRING_FILE` holds UTF-8 JSON:

```json
{
  "activeKeyId": "custody-2026-02",
  "keys": [
    {
      "keyId": "custody-2026-01",
      "encryptionKey": "<64 lower-case hex characters, keep secret>",
      "attestationKey": "<different 64 lower-case hex characters, keep secret>",
      "status": "recovery-only"
    },
    {
      "keyId": "custody-2026-02",
      "encryptionKey": "<64 lower-case hex characters, keep secret>",
      "attestationKey": "<different 64 lower-case hex characters, keep secret>",
      "status": "active"
    }
  ]
}
```

The placeholders above are **not keys** and will fail validation. Create and manage real deployment secrets outside the source repository, deployment logs and ordinary database backups. Reuse of any encryption or attestation key across entries, duplicate key IDs, unknown fields, missing/ambiguous secret settings, an absent active key, a status mismatch, and inline JSON are rejected. Up to 16 entries are accepted within the existing 8 KiB mounted-secret limit. The existing secret-file reader rejects final-component symlinks and, for protected environments, rejects group/world-readable files. No KMS, HSM, automated key escrow or new paid infrastructure is configured.

1. Securely preserve **both** old keys *before* publishing a manifest with a distinct active key ID and new, independently generated keys. Validate authenticated retrieval of a historical receipt and its operator-recorded scan MAC.
2. Promote new key ID to `active`; mark all other entries `recovery-only`. New uploads encrypt and MAC with the active key. Historical immutable receipts retain their old `key_id`, nonce, tag and ciphertext; they are neither re-encrypted nor silently changed.
3. Historical GET and exact same-request POST replay look up the historical MAC key by receipt `key_id`. Missing historical keys cause GET to report `keyRecoveryRequired=true` and `scanRecordMacVerified=false`; exact replay returns 409, never a false verification. A present but incorrect historical MAC key also fails verification.
4. Do not remove old keys or destroy backups until an approved retention/legal-hold and offline export/recovery procedure has been independently tested. Recovery-only keys remain cryptographically able to decrypt existing records if used in an authorised offline recovery procedure; this prototype exposes **no** such recovery/download endpoint.

## Compatibility and limitations

Absent the mounted keyring, S10's explicit `SECUREPAY_CUSTODY_ENCRYPTION_KEY(_FILE)`, `SECUREPAY_CUSTODY_ATTESTATION_KEY(_FILE)` and `SECUREPAY_CUSTODY_KEY_ID` work as before for a single key. Mixing S10 key settings with a keyring is rejected. Existing S9 plaintext is still legacy and is not included in key rotation.

Rotation proves only the possibility of checking old operator-origin claims with retained keys. The HMAC is **not** an independent scanner signature. A compromised application with access to the mounted manifest can read all retained keys. Key-file deployment, rollback protection, escrow, operator dual control, secure destruction, offline recovery validation, backup expiry, real scanner-origin signatures, customer identity, external custody, Australian legal/privacy review and production disaster recovery remain unvalidated. No production deployment or processing of real customer evidence is approved.

## Verification

Node unit tests exercise old and new keys, AAD binding inherited from S10, tampering, absent keys, reused/duplicate keys, malformed manifests, symlinks and single-key compatibility. The authenticated PostgreSQL integration test exercises rotated historical GET, exact replay, missing-old-key status and fail-closed replay. GitHub CI result and independent security review must be recorded before any draft PR is considered mergeable.

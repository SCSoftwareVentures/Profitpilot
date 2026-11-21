# SecurePay S11.2 — offline synthetic encrypted-custody recovery rehearsal

## Delivered security boundary

S11.2 introduces an **operator-only offline restoration rehearsal** for synthetic SecurePay custody receipts. No production file-recovery or retrieval endpoint exists. The existing authenticated application API continues returning metadata only; it never exposes original bytes, nonce, authentication tag or ciphertext. No real-world dispute, payment, identity, retention or legal conclusion becomes authoritative.

The pure src/securepay-offline-recovery.js verifier accepts **privileged, restored PostgreSQL rows** and:

1. Requires a single expected tenant, valid receipt/evidence/actor UUIDs, a 1–512 KiB ciphertext, valid nonce/tag lengths, fixed AES-256-GCM and scanner-reported-clean status.
2. Rejects records whose corresponding case is not synthetic, funds moved, evidence externally verified, or whose database authority/retention/independence flags imply production trust.
3. Resolves the historical key by immutable receipt key_id, verifies the S10 **application-origin** scanner HMAC, re-derives the exact scoped AAD, authenticates/decrypts AES-256-GCM and independently compares original-byte SHA-256 and length.
4. Returns **only** minimal receipt digests and a deterministic aggregate digest for 1–64 records, sorted independently of database fetch order. No original content or key material is returned. Temporary plaintext Buffers are filled with zeros on exit, but JavaScript/runtime copies are not guaranteed to be fully erased from process memory.
5. Refuses missing/incorrect keys, corrupted ciphertext/tag/nonce, swapped tenant scope, inconsistent metadata, mixed/non-synthetic scope and duplicate receipts.

## Standalone restored-DB rehearsal

Command: node scripts/securepay-restore-rehearsal.mjs rehearse TENANT_UUID RESTORED_DB_URL_FILE PRIVATE_AUDIT_DIR OPERATOR_UUID TICKET_REF

The operator must explicitly set PROFITPILOT_PROFILE=prototype and SECUREPAY_OFFLINE_RECOVERY_MODE=synthetic-rehearsal. NODE_ENV=production is refused. The keyring must be supplied through an owner-only SECUREPAY_CUSTODY_KEYRING_FILE, **not** inline JSON or the S10 single active-key compatibility mode. The database URL must be an owner-only regular secret file, without URL query/fragment, pointing to a loopback host and a database whose name ends in _restore; TLS is enforced except for explicit local tests. PRIVATE_AUDIT_DIR must preexist as an owner-only regular directory (no final-component symlink).

The script uses a repeatable-read, **read-only** PostgreSQL transaction and selects a maximum of 65 rows for the tenant, refusing empty or greater-than-64-result sets. Before success it verifies **actual ciphertext from the restored database**, not only backup archive integrity and metadata counts. It creates a new owner-only, exclusive audit JSON file per validly initiated attempt, including refusals when execution reaches the recovery stage. The audit identifies an *operator-reported* actor/ticket, a per-attempt UUID, a synthetic-only outcome, and an aggregate SHA-256, never decrypted content, secrets or DB passwords. Failing to create an audit receipt causes the operation to fail. It does **not** attest the operator's identity independently, prevent a privileged OS user from altering the audit directory, or supply externally anchored or signed audit receipts. It is not legal dual-control approval.

## CI recovery proof

The existing CI first creates an encrypted PostgreSQL backup, confirms that the wrong archive passphrase fails, restores to a separate database, compares inventory checksums and checks tenant RLS. S11.2 then:

- Supplies test-only mounted AES/MAC keys matching the encrypted synthetic receipts created by the authenticated S10 integration fixture.
- Queries the **restored** tenant's encrypted evidence through the offline verifier and proves that its MAC, AEAD authentication tag and original-byte hash can be verified.
- Substitutes a different random keyring to require refusal; confirms one private success audit and one private failure audit.
- Leaves the original database untouched, does not export decrypted evidence, and removes ephemeral keys, restored database and audit files at CI cleanup.

Unit tests additionally cover cross-tenant, non-synthetic, wrong-key, metadata/byte tampering, duplicate, empty, oversize and unsafe audit directory conditions.

## Unresolved before any real recovery

This is a **synthetic feasibility rehearsal**, not operational disaster recovery certification. No key escrow, external KMS/HSM, real customer/party/source authenticity, independent scanner signature, access-controlled production recovery service, legal hold/retention workflow, backup erasure, independent audit witness, dual-person authorisation or actual user-facing plaintext retrieval is established. A database named _restore on loopback is a useful safety fence, not a cryptographic guarantee that the database was restored from a trusted backup. The reporting identity/ticket is self-asserted. Real evidence remains prohibited, and human security/legal review remains mandatory before merging/deploying protected functionality.

S11.1's old-key retrieval and S10's immutable source records remain unchanged.

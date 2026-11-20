# S11 — Signed audit checkpoint operator guide

## Security purpose

Create a **tenant-specific Ed25519-signed hash-chain checkpoint** over public.audit_events in a single read-only repeatable-read database transaction. The checkpoint contains event UUIDs, timestamps and cryptographic hashes, not raw reason or metadata contents. A separate public key can validate the signature offline. A database comparison recomputes the sealed historical prefix.

**Limits:** a signature alone does not prove the initial database was honest, that the signer was authorised, or that an independent witness held the checkpoint. A privileged attacker may rewrite a database and generate a new checkpoint unless the earlier signed file and trusted public key were preserved externally. This feature supplies verification mechanics; it does not create an external witness or immutable storage.

## Buyer/operator procedure

1. Arrange an audited, restricted, read-only audit-export database role capable of selecting the intended tenant records. Do not grant blanket BYPASSRLS casually; production role provisioning requires independent review.
2. Generate an Ed25519 keypair outside the repository. Protect the private key and database URL in separate regular files with owner-only filesystem permissions. Verify the public-key fingerprint through a separate trusted channel.
3. With the project source and npm dependencies installed, invoke the following commands in the operational environment:

```sh
node scripts/audit-checkpoint.mjs seal TENANT_UUID /secure/audit-db.url /secure/audit-signing.pem /secure/checkpoint.json
node scripts/audit-checkpoint.mjs verify /secure/checkpoint.json /secure/audit-signing.pub
node scripts/audit-checkpoint.mjs compare /secure/checkpoint.json /secure/audit-signing.pub /secure/audit-db.url
```

4. Preserve the signed checkpoint and authenticated public-key fingerprint in externally controlled, independent write-once or witnessed custody. For subsequent seals, pass the earlier checkpoint as the optional fifth argument; the tool **must verify that predecessor's Ed25519 signature under the current signer and compare all historical event hashes against the current tenant snapshot** before creating a successor. It rejects changed, missing or backdated earlier events, tenant mismatches, old keys and reversed capture times. Older signed artifacts still require independent custody.
5. Repeat according to an approved operational schedule. Check prior checkpoint prefixes against current data, record exceptions, handle signer key rotation and preserve chain-of-custody evidence.

## Important unresolved controls

- Exports fail closed above **10,000 audit events or 16 MiB** of canonical source fields. An approved segmented protocol is needed for larger tenants.
- Previous checkpoints are not automatically transmitted to any external service. The earlier file's digest is only a cryptographic link, not independent proof of custody.
- The compare operation validates the sealed historical prefix, not events occurring later; ongoing monitoring, actual evidence storage and time anchoring are not implemented.
- Metadata text is taken from PostgreSQL JSONB rendering; a database major-version change may require a controlled canonicalisation review.
- Remote database connections use verified TLS; local plaintext is enabled only for NODE_ENV=test loopback. No real credentials or private keys are committed.
- Keep checkpoint artifacts and subject identifiers out of public source-control and support tickets.
- The project does not claim full independent audit logging, qualified penetration testing, legal privacy compliance or production readiness.

## S12 strengthened continuity rules
Successor `seal` verifies the predecessor signature under the currently configured key, its tenant, the entire old audit prefix and capture-time ordering before it writes a new file. The `previousCheckpointDigest` now hashes the validated JSON bundle (not arbitrary unverified file bytes). Public-key rotation is deliberately NOT supported automatically: a new key or key compromise needs a documented dual-signature migration and independent witness. An initial checkpoint remains a self-signed statement until externally witnessed. `verify` only checks the single file: to validate continuity, inspect the predecessor and compare to the database as described above. Empty historical checkpoints cannot independently demonstrate the database's state at a past time after additional records appear. This is a trust limitation, not a guarantee.

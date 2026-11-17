# Security operations and recovery — deployment handover

Status: implementation candidate; synthetic CI evidence is not production assurance. No live infrastructure, real customer data, secret values or backup archives belong in GitHub.

## Tenant signing keys

Use a trusted managed secret store, administrator-only TLS connection and unique random 32-byte hexadecimal material. Do not use shell history or source control to store keys. Inject ROTATION_ADMIN_DATABASE_URL, ROTATION_DATABASE_CA and ROTATION_NEW_KEY_SECRET using the deployment environment's secret mechanism.

1. Stage a unique new key ID: `node scripts/rotate-tenant-key.js stage NEW_ID`.
2. Change TENANT_CONTEXT_HMAC_KEY_ID and TENANT_CONTEXT_HMAC_SECRET on all API replicas together using a controlled rolling deployment. Verify a signed synthetic tenant request on every replica; do not rely on /health alone.
3. Leave the old key active during transition. After every replica has switched and at least 60 seconds have elapsed, inject ROTATION_CONFIRM_REPLICAS_SWITCHED=yes and the replacement material. Revoke the old key: `node scripts/rotate-tenant-key.js revoke OLD_ID NEW_ID`.
4. Verify old-key rejection, new-key success, audit events and replica health. Never reactivate a revoked key or reuse material. A compromised key requires emergency revocation and incident handling even if this briefly interrupts service.
5. Key lifecycle records live in `private.tenant_key_rotation_events`. They contain IDs, action, database actor and timestamp, not key values. Export restricted audit evidence to the approved operational log store; privileged database administrators remain trusted.

The rotation command cannot verify that every external replica has switched. The operator must explicitly attest to that step before revocation. Runtime role has no rotation rights. The independent rate-limit HMAC secret must be shared across replicas; coordinate its rotation and expect existing short-lived counters to reset. Identity-provider signing keys, database passwords and backup encryption keys use separate rotation procedures and independent secrets.

## Encrypted logical backup

Use an isolated restricted backup runner with PostgreSQL client tools compatible with the database version. The API image does not need backup/admin credentials. Inject BACKUP_DATABASE_URL, BACKUP_DATABASE_CA_FILE and a distinct 32-byte hex BACKUP_ENCRYPTION_KEY from the managed secret store. Keep an approved offsite recovery copy of historical encryption keys separately from the backups.

- Create encrypted archive: `node scripts/secure-backup.js backup /approved/private/path/unique-name.enc`.
- AES-256-GCM authenticates archive contents and header; each archive has a fresh 96-bit random nonce. The tool streams pg_dump over verified TLS and publishes a private file only when the dump and encryption succeed. Existing paths are not overwritten.
- Decrypt into a new restricted temporary directory on an encrypted recovery volume: `node scripts/secure-backup.js decrypt archive.enc recovered.dump`. Do not restore on authentication failure. Never restore over a live database.
- Provision an isolated recovery PostgreSQL instance with the required roles and extensions; restore with pg_restore --exit-on-error --single-transaction; run catalogue, runtime-isolation and representative signed API checks. Reconcile data and validate account/key revocations against authoritative records external to the snapshot before admitting traffic. A database dump does not capture cluster-global roles, provider infrastructure, external objects, or point-in-time recovery history.
- Destroy temporary decrypted copies through the approved retention process. Do not upload archives, dumps or secrets to a public repository, public CI artifacts or chat.

Proposed starting objectives (not yet approved or measured): RPO 24h and RTO 4h. Schedule daily encrypted backups with alerts for missing or failed runs; retain daily archives 30 days pending legal/contractual retention review. Store independent offsite copies with restricted modification/deletion permissions. Test a complete recovery at least quarterly and after significant migration changes. Adjust scheduling, retention and PITR after measured data volumes and owner acceptance.

The repository includes a synthetic CI encrypted restore drill; it does not create or schedule any real production backup. Production backup scheduling, provider-side immutability, offsite storage, retention automation, recovery timing and operator alerting require the selected hosting environment. Treat them as release blockers until demonstrated.

## Security monitoring

Production emits one fixed-schema aggregate `api_security_interval` event per minute per API process: request volume, successes, auth/role denials, rate limits, client/server errors, unavailability, aborted and slow requests. No request URLs, headers, IP addresses, identities, body fields or user-controlled labels are emitted. Other system events report shared-counter cleanup and idle database connection failures without exception detail.

Configure a restricted log destination and external uptime checks after choosing hosting. Suggested initial alerts: sustained 503 or 5xx bursts, repeated rate-limit-store failures, absence of expected health/backup signals, unusual 401/403/429 spikes relative to baseline, failed key rotation, and missed recovery drill. Aggregate across replicas, deduplicate alerts and test delivery with a synthetic event. Log retention and incident-response access require owner approval. Aggregate counters reset on process restart and do not replace durable financial/security audit records or provider monitoring.

## Release evidence required

Before any real data: successful CI on exact integrated head; independent security review and penetration test; reviewed identity-provider/MFA/recovery setup; production TLS and network boundaries; working provider-managed secret injection and least-privilege administrative access; sampled encrypted offsite recovery with RPO/RTO evidence; tested alert delivery; approved data handling/deletion and retention; operational incident owner and response exercise. No automatic merge/deployment is authorized by this document.

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


## Implementation additions — 18 November 2026

These controls are on the unmerged security candidate. Confirm exact-head CI before relying on them.

### Identity and compromised sessions

The configured identity provider must issue a cryptographically verified access token with stable subject, stable session ID (`sid`), integer `auth_time`, issued-at and expiry. Refreshing a token must not replace the original authentication time or session ID. Sensitive upload, approval and export operations additionally require explicit provider-attested MFA within five minutes. Provider-specific claims and account recovery are not yet live-verified.

An approved identity operator can provision an externally verified subject and manage membership via the restricted identity administration functions. No self-registration or self-promotion route exists. Record an opaque approval reference for every action. Never grant the operator role to the API user. Membership changes via the operator procedure require new authentication; the last active owner cannot be removed or downgraded. Emergency disabling of a compromised final owner still requires a supervised recovery procedure. The administrator-only revocation function supports per-session digest revocation, global logout and account disable/enable; revoke globally when uncertain which session was compromised. Revocation affects future authenticated requests, not necessarily a transaction already executing.

Reconcile post-snapshot revocations, account disables, membership changes and signing-key changes from an authoritative external record before restoring traffic. The monotonic replay function does not recreate membership grants or re-enable users. Never assume restoring a backup automatically restores current authorizations.

### File processing

The non-production-only invoice CSV workflow stores AES-GCM ciphertext, verifies the registered checksum, requires a fresh-signature scan and strict bounded content validation, and records a canonical-row manifest digest. An active owner/admin with recent MFA must separately approve processing. The isolated worker reopens and rescans the bytes, verifies the same digest and atomically persists only those rows into financial review, never automatically accepting them. A compromised identity's global revocation, legal hold, expired lease, incorrect manifest or changed source hash blocks promotion. There is no file-download route. Temporary ciphertext expiry is opt-in and respects holds. Disposed markers and source/audit records remain; PostgreSQL logical deletion is not guaranteed physical erasure from existing snapshots or storage.

Before enabling real uploads: provision the restricted scanner role separately, protect the Unix socket and encryption keys, confirm current signature updates, run `CLAMAV_SOCKET_PATH=/approved/socket node scripts/check-live-scanner.js` against an actual isolated ClamAV daemon, and exercise outage, infection, quota, legal-hold and recovery scenarios. Set a reviewed retention policy, confirm appropriate file/row limits and monitor worker scheduling. The harness does not itself provision or run an antivirus service; current production flags still deny upload and worker activation.

### Audit and network boundary

Financial audit events are database-generated and chained by tenant. The application cannot directly insert, modify or delete them. Administrator-only verification detects event mutation, missing/excess events and broken chain continuity. This is tamper-evident against ordinary unauthorized mutations, not tamper-proof against a privileged operator rewriting the chain and checkpoints. Export signed head/count checkpoints to an independently controlled immutable destination and prove verification during recovery. Identity administration and revocation logs are append-only under normal permissions.

Keep direct connections untrusted by default. Configure `TRUSTED_PROXY_IPS` only for exact addresses of the immediate trusted reverse proxy. Ensure the proxy appends the actual peer IP or replaces client-supplied forwarding headers; network firewall must prevent direct bypass of the edge. Verify proxy address changes before redeployment. Browser origins must be exact HTTPS origins in production. The API uses bounded header/request/connection settings; baseline values are engineering defaults, not load-tested capacity limits. An edge network protection layer and deployment-specific stress testing are still required.

### Build integrity

CI checkout and setup actions are pinned to retrieved commit SHAs; checkout credentials are not persisted. npm dependency scripts are disabled, direct versions are exact and lockfile registry/integrity checks must pass. A tracked-source preflight screens common credential shapes and restricted backup/key filenames without printing matching values. This is not a history-wide scanner, DAST, SCA beyond npm audit, comprehensive secret scanner, or container vulnerability assessment. Review and pin production image digests through approved registry evidence; add independently maintained vulnerability scanning, scheduled dependency review and remediation before release.

### Independent checkpoint and alert operation

Use a separately provisioned `profitpilot_audit_reader` login with verified TLS, and an independently controlled Ed25519 signing key. The reader can retrieve only verified chain head/count metadata and compare historical prefixes, not event contents. Run `node scripts/audit-checkpoint.js sign /approved/new-checkpoint.json` from the isolated audit environment. Store the output in separately controlled immutable retention storage; never store the signing key or checkpoints exclusively alongside the database. Before any recovery, retrieve the latest trusted checkpoint and run `node scripts/audit-checkpoint.js verify /approved/trusted-checkpoint.json` with the pinned public key. Reject missing, stale, incomplete or mismatched checkpoints; selection of the latest complete trusted checkpoint is an external operational obligation. Chain verification covers public financial audit events, not every administrative or worker log. The full-chain read is bounded by a separate 30-second audit connection timeout, and may require paginated verification before scaling to large tenants.

The API emits fixed-schema aggregate interval metrics and threshold-driven active/cleared alerts for sustained authorization denials, rate limiting, service errors, slow requests and aborts. No customer values or credentials are included. The two-interval thresholds are initial engineering defaults; alerts are per replica, not cross-replica intrusion classification. Production must collect the logs, protect them from alteration, alert on missing telemetry, tune thresholds, and route urgent alerts to an approved operator. No external notification delivery is provisioned.

### Quarantine expiry after recovery

Preserve authoritative, independently controlled expiry receipts (tenant, batch, source checksum and disposal timestamp) alongside the other post-snapshot recovery evidence. Reconcile holds and stop scanners before replay. The administrator-only `private.replay_quarantine_expiry` clears restored transient ciphertext, preserves the accounting batch and adds an expiry event. Receipt mismatch or active hold fails closed; already reconciled matching receipts are idempotent. Do not reopen service until reconciliation is complete. The procedure does not erase older backup copies or authenticate an externally supplied receipt by itself; trusted receipt custody, backup expiry and operational signoff remain required.

### Production startup readiness

Production now refuses to listen until the actual database login, TLS connection,
restricted role, forced tenant RLS, restricted financial reads, audit permissions,
private security state and configured active signing key pass readiness checks.
The key proof uses a domain-separated HMAC, not disclosure of key material.
The health endpoint rechecks these minimum invariants. It is not a substitute
for the full CI catalog audit or operational monitoring. Use verified CA
certificates, independently generated strong keys and runtime-only credentials.
Reject TLS disable overrides, unsafe database connection overrides and attempts
to enable the unapproved production quarantine workflow.

Select `AUTH_ACCESS_TOKEN_PROFILE=rfc9068` for a verified access-token type,
or `token_use_access` for a provider with a verified access-token claim.
Configure `AUTH_MFA_ACR` to the exact independently reviewed issuer assurance
value. Production step-up requires both the explicit MFA AMR and matching ACR.
Verify the provider's actual claim mapping, audience and session revocation in
an approved staging environment. Do not deploy merely because the synthetic
CI smoke test passes. The diversity check on secrets rejects obvious weak
values but does not prove randomness; generate secrets with a CSPRNG.

### Supply-chain security gate

The API and local/CI PostgreSQL images are now pinned to the digests observed
in successful CI #1589. The Docker build context is allowlisted, with credential,
backup and log files excluded. npm lock preflight binds package identities and
versions to exact registry tarballs, checks root declarations and rejects
install-script metadata. The container job checks non-root execution and
installed dependencies, generates a CycloneDX npm SBOM and attempts independent
Trivy scans of both images. HIGH and CRITICAL findings, scanner failures or
unavailable vulnerability data block the security CI gate; there are no
automatic CVE suppressions or unfixed-vulnerability exceptions.

The scanner is versioned and its downloaded archive checked against the
publisher's checksum manifest. This is integrity checking, not an independently
verified release signature or a separately pinned scanner binary checksum.
No real data, deployment credentials or production images are supplied to the
scanner. The SBOM is generated in ephemeral CI (not yet retained as a release
artifact). Image pinning prevents silent tag drift but does not keep images
patched automatically. Review vulnerability reports, inventory and upstream
security updates regularly; explicitly replace digests and rerun all gates.
A production registry, signed release provenance, retention and independent
penetration testing remain deployment acceptance work.

### Container vulnerability remediation

CI #1605 reported 11 HIGH findings in npm's global build-tool dependencies.
CI #1613 verified zero HIGH/CRITICAL findings in the minimized API image, but
reported 25 HIGH and one CRITICAL Go standard-library finding in PostgreSQL's
bundled gosu binary. No suppressions or scanner exclusions were added.

The reviewed remediation retains the digest-pinned upstream PostgreSQL base
and replaces the obsolete runtime utility with Alpine's signed su-exec
package, pinned to 0.3-r0. PostgreSQL's upstream initialization and entrypoint
are unchanged. The local bootstrap, CI database integration and vulnerability
scan all use this custom Dockerfile. CI verifies the privilege drop (effective
UID/GID, no root supplementary group, actual PostgreSQL PID 1 ownership,
including after TLS restart), migrations, recovery and TLS. Do not use the
old unmodified database image. Do not report remediation as verified until
the complete gate for the resulting commit passes. The replacement removes
the binary from the final runtime filesystem; the inherited base layers remain.
Package installation uses the distribution's signed APK metadata; the final
built image still requires an immutable release digest and independent review.

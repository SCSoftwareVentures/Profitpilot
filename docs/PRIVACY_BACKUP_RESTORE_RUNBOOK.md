# Privacy-aware backup and recovery runbook (pre-production)
Status: operator tooling implemented; production deployment and storage configuration outstanding.

## Retention and custody
Record an authorized retention policy for each backup class, with owner, purpose, maximum age, encryption/key custody, regions, processors, expiry verification and legal-hold exceptions; do not guess statutory time limits. Maintain a complete inventory including snapshots, PITR/WAL, exports, replicas, object storage and vendor copies. Keep the checkpoint signing key and latest authoritative checkpoint digest in independently controlled storage, separate from all database backups. Treat checkpoint identifiers as confidential. Restrict capture and restore to authorized operators. Never place real credentials, manifests or backup copies in GitHub.

The inventory check is advisory and read-only. Input is a JSON array of records with id, createdAt, expiresAt, encrypted, legalHold, and holdReference when held. Set PRIVACY_BACKUP_MAX_DAYS to the approved maximum, then run node scripts/privacy-restore-checkpoint.js inventory inventory.json. Nonzero exit requires review; do not destroy held records or blindly delete expired backups. Confirm provider-side immutable expiry and retain separate evidence of actual destruction.

## Checkpoint capture
Use a restricted administrative database connection over verified TLS via PRIVACY_ADMIN_DATABASE_URL, an independently managed 32-byte random hex PRIVACY_CHECKPOINT_KEY, and a stable PRIVACY_DEPLOYMENT_ID. Run node scripts/privacy-restore-checkpoint.js capture checkpoint.json. The command refuses overwrite and writes a private file. Record its returned digest independently with the capture event. Capture after each successful erasure/closure, and immediately before controlled cutover while privacy writes are frozen. In production automate independently durable checkpoint capture and monitor failures; this repository does not provide that infrastructure.

## Restore and cutover
1. Keep the restored system disconnected from public traffic, background jobs, email and integrations. Revoke app access until the following checks pass.
2. Restore to a separate isolated environment, apply current migrations, and obtain the most recent authoritative checkpoint and digest from independent custody. Never trust a checkpoint bundled with the old backup. Never re-sign restored state as current truth.
3. Set PRIVACY_EXPECTED_CHECKPOINT_SHA256 from independent custody, configure the verified TLS connection to the isolated target, and run node scripts/privacy-restore-checkpoint.js verify checkpoint.json. It fails on stale, missing, tampered, wrong-deployment or inconsistent evidence. Default freshness is 24h; a genuine disaster with older evidence requires reviewed recovery from a trusted source, not bypass.
4. A failed verification means no cutover. Reconcile missing closure/redaction actions from authoritative records under approved controls, verify database and provider access revocation, then rerun. Never infer or recreate deleted values. Validate audit chain, integrations, storage copies and provider deletion separately.
5. Require authorized sign-off, backup expiry review and evidence retention before admitting traffic. Run a real isolated recovery drill before first production use.

The gate detects missing markers covered by the independent checkpoint; it cannot detect actions never recorded externally or recover lost data. It does not automatically enforce network isolation, delete third-party backups, or assure legal compliance. No live backup or retention service is configured.

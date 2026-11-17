# Tenant-context signing key rotation and recovery

Status: development control; operational deployment and independent key custody unverified.

## Routine rotation
1. An authorised infrastructure operator creates fresh cryptographically random 32-byte signing material in a secret manager, using a new, never-reused identifier. Do not paste material in repository files, logs, support tickets or command arguments.
2. Use an authenticated, encrypted administrative database connection, not the application role. Provision the new key through a reviewed parameterized administrative operation; migration 034 derives its fingerprint and registration time. The key registry is inaccessible to the runtime role.
3. Deploy the new identifier and corresponding secret together to every API instance through secret injection. During the short overlap, both active keys are valid.
4. Verify authentication, tenant isolation, sensitive MFA reads and audit writes with synthetic records. Confirm the fleet has switched before revoking the old key.
5. Set the old key's active state to false through the authorised administrative operation. The database removes the live secret value, preserves its fingerprint and key ID, and prevents reactivation/reuse. A successful transaction does not guarantee forensic erasure from database pages, WAL or historical backups.
6. Remove the retired secret from deployment configuration, rotate affected operational credentials if needed, and record completion outside the affected application using a protected audit system.

## Emergency compromise / recovery
Immediately disable the compromised key and isolate affected service instances; an outage is preferable to allowing stale credentials. Provision a new key using independently protected random material and validate the fleet before reopening. A previously revoked identifier or material must never be reactivated. Restoring old databases may restore historical active keys: keep restored systems isolated, compare signing-key state with the independent incident/rotation record, retire all historical signing material, provision fresh keys and verify current security/retention checkpoints before serving traffic. Backups remain encrypted and subject to retention, access and deletion controls.

A privileged database administrator or compromised infrastructure can bypass database guards. Managed secret storage, protected external key inventory, independent recovery drills, physical data destruction and live incident exercises remain pre-production requirements.

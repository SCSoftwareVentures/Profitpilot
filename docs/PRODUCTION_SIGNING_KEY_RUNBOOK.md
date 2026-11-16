# Production signing-key operations runbook

**Status:** required operational control; not evidence of production key custody.

## Key design
- The tenant-context HMAC key is a high-impact production secret. Anyone who obtains it and can reach the database can forge tenant context.
- Never store it in the repository, image, client bundle, database table readable by the runtime role, ticket, chat transcript or ordinary application logs.
- Use a managed secret manager/KMS-backed secret delivery mechanism with access restricted to the API workload identity and designated security operators.
- Use a unique random key of at least 32 bytes per environment. Keep development, test, staging and production keys separate.
- Set both `TENANT_CONTEXT_HMAC_SECRET` and `TENANT_CONTEXT_HMAC_KEY_ID`; the key ID must identify the matching active database key record.

## Planned rotation (overlap and cutover)
1. Create a new cryptographically random key and unique key ID in the secret manager.
2. Insert the new key into `private.tenant_context_keys` as active using a controlled migration/admin session. Never expose the key to the runtime role.
3. Deploy the API with the new secret and key ID; verify authenticated tenant reads and writes, error rates and audit telemetry.
4. Keep the old key active only for the documented overlap window needed by rolling instances. Ensure every API instance has switched.
5. Mark the old database key inactive. Verify old-key signed contexts fail closed and new-key contexts still work.
6. Record operator, approvals, timestamps, key IDs and verification evidence. Do not record secret material.

## Emergency revocation
1. Declare a security incident and restrict access to the affected API workload/secret.
2. Disable the suspected key in `private.tenant_context_keys` immediately using a privileged database session.
3. Remove the secret from the secret manager version used by the workload; rotate deployment credentials if compromise scope is uncertain.
4. Issue a fresh key, provision it through the normal controlled process, and deploy it only after confirming the compromise path is contained.
5. Confirm the revoked key fails, the replacement succeeds, tenant membership is rechecked, and no transaction context survives connection reuse.
6. Preserve relevant logs and audit records; assess unauthorised access and notification obligations with incident counsel.

## Recovery and failure behaviour
- If the active key is lost, do not recover it from source control, logs or database dumps. Generate and provision a replacement key.
- If no valid key is available, tenant-scoped requests must fail closed. Do not bypass RLS or temporarily accept raw tenant GUC values to restore service.
- Restore the database key registry and secret-manager version from separately controlled backups/versions; reconcile active key IDs before reopening traffic.
- Test recovery in a non-production environment at least annually and after material changes.

## Required production evidence
- Named service owner and two-person approval for emergency revocation.
- Secret manager/KMS product, workload identity, access policy and audit-log configuration recorded in deployment runbook.
- Rotation and emergency revocation exercise results.
- Recovery exercise proving fail-closed behaviour and successful key replacement.
- Monitoring for key validation failures, unusual authorization denials and privileged key-registry changes.

This runbook is a procedure template. It does not configure a secret manager, provision a production key, or prove that a rotation/recovery exercise has occurred.

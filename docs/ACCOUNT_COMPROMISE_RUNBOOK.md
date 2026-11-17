# Account compromise response and recovery (pre-production)

## Containment
- On a credible compromise report, confirm the affected immutable local user UUID using a trusted administrative inventory. Never rely on an email or reported token alone.
- A dedicated named SQL login with only the containment group, separately protected by operator MFA and approved network access, calls private.contain_compromised_account(uuid, evidence_sha256). Do not grant the group to the application or recovery operator. The operation disables global local access, revokes sessions, advances the authentication cutoff and records an immutable incident. This is not an external provider block and does not cancel already-running transactions.
- Isolate affected integrations, rotate exposed credentials, and contact the identity provider through authorised personnel. Preserve evidence outside application source control. Capture the latest independent signed checkpoint immediately; alert if unavailable. Notify appropriate people using approved incident and legal procedures.

## Independent recovery
- A different named SQL login in the recovery group reviews trusted out-of-band proof of control, provider-side credential and factor recovery, all refresh/device-session revocation, and evidence of remediation. Do not use a compromised email or phone as sole proof. Never collect passwords, MFA secrets or bearer tokens into the case file.
- Only after those steps, call private.recover_contained_account(incident_uuid, identity_evidence_sha256, provider_revocation_evidence_sha256). The digests must represent separate preserved evidence artifacts, not arbitrary placeholders. The procedure checks independent SQL identity and incident state, not the authenticity or completeness of external evidence. It cannot reopen a closed account, change the provider subject or grant membership. Recovery advances the local cutoff again; require a new provider authentication event after that second.
- Capture an independent checkpoint, validate account and tenant access, verify provider-side session status and audit relevant changes. Keep the case open until containment, recovery and notification decisions are independently reviewed.

## Release conditions
Both operator groups are NOLOGIN and empty by default. Provision individual authenticated operators under separate controlled identity and network policies; never share credentials or grant both groups to one operator. Database superusers are an exceptional privileged boundary and not ordinary responders. No live identity provider, operator MFA, outreach, monitoring, evidence store or incident exercise has been configured. Do not use the synthetic CI fixture identities or evidence hashes in production.

# ProfitPilot — operational security acceptance and release blockers
Date: 18 November 2026. Status: first-party evidence and operational readiness
plan, not independent certification or approval to operate with live data.
The most recent verified baseline before these changes is CI #1784, including
signed source and scanned image manifest provenance. Verify the exact new CI
run and signed candidate before relying on any new implementation.

## 1. Dashboard interface

The deployable dashboard is a standalone browser UI served by
`scripts/security-dashboard.js`, with read-only security reader access and a
15-second refresh. Configure an approved operator environment with
`SECURITY_READER_DATABASE_URL`, `SECURITY_READER_DATABASE_CA`,
`SECURITY_DASHBOARD_PORT` (default 8443), a random 32-byte hexadecimal
`SECURITY_DASHBOARD_TOKEN`, and paths
`SECURITY_DASHBOARD_TLS_KEY_FILE`, `SECURITY_DASHBOARD_TLS_CERT_FILE`.
Start `node scripts/security-dashboard.js`; access only through an approved
private operator path to HTTPS localhost. Never expose port publicly or map
the API role into the dashboard. The loopback boundary and token are an
additional control, not an individual identity provider or production SSO.
Approved deployment must establish identity-bound operator MFA,
network access, credential rotation and Safari/mobile acceptance. No
credentials or real snapshots are published or stored in browser storage.
Failure or drift clears the data view. No action buttons for lockdown or release.

## 2. Signed external notification delivery

The standalone one-shot `scripts/security-alert-delivery.js` polls the
restricted snapshot and observes availability, catalogue drift, tenant
containment and fixed provisional actor/queue thresholds. Schedule it every
minute on an approved secured host after deployment. Set
`SECURITY_ALERT_ENABLED=yes`, `SECURITY_ALERT_WEBHOOK_URL` (fixed approved
HTTPS receiver, no URL credentials/query), independent random 32-byte
hex `SECURITY_ALERT_SIGNING_KEY`, optional `SECURITY_ALERT_CA` and mode
0700 owned `SECURITY_ALERT_STATE_DIR`; use separate restricted reader TLS
credentials. No direct live destination is configured by the repository.
The receiving service validates HMAC, five-minute freshness and exact
schema using verifyAlert; durably deduplicate Idempotency-Key before
returning a 2xx acknowledgment. Pending events survive ordinary process
restarts; retry same ID and never clear unobserved signals. A crash leaving
cycle.lock requires operator confirmation the previous process is stopped
before removing the lock. Back up and protect state files; receiver
acknowledgment does not prove a person was notified. Polling may miss very
brief events. Existing per-process API alert logs need separately approved
aggregation. Alert thresholds are provisional.

Live acceptance: identify approved endpoint and recipients, test active and
cleared transitions plus invalid signature, wrong CA, redirect, network
outage, replay and receiver suppression, then verify a named on-call person
received and acknowledged test notification within the agreed objective.
Verify forwarding/recipient policy and absence of identifying data. Record
destination and evidence securely outside the public repository.

## 3. Security recovery reconciliation and live disaster recovery

Migration 043, `scripts/security-recovery.js`, and actual encrypted
synthetic backup exercise add a signed inventory of tenant/user/membership
states, subject hashes, session revocations, cutoff, key status and incident
state. Inventory is security-sensitive; retain encrypted outside repo.
After freezing authoritative source, an approved offline runner uses
`SECURITY_RECOVERY_SOURCE_FROZEN=yes`, restricted recovery reader URL,
`SECURITY_RECOVERY_CA`, independent Ed25519 private key
`SECURITY_RECOVERY_PRIVATE_KEY`, and
`node scripts/security-recovery.js sign <encrypted-backup> <manifest>`.
Retain latest manifest digest, archive digest and approved trust anchor in
independent custody. With isolated target, set
`SECURITY_RECOVERY_TARGET_ISOLATED=yes`,
`SECURITY_RECOVERY_TARGET_URL` (approved admin only),
`SECURITY_RECOVERY_PUBLIC_KEY`, `SECURITY_RECOVERY_EXPECTED_SHA256`,
and run the replay command against the actual encrypted backup.
The signed package is distinct from the privacy disposal/hold package;
both must reconcile. Apply denial-only changes: revoke eligible membership,
disable identities, suspend active tenants, deactivate keys, merge cutoff
and targeted session evidence, activate missing open incidents. Never
reenable accounts, keys, memberships or release incidents automatically.
Missing/new identities, role/subject mismatches, historical closed incidents
not in snapshot, prior cutoff conflicts or privilege expansion require
explicit external reconciliation. Verify key material and actual current
IdP separately; inventory is not key recovery. Signed manifest attestation
does not itself prove freshness, authoritative source completeness, an
isolated target or approved deployment. The recovery process is a human-led
operational gate.

Live exercise: isolate a clean target; demonstrate restore from an actual
encrypted offsite archive, release no traffic; validate independently approved
archive, both signed recovery inventories and external audit chain checkpoint;
verify no disposed data or superseded authorizations reappear and active
incidents remain fenced. Test current key/IdP configuration, real scanner,
tenant boundaries, backup expiry and genuine user flows. Measure RPO from
latest accepted business record and RTO from incident declaration to approved
service availability. Provisional goals: RPO <=24h, RTO <=4h; owner must approve
against actual hosting budget/workload. Preserve log of start/end, restore
identity, source checkpoint and operator evidence. Failure leaves target
isolated. No live exercise has been performed by CI.

## 4. Independent penetration testing — engagement scope

An independent practitioner with written authorization must assess the
exact signed release against a private production-like staging environment
with synthetic data. Scope includes user and operator identity, MFA and
recovery, API object access and role escalation, cross-tenant and export
exfiltration, malformed transport and proxy translation, storage and
encryption, role/DB/worker boundaries, file/CSV/scanner handling,
misconfiguration and recovery, dependency/provenance, frontend/CSP and
rate-limit abuse. Include negative and business-logic tests with at least
two tenants, multiple roles and multiple auth sessions. No real customer
data, no unauthorized targets, external network attacks, destructive
production testing or unbounded DDoS. Define rules of engagement,
contact/escalation, permitted timing and stop criteria before testing.
Require named tester, signed scope, tested SHA and environment, reproducible
sanitized findings, severity and remediation owners, retest and unresolved
risk decisions. No unresolved critical/high risk; explicit owner approval
of residuals. First-party CI attacks and code review are useful evidence,
not independent penetration test results. No contractor or report has
been engaged or produced.

## 5. Malware scanner acceptance

CI starts a genuine disposable ClamAV daemon using a synthetic hash database
for clean and detection controls, and verifies the application refuses a
daemon without current versioned definitions. This tests actual engine and
socket handling but is not the live accepted production scanner. On the
chosen isolated scanner host, install a maintained verified ClamAV package,
refresh official signatures using freshclam, confirm UTC and current
definitions (<=48h), configure the protected Unix socket and restrictive
stream/scan limits, then run `node scripts/check-live-scanner.js` with
`CLAMAV_SOCKET_PATH`. It checks clean and harmless EICAR controls without
persisting EICAR. Test updated signature age, unauthorized socket access,
scanner outage, timeout, malicious control, archive/format policy, stale
lease, legal hold, manifest integrity, and two scans before approved
promotion using non-production synthetic records. Do not bypass failure,
freshness or approval. Maintain production intake disabled until all
permissions, scanner and data handling have been approved.

## 6. Production network and load acceptance

CI exercises the actual production-mode API image and simulated attack
requests on loopback; no external targets. Actual deployment needs chosen
TLS edge and proxy, trusted peer settings, TLS certificate monitoring,
host firewall, private PostgreSQL and scanner access, no public dashboard,
egress allowlist and no uncontrolled forwarding. Verify direct API access
from internet is impossible, headers ambiguous after HTTP/2-to-HTTP/1
translation are rejected, only trusted proxy may identify client, database
and scanner endpoints are private. Benchmark authenticated synthetic
business operations, 95th/99th percentile, database pools, replica
quotas and memory under approved target load. Proposed initial staging
exercise: 10 concurrent genuine synthetic business sessions for 10
minutes with approved workload, fail on cross-tenant access, wrong
authorization, database error or uncontrolled resource usage; target p95
<1s for normal reads and p95 <2s for writes, explicitly review rate limits.
These are provisional design targets, not claimed measured production
performance. Scale only with owner approval and stop on availability
degradation. Preserve measurements, network route/edge configuration and
independent retest evidence.

## 7. Australian legal/privacy acceptance

See [AUSTRALIAN_PRIVACY_LEGAL_REVIEW.md](AUSTRALIAN_PRIVACY_LEGAL_REVIEW.md)
for current OAIC and Fair Work source review, record-specific requirements,
PIA, and the upcoming 10 December 2026 automated decision transparency
obligation. Qualified Australian counsel reviews the actual legal entity,
law applicability, product processing, retention, notices, processor
contracts and user rights before publication/real intake. Record
recommendations, changes, approval scope and date; do not claim lawyer
sign-off or send any notices/filings automatically.

## 8. Non-waivable launch sign-off checklist

| Evidence | Owner/independent reviewer | Current external acceptance |
|---|---|---|
| Exact signed candidate and complete green CI | Technical owner | Verify new candidate |
| Dashboard actual operator access and SSO/MFA | Security operations | Not deployed |
| Alert receiver and person acknowledgment | Security operations | No approved live destination |
| Signed recovery reconcile and offsite custody | Recovery owner | Synthetic only; real custody not established |
| Independent penetration and remediation retest | Independent assessor | Not performed |
| Actual production scanner with current official definitions | Operations / independent review | Synthetic engine only |
| Actual production network, proxy and workload | Operations / independent review | Synthetic container only |
| Live disaster recovery RPO/RTO and owner approval | Recovery owner | Synthetic restore only |
| Legal/privacy review and agreements/rights | Qualified counsel | First-party review only |

Store actual approvals and confidential evidence outside the public repo.
Nothing authorizes main merge, paid infrastructure, deployment, live
collection, procurement, or legal filing. Every row must be reconciled
against the actual production system before the final G5 authorization.

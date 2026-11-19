# ProfitPilot — buyer security handover
18 November 2026 | Technical owner for handover: Sammy Chehade | Acquisition diligence, not launch approval

## 1. Asset and release identity
ProfitPilot is an unreleased contract-economics and exception-control software prototype, initially for Australian recurring multi-site commercial cleaning businesses. This handover covers the security-engineered repository candidate, not a commercially validated business, complete product, accounting certification or production-ready SaaS.

- Repository: https://github.com/luxhustle01-ux/Profitpilot (public; synthetic data only).
- Draft PR #38: https://github.com/luxhustle01-ux/Profitpilot/pull/38
- Reviewed source branch: security/tenant-isolation-release-gate-20261118
- Source head: ae8cdd65147ff41e82ff13cd7416b0d1746ef637
- CI-tested signed merge-ref: refs/pull/38/merge, commit 928f26fc6fbf36b8b5c35c53cf018e1c4c4e5b05
- Run #1838, ID 44233020448, attempt 1: https://github.com/luxhustle01-ux/Profitpilot/actions/runs/44233020448
- Attestation: https://github.com/luxhustle01-ux/Profitpilot/attestations/68947586
- Signed manifest SHA-256: dca60403b783fb2e9fda98e5fca02e8f88921eb6ac286b3d81551c37d9109115

The source branch head and the CI-generated merge commit are not interchangeable.
The evidence applies to the exact signed merge-ref candidate bytes. This
handover document is maintained separately from that candidate; it does not
claim a new attestation for its own documentation commit.

## 2. Evidence and reproducibility

| Job | Result | ID |
|---|---|---|
| Node.js 22 verification | Pass | 134562385880 |
| PostgreSQL migrations and tenant RLS | Pass | 134562386280 |
| Container and software supply-chain audit | Pass | 134562479149 |
| Synthetic operations and real ClamAV | Pass | 134562479168 |
| Signed candidate provenance and independent byte verification | Pass | 134562874850 |
| Security CI release gate | Pass | 134563007255 |

Node reported 259 tests: 228 passed, zero failed, 31 conditional skips. Dedicated
database and operations jobs ran their own integration tests; these are not
259 all-passing unit tests. Reviewed 46 ordered database bootstrap steps, 235
tracked files, 88 locked dependencies, 5,904 reachable Git objects (1,718 blobs,
21,904,730 bytes), zero credential-shaped findings in the configured scanners.
Runtime API and PostgreSQL images passed configured HIGH/CRITICAL scans,
including unfixed findings. Scans do not establish absence of all defects.
Seven distinct restricted worker login capabilities were adversarially tested.
Production-mode loopback test: four malformed requests rejected, 128
unauthorized requests (99 HTTP 401, 29 HTTP 429), zero detected leakage,
61 ms p95 in this synthetic workload; not a production performance SLA.
Real isolated ClamAV current official definitions, clean and harmless EICAR
controls, simulated stale definitions denial, TLS webhook, HTTPS dashboard,
encrypted logical backup and signed post-snapshot restrictions all passed.

Audit corrections in the final candidate: migration 044 blocks both privacy and
security recovery inventory export on catalogue drift; alert-state replacement
fsyncs the containing directory; verifier rejects invalid clocks and weak
keys; revocation cutoffs cannot postdate a signed recovery manifest.

## 3. Exact artifacts (retain the original ZIPs)

| Artifact | ID | SHA-256 |
|---|---:|---|
| Candidate ZIP | 14395816850 | bc537e88891c8c8539f098361b9c0c0fd6800911defb2703df13f2741a2fa2c7 |
| Provenance ZIP | 14396256010 | 896819c7905648e9ddedae56cc688b5c2e047bc8aaef5410f9c20fc288804e62 |

Download from the CI run artifacts section. GitHub retention expires on
25 November 2026 at approximately 03:50 UTC (14:50 Melbourne).
The handover copy retains the two original ZIPs. Independently preserve and
recheck them; do not rely on continued access to the transient Actions artifacts.
Do not store real credentials or customer information in GitHub.
The candidate contains source.tar.gz, exact linux/amd64 API and database image
archives, two vulnerability reports, dependency CycloneDX SBOM and manifest.json.
The provenance ZIP contains provenance-bundle.jsonl.

### Buyer verification

On an independently trusted technical workstation, check the two original ZIP
SHA-256 digests against the table. Extract them to separate private directories.
Before executing any downloaded source, verify the manifest with a trusted
GitHub CLI installation:

```sh
gh attestation verify candidate/manifest.json \
  --bundle provenance/provenance-bundle.jsonl \
  --repo luxhustle01-ux/Profitpilot \
  --signer-workflow luxhustle01-ux/Profitpilot/.github/workflows/ci.yml \
  --source-ref refs/pull/38/merge \
  --source-digest 928f26fc6fbf36b8b5c35c53cf018e1c4c4e5b05 \
  --deny-self-hosted-runners
```

Use an independently reviewed verifier from the trusted commit:
```sh
node scripts/release-candidate-manifest.js verify candidate \
  luxhustle01-ux/Profitpilot 928f26fc6fbf36b8b5c35c53cf018e1c4c4e5b05 \
  44233020448 1
```

Verify every manifest SHA-256 and size. Inspect SBOM, scan scope/date and actual
image IDs; load only verified archives into an isolated synthetic staging
environment. Never use an unverified rebuild as a substitute for tested bytes.
For a transferred repo, independently approve the buyer's repo/ref/workflow
identity and generate new signed provenance, rather than accepting old trust
settings automatically. PR merge-ref provenance establishes build origin,
not protected production release approval.

## 4. Technical diligence map (relative to signed source archive)

| Purpose | Location |
|---|---|
| Local synthetic setup | docs/LOCAL_DEVELOPMENT.md, docker-compose.yml, .env.example (review current code over older text) |
| Runtime and CI | Dockerfile, database/Dockerfile.postgres, .github/workflows/ci.yml, package-lock.json |
| Security architecture and audit matrix | docs/SECURITY_ENGINEERING_FINAL_ACCEPTANCE.md, docs/SECURITY_PRIVACY_READINESS_REVIEW.md, docs/IDENTITY_AND_TENANT_SECURITY.md |
| Production acceptance / pentest statement of work | docs/PRODUCTION_SECURITY_ACCEPTANCE.md |
| Key rotation, backup, alert and recovery procedures | docs/SECURITY_OPERATIONS_HANDOVER.md, docs/PRODUCTION_SIGNING_KEY_RUNBOOK.md, scripts/secure-backup.js, scripts/privacy-recovery.js, scripts/security-recovery.js |
| Dashboard and alerts | ops/security-dashboard.*, scripts/security-dashboard.js, scripts/security-alert-delivery.js |
| Data governance and privacy review | docs/AUSTRALIAN_PRIVACY_LEGAL_REVIEW.md, docs/DATA_CLASSIFICATION_PRIVACY_AND_TENANT_GOVERNANCE.md |
| Product limitations and transfer strategy | docs/ACQUISITION_READINESS_PLAN.md, docs/MASTER_COMPLETION_REGISTER.md |

Use Node.js 22, PostgreSQL 16, verified TLS DB and known-good OIDC/JWKS.
CI + Compose orders migrations 002–044 and initial schema/roles/key
bootstrap (46 steps). Use a fresh synthetic environment. Existing volumes
must be migrated deliberately. Local Compose is not production infrastructure.
The business dashboard remains a synthetic demonstration distinct from the
restricted security dashboard. Production import intake and payroll remain
disabled. Do not change those gates to demonstrate an unsupported feature.

## 5. Remaining buyer acceptance gates

| Gate | Required evidence before live customer data | Responsibility |
|---|---|---|
| Independent penetration testing | Written scope, independent reviewer, exact tested SHA, environment, sanitized findings, remediation and retest; no unresolved high/critical risk | Buyer security owner and independent assessor |
| Production identity and dashboard | Real OIDC, MFA, managed keys, per-operator access, approved private dashboard route and rotation exercise | Buyer operations |
| Live alerts | Approved HTTPS receiver, durable deduplication, monitored retries, confirmed on-call acknowledgment, no identifiers | Buyer operations |
| Production scanner | Actual isolated maintained scanner and current official signatures; clean/EICAR, outage, freshness, lease, promotion and retention checks | Buyer operations |
| Network/load | Chosen TLS proxy and firewall, direct-path denial, HTTP/2 translation, authenticated workload, replica quotas and resource limits | Buyer operations |
| Disaster recovery | Actual encrypted offsite backup, independently retained latest checkpoints, both signed manifests, current IdP/key state, isolated restore, measured RPO/RTO and approval | Buyer recovery owner |
| Australian privacy/legal | Qualified counsel review of entity, notices, actual flows, contracts, retention, APP/NDB/TFN applicability and automated decisions; named privacy contacts and rights process | Buyer counsel / privacy owner |
| Commercial/product | Working end-to-end product, financial validation, support and applicable payment/regulatory obligations | Buyer product and finance |

No live target, approved alert destination, legal opinion or independent
penetration report is supplied. The first-party tests are not independent.
No security percentage or absence-of-bugs warranty is asserted. Keep customer
intake closed until all applicable gates are evidenced. Existing operational
documents propose RPO 24h, RTO 4h and 30-day routine encrypted backup expiry;
the buyer must approve the actual workload, timing and legal holds.

## 6. Transfer and chain-of-title checklist

Before closing an acquisition, verify the seller's rights to all contributions,
product marks, designs, source, and contractual assignments. The public GitHub
repository does not by itself establish exclusive ownership or a licence to sell.
A root LICENSE file was not found at the reviewed source head; do not invent one
or represent legal title as established. Repository and Git history exposure
cannot be retroactively erased by changing visibility. At this head,
package-lock.json has 88 dependency entries declaring MIT (82), ISC (4),
BSD-2-Clause (1), BSD-3-Clause (1), all with lock integrity metadata.
These are declared metadata only, not independent licence review. Reconcile
actual NOTICE/licence texts, container OS/PostgreSQL and ClamAV components,
build tooling, scanner/registry terms and all other assets with counsel.

- Confirm assets legally included/excluded and signed sale/assignment terms.
- Verify buyer's repository control and agreed migration method; preserve archive
  digests, source history, verified evidence, CI work and issues. Do not transfer
  personal accounts, old access tokens or production secrets. Buyer creates
  new credentials, environment, IdP and signing custody.
- Reconfigure hardcoded repository/ref checks and Actions permissions only in
  the approved buyer repository, protect the release branch, rerun all tests,
  re-scan at transfer and attest the exact buyer-owned release.
- Arrange private evidence custody for actual operational approvals; never commit
  real personal or customer data to this public repository.
- Record named acceptance owners, evidence links, exact SHA, decision, expiry,
  outstanding risks and signatures outside public Git.

Seller deliverable: exact candidate and provenance archives, technical evidence
and documentation. Buyer retains deployment, independent review, legal sign-off
and commercial operating decisions. No sale, legal commitment, main merge,
deployment, external outreach or expenditure is authorized by this pack.

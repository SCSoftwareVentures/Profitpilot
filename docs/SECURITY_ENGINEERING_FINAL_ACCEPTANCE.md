# ProfitPilot — final security engineering acceptance

Date: 18 November 2026. Technical owner: Sammy Chehade.
Scope: draft PR #38, synthetic repository release candidate only; no production
deployment, real customer data, independent penetration test or certification.

## Verified baseline and new release gate

The verified baseline is commit `fb0fa6201b06c5ad18ee72fdbb1c095803c248fd`,
CI #1767 (https://github.com/luxhustle01-ux/Profitpilot/actions/runs/44226462045):
all four jobs passed, including PostgreSQL 16, real TLS, API authorization,
encrypted synthetic backup/restore, database catalogue integrity, incident
containment and the minimized security-command report. HIGH/CRITICAL runtime
image scans passed. This baseline does not verify the new candidate changes.

This candidate adds mandatory fetched-history inspection, scanned artifact
packaging, byte-level manifest verification, GitHub OIDC-signed build
provenance and verification pinned to repository, workflow, exact ref and
commit. It adds realistic worker-role credential attack and emergency lock
race tests, plus internal foreign-key trigger and RLS definer login
drift detection. Exact-head CI must pass all five jobs on the reviewed
candidate ref before engineering acceptance. The final security gate depends
on provenance; no previous green run substitutes for that result.

## Engineering review and acceptance matrix

| Attack/control | Required evidence | Boundary that remains |
|---|---|---|
| Authentication forgery, old tokens, wrong issuer, audience, profile, MFA and sessions | Auth/JWKS/session tests and real DB revocations | Real IdP, key/session lifecycle, account recovery |
| Tenant data theft, BOLA, spoofed GUC, wrong actor, direct SQL | Actual API matrix, runtime RLS, composite FK and exact catalogue tests | Every future route/data source; independent test |
| Privilege escalation across workers | Exact effective grants, no delegation, seven real restricted worker login tests | Individually managed operator credentials and access reviews |
| RLS and constraint tampering | Live fingerprint incl policy, ACL, function, trigger, internal FK and definer login tests; restore parity | Privileged DB/host administrator trust; independently authorized baseline |
| Injection, HTTP ambiguity, unsafe bodies and parsing | Parameterized SQL, raw HTTP framing tests, bounded JSON/CSV and malicious corpus | Production proxy translation, production scanner corpus, new formats |
| Sensitive personal data and metadata exposure | Allowlisted invoice rows, prohibited data screening, minimized outputs/export, no payroll intake | DLP is heuristic; legal/field-map approval and human review |
| Denial of service and brute force | Shared limits, concurrent quotas, budgets, temporary containment and lock recovery | Real deployment load, upstream DDoS, workload thresholds |
| Fraudulent or overwritten financial evidence | Insert-only automated proposals, row provenance, signed role checks and audit chain | Complete business workflows and independent accounting review |
| Malware, tampered or unapproved import | Encrypted quarantine, scanner lease/manifest, signed MFA session approval and revocation | Production import API disabled; real isolated scanner acceptance |
| Emergency containment bypass | Dedicated operator/recovery authorities, transaction fence, concurrent lock test and invalidated promotions | No recall of bytes previously returned; external incident reconciliation |
| Audit and privacy rollback | Append-only events, chain checkpoint, authenticated backup and signed privacy receipt replay | Offsite latest checkpoints and independent custody; identity/membership/key/incident reconciliation |
| Secrets, dependency redirection and build chain | Source scan, reachable-history scan, exact lock, pinned images/actions, no install scripts, scans and SBOM | Provider/registry/runner trust; scanners cannot recognize all secrets or vulnerabilities |
| Artifact substitution | Exact manifest hashes; image reload IDs; GitHub Sigstore provenance verification | Independently reviewed release approval; retain exact bytes; no registry/tag/deployment |
| Monitoring and incident response | Restricted command report, aggregate alarms, incident recovery | Live UI, independent alert delivery, on-call and tabletop |

## Identified defects corrected by this engineering pass

- The live fingerprint previously excluded internal FK trigger modes and
  did not detect enabling login for the BYPASSRLS context owner. Migration
  042 retains historical baselines, fingerprints structural constraint
  trigger identity and mode without OID-dependent names, and checks the
  definer remains NOLOGIN. Privileged migrations remain trusted operations.
- Restricted function grant options are now explicitly rejected in the
  catalogue test. Seven isolated real logins attempt cross-role assumption,
  direct data theft, unauthorized function execution and DDL.
- CI now scans fetched reachable history, not just current tracked files.
  This recognizes common secret shapes and restricted backup/key filenames;
  it is not a guarantee about arbitrary secrets, omitted refs, deleted
  unreachable objects, external forks or local repositories. The scan
  blocks on findings or incomplete coverage and never prints values.
- The candidate package includes exact scanned image archives, source archive,
  dependency SBOM, scanner JSON and digest manifest, not a rebuild represented
  as the previously scanned bytes. Artifact generation follows source verification.
  The independent runner validates bytes and image identities, then attests the
  manifest. The gate fails if the required provenance job fails.

## Release candidate verification and handover

Download candidate and provenance artifacts from the same successful
workflow run and attempt. They are synthetic/public-repository build
artifacts with seven-day retention. A buyer or approved operator verifies
the manifest's GitHub attestation with `gh attestation verify`, using
independently approved repository, workflow, ref, SHA and GitHub-hosted
runner requirement. Supply the downloaded bundle using `--bundle`.
Then verify every artifact's SHA-256 and size using
`node scripts/release-candidate-manifest.js verify <directory> <repository> <commit> <run-id> <attempt>`.
Never run a verifier from untrusted downloaded source before its integrity
has been established: use the reviewed verifier from an independently approved
commit. Do not use unverified build bytes, substitute a later rebuild,
or infer release approval from a PR merge-ref provenance. For a real release,
independently approve a protected branch/tag, verify its exact provenance
and retain its immutable artifacts. An Actions attestation proves provenance,
not independent owner authorization, absence of bugs, or production safety.

## Release disposition

Production customer intake remains closed. No live deployment, main merge,
production secret, purchase, or customer data is authorized by this review.
A full engineering acceptance is contingent on exact-head CI and actual
artifact/signature validation. Independent penetration testing, actual IdP,
proxy/load tests, malware scanner, recovery reconciliation with authoritative
operator records, incident records outside the backup, privacy counsel and
on-call/alert acceptance remain mandatory before live release.

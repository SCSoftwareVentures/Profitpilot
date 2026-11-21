# B17 — Independent review evidence **byte-integrity** verification

**Scope:** Offline, read-only cryptographic preflight only. It cannot assess reviewer independence, report completeness, professional qualifications, release approval, real demand, compliance or deployment safety.

## Prior defect

B13 bound two Ed25519 review signatures to the exact source, container digests and five 256-bit evidence references. Without validating the actual report bytes, it was possible to verify a properly signed manifest of hashes even when the documents themselves were missing or altered. Signatures alone did not prove any report existed.

## B17 implementation

The new script first executes **B13 verification** of both independent pinned reviewer keys, the protected external key-policy SHA-256, signed request scope, timestamp, source SHA, image IDs and dossier digest. Only if B13 succeeds does B17 read the five reports and independently SHA-256 hash their actual bytes. These hashes must match the exact digests authenticated in the signed B13 request.

Five required report byte streams:
- penetrationTest.evidence
- legalPrivacy.evidence
- deviceAccessibility.evidence
- recoveryOperations.evidence
- ipLicensing.evidence

The files must be in a separately controlled, non-source directory. The names are deliberately extension-neutral: a PDF, JSON or text file can be copied **byte-for-byte**, without recoding, to its corresponding .evidence filename. Do not commit sensitive report content or private employee/customer information.

Each report must be a nonempty regular file no larger than 8 MiB. B17 opens without following final-component symlinks, reads through one bounded file descriptor, refuses mutation/growth during the read, rejects duplicate inodes and compares the exact SHA-256 digest. Paths resolving into the editable source tree are refused. The two signatures, pinned policy and report byte hashes are all mandatory; partial evidence cannot pass.

## Offline invocation — no hosting or API access

On a separately controlled, trustworthy machine with Node.js 22, not on a live production server:

1. Independently provision a B13 approved policy, the external expected SHA-256 of that policy, and the two-signed review bundle outside the repository.
2. Populate a protected directory with five independent review report byte streams named above.
3. Export the B13 environment variables plus the evidence directory.
4. Execute:

\`\`\`sh
export PROFITPILOT_RELEASE_REVIEW_POLICY_FILE=/secured/review/pinned-key-policy.json
export PROFITPILOT_RELEASE_REVIEW_POLICY_SHA256=<external trusted 64-hex policy digest>
export PROFITPILOT_RELEASE_REVIEW_BUNDLE_FILE=/secured/review/signed-approval.json
export PROFITPILOT_RELEASE_EVIDENCE_DIR=/secured/review/evidence
node scripts/verify-release-evidence.mjs COMMIT_SHA API_IMAGE_SHA256 PROTECTED_IMAGE_SHA256 DOSSIER_SHA256 CHANGE_TICKET
\`\`\`

The command exits nonzero if any proof, scope, file or hash fails and reports the five matched report hashes on success. It has **no deploy, merge, source signing or fund movement powers**. Signing-key custody, report provenance, actual dates/assurance, revocation, receipt freshness and independent assessments remain separate human controls. Even if all reports match, the output reports \`productionReleaseApproved:false\` and \`deploymentAuthorized:false\`.

## Outstanding hard gates

- Container Grype currently blocks protected ClamAV for 14 OpenSSL findings, with no verified upstream remediation available from the checked CI evidence; no policy overrides or invented clean scan.
- Actual independent penetration retests, vendor-signed scanner signature operations, Australian legal/privacy review, iPhone Safari/VoiceOver, MFA and TLS integration, external backup custody, incident tabletop, monitored recovery and buyer/IP rights remain unproven.
- Real GitHub branch protections and externally governed two-person release approvals have not been configured. This script is never sufficient to replace them.
- Existing CI can test B17 with synthetic documents, but that is not independent testing of any of the real-world external requirements.

**Disposition: REVIEW-INTEGRITY CODE ONLY; PRODUCTION AND COMMERCIAL RELEASE STILL BLOCKED.**

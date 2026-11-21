# ProfitPilot B13 — Independent, cryptographically scoped review proof (draft)

**Status:** Executable offline proof verifier plus unit tests, NOT a production-release authorisation service, legal certification, external evidence validation, or a completed approval.

## Why it exists

B9/B10 source provenance attests the workflow that constructed a GitHub artifact, but cannot show that an independent security reviewer or owner separately agreed to a specific release. B13 can cryptographically verify **two distinct Ed25519 private-key signatures** over an exact source commit, the two image digests, a source dossier digest, a short-lived change ticket and five evidence references. These are self-contained review records, not proof the evidence is true or the human signers were independently identified.

No private key is generated, committed, uploaded, read or accepted by the production API. The verifier has **no signing, pushing, merging, deployment, notification, payment or dossier publishing capability**.

## What is implemented

- Bounded, schema-strict signature request; namespaced canonical bytes with fixed field order and exact SHA format.
- Separate pinned owner and independent-security-reviewer Ed25519 public keys, with distinct key IDs and key fingerprints.
- Expiring requests (at most one hour), scope matched to exact repository/commit/API-and-protected-image/source-dossier digests and change ticket. No approval reuse across changed images or commits.
- Five non-empty SHA-256 evidence references: penetration test, legal/privacy review, device/accessibility acceptance, recovery/operational readiness and IP/licence review.
- Read-only, no-follow, bounded external-file CLI. Policy and approval bundle must be distinct and located **outside** the editable repository tree.
- Result explicitly returns false for production readiness, deployment authority, independently verified identity/evidence and buyer demand. This is not an automatic go/no-go certificate.
- Negative tests: duplicate or forged signatures, both roles using the same key, changed source/evidence, expired and future requests, malformed shape, unsafe file paths and symlink substitution.

## Offline review-only interface

With Node.js 22 in a trusted checkout (nothing is deployed):

```sh
export PROFITPILOT_RELEASE_REVIEW_POLICY_FILE=/protected/review/owner-and-security-public-keys.json
export PROFITPILOT_RELEASE_REVIEW_BUNDLE_FILE=/protected/review/two-signed-review-approval.json
node scripts/verify-release-review.mjs SOURCE_COMMIT_SHA API_IMAGE_SHA256 PROTECTED_IMAGE_SHA256 SOURCE_DOSSIER_SHA256 CHANGE_TICKET
```

The two files must be privately and independently provisioned. **Do not create pseudo-independent roles with the same user/key.** Only the public keys and signatures are needed by the verifier; secret keys must remain outside ChatGPT, source, CI artifacts and untrusted build runners. An evidence digest signs a reference to a report; a qualified reviewer must separately authenticate the actual report and confirm the digest.

The pinned key-policy file is a trust root. It must be managed and independently approved outside an editable feature branch. If a repository author can replace the policy and both signatures, this verifier alone cannot establish independence.

## Verification boundary and integration blockers

1. The latest B12 scan still contains 14 blocked OpenSSL findings in the protected ClamAV image. Both images must be rebuilt and rescanned against currently supported patched libraries or another independently reviewed compliant scanner. **No scanner disabling, vulnerability ignoring or policy lowering.**
2. Independent security pen test, qualified Australian legal/privacy review, physical iPhone Safari/VoiceOver and a measured production-like disaster recovery drill **have not occurred**. B13 requires their report digests but cannot create those reports or validate their contents.
3. Cryptographic review is not sufficient by itself. Before it can become a production gate, establish protected GitHub release rules, required checks, two-person governance of public-key policy, environment boundaries and audit retention. Admin/branch protection is not configured by this draft.
4. There is **no production deployment workflow** bound to B13. This deliberate isolation avoids treating a review proof as permission to deploy.
5. Actual customer data, real payments, legal clearance, transfer rights and real buyer demand are outside scope. Never add approval evidence containing employee/customer records to this public repo.

## CI acceptance and follow-up

B13 Node tests execute under the existing `npm test` and syntax checks under `npm run check`. Only exact-head GitHub CI can establish this branch passed; a green unit-test result never overrides failed container-security checks. External signers and evidence are not synthetic CI fixtures that can be promoted into real approval.

**Current intended disposition:** DRAFT REVIEW-PROOF ONLY; PRODUCTION RELEASE AND SOURCE ACQUISITION SIGN-OFF BLOCKED. No spending, deployment, merge, repository rule changes or outside customer interaction were performed by this implementation.

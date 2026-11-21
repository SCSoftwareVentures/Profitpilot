# ProfitPilot B9 — Candidate source-acquisition evidence dossier

**Purpose:** Make the draft technical asset transferable for inspection, without implying that it is lawful to transfer, production-ready, has revenue, or has real customer demand.

## Candidate materials

The offline CI-generated handover contains the exact reviewed Git source archive, a CycloneDX npm SBOM, the B6 tracked-file and dependency metadata inventory, a buyer-facing truthful limitation notice, and commit-specific SHA-256 manifest/checksums. The source archive includes the fictional B5 mobile demonstration, B8 CI-only recovery rehearsal, partial API and tenant/RLS migrations, security documentation, and all tests committed at that source revision.

When the workflow succeeds, it creates a canonical tarball containing these six files, signs the tarball using GitHub's provenance action, verifies the attestation and retains both tarball and attestation in the job artifact. A consumer must verify the attestation independently. The manifest cannot hash its own external signature or certify its publisher. GitHub attestation confirms the workflow identity and artifact digest; it does NOT establish original copyright ownership.

## Security and automated gates

The B9 job requires the success of five upstream jobs: Node tests/npm audit, PostgreSQL migrations/RLS and synthetic recovery, CodeQL, container vulnerability scan, and the B8 real isolated Compose boot and legacy-volume upgrade rehearsal.

The job runs ONLY on a push to its specific named draft feature branch, with repository-read, GitHub OIDC token and attestation-write permissions. It neither pushes changes nor deploys software. It installs the lockfile with npm ci --ignore-scripts, archives the exact GITHUB_SHA source commit, generates an npm CycloneDX SBOM and the read-only B6 source audit. The package builder rejects a stale source commit, altered permission claims, malformed SBOM, changed files and missing warning statements.

All source/manifest files are non-secret public-repository content at the indicated revision. CI keys and attestation identities stay with the runner. The output is a short-lived GitHub Actions artifact, not a web-hosted product. No additional paid service or customer data is authorised.

## What is not established

- Ownership/transfer: contributor chain of title, rights assignments, full open-source licence obligations, container/base-image licensing, trademarks, contracts or legal right to resell.
- Commercial outcome: real customer demand, validated paid interest, price support, acquirer commitment or operating revenue.
- Operations: production SaaS, live identity provider, real data, monitoring, legal privacy compliance, live payment provider, independent penetration test, production backup custody or safe upgrade of untested environments.
- Device/accessibility: real iPhone Safari/WebKit, VoiceOver/Voice Control and large-text acceptance.
- G0–G5: a fictional demonstration or numeric G0 evaluator cannot authorise the production build.

This is technical source evidence for buyer diligence. Independent inspection, a legally valid transfer agreement and owner authorisation remain necessary. It is not a sale announcement or authority to merge, deploy or transfer anything.

## Buyer verification on a trusted machine

1. Extract the GitHub Actions artifact ZIP and verify the checksum file for its six-file candidate dossier.
2. Compare MANIFEST.json source SHA with the exact CI commit and acquisition-inventory.json. Validate tracked source file hashes in a clean checkout.
3. If PROVENANCE.jsonl is present, verify the attested ProfitPilot_RC_Source_Dossier.tar.gz with GitHub CLI against the expected SCSoftwareVentures/Profitpilot repository identity; inspect that tarball's embedded files.
4. Review and test independently. GitHub attestation does not certify IP title, customer demand, legal compliance or security readiness.

B9 does not change the B5 fictional demo, API endpoints, production database or payment features. The job must itself pass CI before any claims of verified packet provenance.

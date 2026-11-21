# ProfitPilot B10 — Source archive and SBOM reconciliation gate

**Scope:** the existing B9 draft source dossier remains an unreleased acquisition diligence artifact. B10 strengthens source and supply-chain verification, not legal ownership.

## Finding

B9 checked the source tarball for only a gzip magic header and required merely a nonempty CycloneDX component list. It did not independently verify archived source-file contents against the B6 file inventory or reconcile actual SBOM packages and versions to the locked dependency inventory. A mismatched archive or inaccurate inventory could pass those checks while having valid outer checksums.

## Correction

The new pure Node.js verifier in src/source-handoff-integrity.js bounded-decompresses the Git tarball, verifies tar-header checksums, the exact commit in the Git archive global PAX comment, safe file paths and entry types, and every archived file's size, SHA-256 digest and path against the B6 inventory. It refuses duplicates, omitted or extra files, special/link entries, path traversal, truncated archives, and oversized input.

It separately reconciles every CycloneDX component's npm package path and version with the locked npm inventory, rejecting absent, additional, duplicate and mismatched packages. The B9 dossier manifest now records verified source file and locked dependency counts. Synthetic unit tests and adversarial cases cover both gates.

The B10 validation is part of the existing CI-gated acquisition dossier build. It can generate signed candidate evidence only on the specifically allowed B9 and B10 draft feature branches after Node, PostgreSQL/tenant RLS, CodeQL, container vulnerability analysis, and the B8 synthetic Docker Compose recovery rehearsal have passed.

## Limitations

These checks establish internal consistency, not copyright ownership, legal right to transfer, independently validated customer demand, pricing or a production service. A forged inventory and matching forged source can still be consistent; buyer verification of the GitHub Actions attestation, workflow identity and intended repository is a separate authentication step. Independence, IP/title, licence-text, iPhone Safari/accessibility and real-customer requirements remain open. No real data, spend, deployment, merge or notifications are involved.

Before committing B10, its verifier was independently exercised against the previously downloaded B9 source archive: 187 archived source files and 88 locked npm dependencies matched. The original B9 artifact does not retroactively gain the new CI gate; the B10 CI result must be checked at its exact commit.

# ProfitPilot B6 — Acquisition source inventory and rights evidence

**Status:** automated metadata inventory, NOT an IP legal opinion, chain-of-title certificate, licensed distribution, customer-demand proof or production release.

## Why B6 exists

The earlier B5 ZIP proves the narrow technical **fictional offline demo** can be recreated at a particular commit. It does not tell an acquirer which source files and dependencies are being transferred, whether contributor rights are assignable, or whether embedded third-party components satisfy redistribution obligations. B6 makes the factual part of that review reproducible while explicitly blocking unsupported legal/commercial conclusions.

The base repository snapshot inspected on 21 November 2026 had **88 resolved npm packages in package-lock.json** (82 declaring MIT, 4 ISC, 1 BSD-2-Clause and 1 BSD-3-Clause), with integrity and resolved fields present. This is lockfile metadata, **not independent review of actual licence texts, attributions, copyright ownership or permitted redistribution**. The base tracked source had no top-level LICENSE/LICENCE/COPYING file. Absence of a public licence does not prohibit a lawful private asset sale; it does mean no public licence/transfer right is established by that file.

## Executable, offline inventory

- Core: src/buyer-acquisition-audit.js — compares package.json runtime dependencies against package-lock root dependencies, enumerates pinned dependency metadata, checks source inventory claims and preserves manual gates.
- CLI: scripts/build-buyer-acquisition-audit.mjs — uses git ls-files to inventory only tracked paths at the current HEAD; refuses dirty tracked files, unsafe paths, symlinks/nonregular source files and oversized files. Computes SHA-256 for each tracked file **from bounded reads**. No network request or upload.
- Tests: tests/buyer-acquisition-audit.test.js — missing licence metadata, missing source components, unexpected sensitive-looking filenames, duplicated records, malformed paths, dependency drift and fixed human-evidence gates.
- Usage in a clean Git checkout with Node.js 22: npm run audit:buyer for JSON, or npm run check to enforce the automated metadata consistency rules. The audit is read-only; the command emits the manifest rather than creating a persistent release asset.

The manifest contains filenames, byte lengths, file digests, npm lock metadata and an exact Git HEAD. Its SHA values detect changes against the reported manifest but DO NOT authenticate the publisher or validate historical authorship. Checking a filename against a pattern is not secret scanning; copyright or embedded secrets cannot be inferred solely from metadata. Human reviewer must inspect actual file content and Git history. Checks run within the reviewing environment, which is not equivalent to a trusted third-party audit.

## Explicitly unresolved buyer gates

1. **Source IP and contributors:** written chain of title for every contributor, licence rights for any copied assets/templates, trademark and brand checks, contractual transfer restrictions.
2. **Dependency redistribution:** independently inspect licence texts, notice/attribution requirements, package trees, source commitments and bundling obligations. MIT/ISC/BSD declarations in npm lock are not exhaustive legal due diligence.
3. **Runtime components:** Node.js/Alpine, PostgreSQL and ClamAV containers/native components and any redistributed binaries need independent licence and notice assessment. npm inventory covers none of these.
4. **Clean transfer:** buyer repository permissions, organisation access, successor maintainers, release branch inventory, secure handover of operational responsibilities and independent clean-install review. No credentials or secrets in the public repo or buyer ZIP.
5. **Commercial evidence:** real demand, paid intent, acquisition interest, valuation, actual source authorisation and all G0–G5 gates remain unverified.
6. **Independent acceptance:** physical iPhone/WebKit and accessibility acceptance, independent security/financial review, production operating/legal/provider approvals, signed provenance for the final source asset.

**No sale authorisation is inferred by running this tool.** It always returns PENDING_INDEPENDENT_DUE_DILIGENCE, even when mechanical checks succeed. This source-only handover evaluation is separate from software-build G5 and SaaS deployment.

## Interpretation

A reproducible inventory improves buyer diligence and reduces surprise; it cannot force a buyer to pay or guarantee a sale. A buyer can acquire unfinished proprietary source code only after the parties address ownership, transfer and disclosed-condition risks under their own terms. The product remains a partial technical prototype, and its B5 fictional demonstration is not a customer-validated business.

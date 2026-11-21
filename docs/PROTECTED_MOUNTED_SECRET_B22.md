# ProfitPilot B22 — Protected mounted-secret integrity and startup security review

**21 November 2026 · review-only draft · no production deployment**

## Scope and reviewed threat

The protected API requires two independently mounted secrets: a PostgreSQL connection URL and a tenant-context HMAC signing key. B14 checked that the target was a bounded regular file and applied owner-only file permissions. An attacker who could influence the filesystem path or replace a parent symlink could redirect the secret read without using a final-component symlink. Previously, ownership, hardlink counts, directory writability, changes during a read and consistency at protected startup were not all checked.

The review assumes a nonroot Linux application process, container filesystem isolation and administrator-controlled read-only mounts. It does **not** assume a malicious process running as the application's own UID can be securely excluded; same-UID compromise and host mount tampering require external OS/container isolation and independent assessment.

## Implemented controls

1. For **protected** mode, require an absolute, canonical, length-bounded filesystem path with no `.`, `..` or embedded nulls. Require the platform to support `O_NOFOLLOW` and POSIX effective-UID checks.
2. Walk every ancestor from filesystem root to the secret file with `lstat`; reject symlinks, nondirectories, parents owned by unrelated UIDs and group/world-writable ancestors. A root-owned sticky directory (e.g. `/tmp`) is accepted to permit isolated synthetic CI tests, but its descendant mount directory must be owner-controlled and not group/world-writable.
3. Require the **secret file** to be regular, single-linked, owned by the process effective UID, and mode **0400 or 0600**. Do not follow even the final symlink. Verify the opened descriptor has the same inode, ownership, mode, size and mtime/ctime as the opened path immediately before and after reading.
4. Bound the read to **8192 bytes**, reject empty/invalid UTF-8 and unsafe controls. Accept an optional single terminal newline from secret managers. Reject leading/trailing whitespace and embedded control characters in protected mode rather than silently trimming altered contents.
5. Refuse ambiguous environment + file secret configuration (even if the raw environment variable is an empty string), and refuse plain environment fallback in protected mode.
6. Before binding an HTTP listener, run `protectedStartupPreflight()`: validate **both** required mounted secrets, the PostgreSQL URL's TLS-safe syntax, and a minimum 32-byte hex tenant signing key. The existing protected issuer/JWKS preflight and scanner executable gate remain mandatory.
7. Keep prototype/test-mode compatibility for synthetic Compose and existing nonprotected secret workflows.

## Operational provisioning contract

A production-equivalent operator must mount the two secrets separately under **trusted directory paths** (for example, `/run/secrets/...`), with each file owned by the application's runtime UID **1000** and mode **0400 or 0600**. Ancestors must not be symlinks and must be trusted, non-writable by other users. The mounts must be **read-only at the container/mount layer**. File mode 0600 by itself does not prove read-only custody.

This rejects common Kubernetes secret-volume `..data` symlink layouts rather than bypassing symlink checks: operators must use a compatible securely projected or direct-mounted layout that satisfies the documented requirements, with independent review. Docker/Compose's existing `api` service remains a **synthetic prototype**, not a protected deployment with live secrets.

Key rotation needs a securely prepared replacement and a controlled restart/rollover. A mutated, moved or malformed secret causes a fail-closed error; no plaintext secret bytes or file paths are intentionally included in logs. The HMAC key is re-read before tenant-scoped queries, so mid-operation mutation can block requests even after an earlier successful preflight.

## Adversarial regression review

Tests exercise valid 0400/0600 owner-controlled files with optional final newline, missing files, raw-env ambiguity, invalid HMAC, final and parent symlinks, writable parent, hardlink alias, executable/group/world-accessible file modes, oversized file, embedded NUL/control/newline, leading/trailing spaces, noncanonical paths and protected startup preflight rejection.

Review of guard limitations:

- `lstat` + `open(O_NOFOLLOW)` + descriptor checks **reduce** path substitution, but do not atomically pin all parent directory file descriptors; an attacker who can mutate a trusted same-UID mount namespace may race parent resolution. Real read-only immutable mounts and host isolation must still be verified.
- `fstat` and mtime/ctime checks are not tamperproof cryptographic integrity proofs; a privileged host attacker could replace secrets between startup checks and later reads. Mount source custody and rotation procedures remain external gates.
- Process memory contains plaintext secrets for necessary PostgreSQL/HMAC use; this implementation does not claim secret memory zeroisation or protection from same-process code execution.
- File ownership compatibility must be validated against the actual nonroot runtime and deployment secret store. No live secret store or production environment was accessed.
- This sprint is **not** a substitute for real IAM/MFA, independent penetration testing, privacy/legal review, backup restoration, incident response, or signed external release approval.
- The 14 existing Alpine OpenSSL vulnerability findings remain **unsuppressed, blocked** by Grype and the B19 patched-version check; no dependency was replaced or risk accepted.

### Acceptance evidence

Require an exact-head GitHub Actions run with all zero-skip unit tests and the three separate PostgreSQL integration tests passing, CodeQL passing, synthetic Compose and native scanner negative controls passing, and full protected vulnerability scan retaining its hard fail until vendor-patched OpenSSL is verified. Capture both source commit and exact CI run in the draft PR. No merge or deployment without explicit owner approval.

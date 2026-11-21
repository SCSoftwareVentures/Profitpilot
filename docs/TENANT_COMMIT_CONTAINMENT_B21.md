# B21 — Tenant transaction COMMIT uncertainty and HMAC input hardening

**21 November 2026 · draft only · synthetic and CI verification**

## Audited failure mode

`withTenantUsingPool` in `server/db.js` signs a tenant UUID, an authenticated subject and a bounded key ID into an HMAC-backed, transaction-local PostgreSQL context. B15 already destroyed an uncertain pooled connection when `ROLLBACK` failed. However, if an application callback had finished and `COMMIT` returned an error **but a subsequent ROLLBACK succeeded**, B15 released that connection for reuse. A COMMIT error (for example, a broken network connection after the server committed) does not necessarily prove that the transaction did not commit.

That error is **not automatically retried**. The caller receives the original failure; any subsequent retry must be handled using the endpoint's independently tested business idempotency semantics.

## B21 mitigation

1. Before constructing a signed scope or borrowing a pooled connection, require a supported RFC-version UUID with proper variant bits. Normalise uppercase UUIDs to PostgreSQL's lowercase canonical text. This prevents malformed, control-character or non-UUID inputs from entering the HMAC boundary.
2. Require `TENANT_CONTEXT_HMAC_KEY_ID` to be a bounded, nonempty identifier with safe ASCII characters (letters, numbers, dot, underscore, colon, hyphen), length 1–64. If unspecified, continue to use `primary`. Explicitly invalid values now fail closed.
3. Mark a transaction **before** sending `COMMIT`. Any COMMIT error, even if `ROLLBACK` appears successful, triggers `client.release(Error)`: node-postgres must discard the connection rather than put it back in the tenant pool.
4. Keep the earlier B15 protections: a pre-COMMIT callback error with a successful rollback returns a clean connection; a failed rollback destroys it and reports an `AggregateError` containing both errors. No automatic retry, external actions or production migrations.
5. Injected fault tests verify normal commit, callback exception, COMMIT exception with successful rollback, COMMIT exception with failed rollback, callback exception with failed rollback, bad tenant UUID and key identifiers, and canonical HMAC inputs.

## Security evidence and explicit limits

The unit tests are **fault-injection simulations** of the pool client. They do not constitute a real PostgreSQL forced-network-disconnect test or establish a transaction's final outcome after COMMIT uncertainty. A real protected network/TLS, database failover/recovery exercise and incident-oriented idempotency check remain external security gates.

The existing CI runs Node tests, PostgreSQL migrations and tenant RLS integration tests, CodeQL, synthetic Compose/recovery and the **unsuppressed Grype container security policy**. The known Alpine OpenSSL 3.5.9-r1 vulnerabilities remain release-blocking, and this PR does not claim to repair them.

No merge, deployment, release approval, paid service, live data or modification to the production database is authorised by B21.

# ProfitPilot B15 — Tenant connection-pool rollback containment

**Scope:** A defensive failure-mode correction for Node PostgreSQL tenant-scoped transactions. Draft only; no production environment or customer data was used.

## Defect

The previous tenant database transaction function issued ROLLBACK in its error path but always called client.release() without an error argument. If rollback itself failed because a connection became unhealthy or its session state was uncertain, the pool could be asked to reuse that connection. Since the transaction uses tenant-scoped LOCAL parameters and HMAC context, returning an unverified session to the pool is an unacceptable cross-tenant risk.

## Correction

- Keep all current short-lived tenant HMAC context, signature, timeout and transaction semantics.
- On a successful COMMIT, release the connection normally.
- When an application query fails and ROLLBACK succeeds, preserve the original error and release normally.
- When ROLLBACK fails for any reason, raise an AggregateError preserving both the initiating and rollback failures; explicitly call node-postgres client.release(Error) to discard the connection rather than reuse it.
- A small internal function accepts an injected pool solely so adversarial unit tests can simulate database failure without network access. The normal HTTP path still uses the single application pool; no HTTP-supplied pool is accepted.
- Tests verify successful execution, strict separation of failed rollback, uncertain COMMIT, HMAC/context calls and rejection of invalid subjects/secrets before acquiring a connection.

## Residual limits

The tests simulate connector failures; they are not a real network partition, actual SQL transaction fault injection, independent penetration test or proof of RLS under all concurrent loads. Existing authenticated PostgreSQL integration and Compose tests must still pass at the exact commit. The protected-image OpenSSL CVEs and all external production, legal, actual MFA, iPhone, storage and review gates remain blocked. There is no live deployment, paid service, merge, customer-data processing or financial-authority change.

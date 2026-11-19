# Tenant isolation and server-side authorization release gate

Status: BLOCKING / NOT PRODUCTION APPROVED
Base integration commit: 1f30cb0ef6dd75a6f05190a73335614ddd4ddfdd
Scope: all tenant-owned tables, API routes, background jobs, exports and object storage.

## Mandatory invariants
1. Every tenant-owned row has a non-null tenant_id; every cross-row relationship is constrained to the same tenant at the database level where applicable.
2. The runtime database role has no BYPASSRLS, table ownership or migration privileges; RLS is enabled and FORCEd for every tenant-owned table. No unscoped reads or writes.
3. The authenticated server establishes signed tenant/actor context transaction-locally, validates active membership and required permission for every operation, and rejects caller-supplied role or tenant assertions.
4. Every list, detail, create, update, delete, search, aggregate, export and background-job operation enforces tenant scope and object-level authorization. Deny by default.
5. Global identity data is self-only for runtime access; tenant membership and privilege changes require explicitly authorized administrative workflows and auditable events.
6. Private objects use tenant-scoped keys and authorization at both upload and download; signed URLs are short-lived, scoped, and revocable through access-control design.
7. Audit events bind the real authenticated actor, tenant, action, object and outcome, with integrity protections and no sensitive payload leakage.

## Required automated negative tests
- Tenant A actor cannot read, list, search, export, update, delete or infer tenant B data via direct API or SQL.
- Forged, missing, expired and revoked signed contexts fail closed.
- Removed tenant membership fails immediately; role downgrades deny privileged operations.
- Cross-tenant foreign-key inserts and reassignment attempts are rejected.
- Every API route is enumerated and checked for authentication, permission and tenant/object authorization, including nested routes, pagination and bulk operations.
- Worker and queue messages cannot switch tenant context or replay an elevated actor.
- Global users remain self-only and runtime writes fail.
- Error messages and timing-sensitive lookup responses do not reveal cross-tenant existence.
- Object download and upload paths reject cross-tenant access.
- Tests run under the actual restricted runtime role against PostgreSQL 16, not just privileged migration credentials.

## Evidence required to clear gate
- Machine-generated inventory of tenant tables, RLS/force flags, policies, FK edges, runtime grants and API endpoints.
- Exact tested commit SHA, CI run links, passing negative-test matrix and review of all exceptions.
- Independent review of production identity, storage, secrets, monitoring, backups, incident response and privacy controls.

## Explicit exclusions
Passing existing unit tests or a partial table audit does not clear this gate. Do not merge, deploy, ingest real customer/payroll data, process payments or claim certification on this document alone.

## Implementation sequence
1. Generate schema and endpoint inventories; identify missing RLS, composite FKs and permission checks.
2. Patch one gap per reviewable commit with adversarial regression tests.
3. Run full Node and PostgreSQL integration CI on the combined exact head.
4. Reconcile evidence and blockers before any release decision.

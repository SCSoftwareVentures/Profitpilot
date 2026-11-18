# Workflow integration readiness — 19 November 2026

Status: **planning and synthetic-data verification only**. Not an approval to build or deploy SaaS. G0–G4, competitive preconditions, and signed G5 GO remain mandatory under docs/PROJECT_STATUS.md.

## First vertical slice: invoice exception to traceable period report
Use synthetic, non-identifying records exclusively.

1. Authenticate an authorised tenant member; enforce least-privilege role and transaction-scoped tenant context on every operation.
2. Select contract, site, service period, currency and tax basis; reject missing or overlapping contract versions.
3. Submit synthetic invoice rows through existing JSON import scaffold with idempotency key; validate schema, dates, totals and duplicates. Do not imply secure file upload exists.
4. Persist and expose all rejected/unmatched rows and their reasons. Never auto-confirm a candidate.
5. Record explicit human match decisions with reviewer, source evidence and audit event; reject cross-tenant references and duplicate confirmations.
6. Calculate only supported eligible invoice and confirmed labour allocations. Disclose exclusions, residuals, source coverage and calculation version. Never label incomplete contribution as profit.
7. Render a synthetic read-only period report and source trace; unsupported figures must display **incomplete**, not zero.

## Acceptance gates
- [ ] Browser integration tests demonstrate steps 1–7 against an ephemeral API and PostgreSQL database, not static demo data alone.
- [ ] Cross-tenant reads/writes denied for every object in the slice, including indirect IDs and report exports.
- [ ] Role escalation, membership revocation, expired tokens, forged tenant context and pooled connection reuse tested.
- [ ] Import replay, malformed rows, oversized payloads and formula injection rejected or safely neutralised.
- [ ] Conflicting match decisions and simultaneous confirmations do not double count.
- [ ] Re-running a calculation on the same immutable source snapshot gives identical values and source references.
- [ ] Missing sources, unmatched invoices, partial payroll, currency/tax mismatches and reversed invoices are explicitly blocked or marked unsupported.
- [ ] Accessibility tests cover mobile viewport, keyboard focus, screen reader labels and error messaging.
- [ ] CI reports exact test totals and artifacts; failures block merge.

## Non-goals and release constraints
No live payments, payroll execution, customer-data ingestion, third-party integration or production deployment. No claim of Australian legal clearance or independent security certification. No merge to main without review. Any expansion into production-native SaaS implementation requires the existing signed G5 GO.

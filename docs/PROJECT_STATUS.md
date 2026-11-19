# ProfitPilot — Project Status

**Baseline:** V8.6.1 Master Product Blueprint, dated 16 November 2026  
**Repository:** working public project repository  
**Status:** product validation specification plus a partial API/database implementation scaffold; not a production application

## Current product decision

ProfitPilot's overall vision is a business operations and customer transaction-management platform. Its initial beachhead remains contract economics reconciliation and exception control for Australian independent commercial cleaning contractors with recurring multi-site B2B contracts.

The first delivery mode is a concierge validation service using secure, authorised data and manual/scripted reconciliation. The initial analysis unit is contract × site × service period.

## Current repository contents

- Product overview and scope
- G0–G6 validation gates
- Architecture and data-control principles
- Staged roadmap and initial risk register
- Static landing-page HTML concept
- Express API scaffold with JWT/JWKS authentication, tenant membership and role checks
- PostgreSQL schema, tenant RLS migration and ordered initialization scripts
- Import row persistence, invoice validation decisions, human-reviewed match decisions and evidence-gated calculation endpoints
- Node.js 22 engine tests and GitHub Actions CI
- PostgreSQL 16 schema/migration execution and HMAC-signed tenant RLS tests
- Authenticated HTTP API tests for membership, role restrictions, date validation and import idempotency
- Cross-tenant contract read/write negative tests, raw-GUC spoof rejection, HMAC signature/expiry/membership negative tests, private-key access denial, same-tenant actor foreign-key enforcement and pooled tenant-context cleanup test
- Production Docker image build and running-container database health smoke test
- Migration 008 narrows runtime writes to current endpoint operations, removes automatic grants on future tables and prevents runtime modification/deletion of raw evidence, calculation snapshots and audit events. Expanded tenant-table and foreign-object regression tests passed CI #2944 (commit bad8319).

- Import integrity: contiguous chunks, atomic conflict rejection, exact replay, serialized ingestion/validation and preserved review decisions; calculations use a consistent snapshot, full-period contract coverage and payroll currency checks. Regression tests passed CI #2945 and #2946. Source file hashes remain client-declared; original-byte verification is outstanding.

- Payroll prototype: structural validation, reviewer-attested controls, exact decimal whole-row allocations, residuals, tenant-scoped source lineage and duplicate reference rollback (migration 009). CI pending. Split allocations, independent source verification, database-only enforcement of allocation invariants, and statutory payroll compliance remain outstanding.

## What is not established

- Customer demand or willingness to pay
- Repeatable lawful access to customer data
- Production-grade native application implementation
- Production deployment, exhaustive tenant-isolation assessment and independent security certification
- Excel or Google Sheets equivalence for the audit workbook
- Live integrations
- Legal/privacy clearance
- Payment-provider approval or safeguarded-funds structure
- Production security or operational readiness

## Build-control rule

Do not treat repository setup, HTML concepts, documentation, or technical preparation as authorisation to build the SaaS.

Software build remains blocked until G0–G4 and competitive preconditions pass and G5 records an explicit signed GO with named technical ownership, legal/privacy plan, delivery capacity and approved budget.

G6 is a post-build paid software-pilot exit gate.

## Immediate next work

1. Prepare and run G0 data-feasibility and competitive-proof work.
2. Obtain at least five complete, authorised export sets from at least three unrelated businesses.
3. Use the G0 pilot pack to control scope, permissions, data minimisation, source lineage and effort measurement.
4. Produce one-site contract variance bridges and record pass/fail evidence.
5. Stop or pivot if no lawful, repeatable source path exists.

## Repository safety

This repository is public at the time this status file was written. Never commit customer exports, employee-identifiable records, confidential contracts, credentials, API keys, payment secrets or private source documents. Keep any real pilot data in an appropriately authorised, secure environment under documented terms.

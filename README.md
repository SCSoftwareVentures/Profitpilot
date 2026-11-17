# ProfitPilot

ProfitPilot is a proposed business operations and customer transaction-management platform. Its initial beachhead is contract economics reconciliation for Australian independent commercial cleaning contractors with recurring multi-site B2B contracts.

## Status

This repository is a working product specification and development foundation. Customer demand, payment-provider feasibility, legal and privacy clearance, production security, and production readiness have not been established.

## Initial validation approach

Begin with an evidence-led concierge workflow using authorised data. Validate data feasibility, customer pain, repeatability, willingness to pay, and usability before authorising a software build. Preserve the G0–G6 validation gates.

## Core controls

- Primary unit: contract × site × service period.
- Payroll is authoritative for pay-period payroll cost; site allocations remain management allocations unless supported by direct source evidence.
- Variations are candidates until explicitly approved.
- Invoice matches require human confirmation.
- AI may assist extraction and explanation, but must not authorise financial calculations, approvals, payments, disputes, or ratings.
- Never commit credentials, customer exports, employee records, or other sensitive information.

## Buyer trust and diligence pack

- [Buyer Trust Pack Index](docs/BUYER_TRUST_PACK_INDEX.md) — five-minute entry point for prospective acquirers.
- [Security, Trust & Privacy Overview](docs/BUYER_SECURITY_PRIVACY_OVERVIEW.md)
- [Security Architecture Diagram](docs/SECURITY_ARCHITECTURE_DIAGRAM.md)
- [Security & Privacy Control Evidence Matrix](docs/SECURITY_PRIVACY_EVIDENCE_MATRIX.md)
- [Preliminary Privacy Data Inventory](docs/PRIVACY_DATA_INVENTORY.md)
- [Audit Evidence Format](docs/AUDIT_EVIDENCE_FORMAT.md)

## Documentation

Further product, validation, architecture, roadmap and risk documentation will be added as the repository foundation is populated.


## Project documentation

- [Current project status](docs/PROJECT_STATUS.md)
- [G0 concierge pilot pack](docs/G0_CONCIERGE_PILOT_PACK.md)
- [Target architecture](docs/ARCHITECTURE.md)
- [Initial threat model](docs/THREAT_MODEL.md)
- [Release and test plan](docs/RELEASE_AND_TEST_PLAN.md)

## Data, calculation and workflow specifications


- [Canonical data dictionary](docs/DATA_DICTIONARY.md)
- [Core calculation specification](docs/CORE_CALCULATION_SPEC.md)
- [Core UX workflows](docs/UX_WORKFLOWS.md)

## Application prototype and implementation


- [Identity and tenant security plan](docs/IDENTITY_AND_TENANT_SECURITY.md)
- [PostgreSQL schema scaffold](database/schema.sql)
- [Prototype calculation/import engine](src/engine.js)
- [Interactive application prototype](app/index.html)
- [Browser test runner](tests/index.html)

## API, test fixtures and release controls


- [Core API contract (OpenAPI)](api/openapi.yaml)
- [Fictional development seed data](database/seed_demo.sql)
- [Synthetic invoice CSV fixture](tests/fixtures/invoices_demo.csv)
- [QA verification matrix and release gates](docs/VERIFICATION_MATRIX.md)

## Backend and development

- [Local development guide](docs/LOCAL_DEVELOPMENT.md)
- [Implementation audit and defect register](docs/IMPLEMENTATION_AUDIT.md)
- [Database migrations](database/migrations/)
- [GitHub Actions CI](.github/workflows/ci.yml)

The API and database are implementation scaffolds, not a deployed service. Review the audit and development guide before attempting to run them.

## Visual prototypes

- [Simplified dashboard concept](demo/dashboard.html) — responsive static HTML with fictional placeholder figures; no live data or connected services.
- [Landing-page concept](index.html) — static presentation concept.

These prototypes are for design review only. They are not a deployed product or evidence of implemented business workflows.

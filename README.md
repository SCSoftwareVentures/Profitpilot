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

## Architecture specification baseline A1

[Complete internal design package and requirement catalogue](docs/specification/README.md) — target design, not a completed application or production approval.

## Security and privacy handover
[Protected deployment requirements, privacy lifecycle and independent review gates](docs/SECURITY_PRIVACY_HANDOVER.md). Main-branch CI includes encrypted synthetic recovery, native scanner fixture testing, dependency inventory and source package provenance. Review corresponding run before relying on any claimed result.

## Evidence-first buyer walkthrough (synthetic B1 draft)

- [Standalone buyer walkthrough](demo/buyer-walkthrough.html) — dependency-free HTML with fictional figures, visible source references, source completeness gates and simulated human-review choices. This file is not a deployed SaaS or proof of customer demand.
- [Buyer B1 operating and due-diligence notes](docs/BUYER_WALKTHROUGH_B1.md) — initial vs completed arithmetic, verification scope and unverified acquisition conditions.
- [Auditable demo calculation logic](src/buyer-walkthrough-core.js) — deterministic cents-based contract economics scenario, with tests and a reproducible standalone build.

To verify the packaged demo in a Node.js 22 source review environment: `npm test` and `npm run check`. Production security, real customer identity, legal/payment clearances and independent iPhone browser tests remain outstanding.

## B2 guided buyer review and mobile acceptance

The [offline interactive buyer walkthrough](demo/buyer-walkthrough.html) now guides the visitor through three evidence states and offers an on-page, selectable JSON summary when a mobile browser cannot download the export. [B2 device acceptance protocol](docs/BUYER_DEVICE_ACCEPTANCE_B2.md) separates automated CI checks from **unperformed actual iPhone/WebKit tests**. Do not describe this UI as mobile-certified or customer-validated.

## B3 portable buyer evaluation handoff

The reviewed B3 branch packages the **fictional, standalone** walkthrough as a short-lived GitHub Actions artifact named \`profitpilot-fictional-buyer-demo-<commit-sha>\`. Its workflow only packages files **after the existing Node, PostgreSQL/recovery, CodeQL, and container-security checks pass**. The package contains exactly four files: executable local HTML, a plain-language evaluation guide, a commit-specific manifest, and SHA-256 checksums.

A reviewer needs no working server, domain or customer account to inspect the artifact. On iPhone, whether a downloaded local HTML file can run inside Safari depends on the device and opening workflow; this has **not** been tested on a physical iPhone. The file can alternatively be inspected as source; that does not constitute a UI test. There is no public hosting or deploy action. CI artifacts expire after seven days, whereas the source HTML remains in the repository.

The checksums detect modifications relative to the package manifest but are **not** a trusted-publisher signature. Actual buyer validation, licence/ownership audit, independent legal/security review and customer willingness-to-pay evidence remain mandatory before any honest market-sale valuation.

## B4 aggregate G0 feasibility evaluator

The [B4 G0 feasibility engine](src/g0-feasibility.js) computes explicit pass/fail/exclusion outcomes for pseudonymous aggregate export-set records, with [adversarial regression tests](tests/g0-feasibility.test.js) and [evidence limitations](docs/G0_FEASIBILITY_ENGINE_B4.md). This is not a validated pilot, actual demand, verified independent-source permission or authorisation to build the SaaS. G0 remains externally blocked even if declared numeric thresholds are met.

## B5 mobile buyer walkthrough overflow correction

The [B5 layout investigation and test boundary](docs/BUYER_MOBILE_LAYOUT_B5.md) documents a content-sized grid defect discovered with an actual headless Chromium interaction run, its minmax/min-width CSS correction and new regression tests. Browser-emulated widths passed locally; real iPhone/WebKit and assistive-technology QA remain unperformed.

## B6 reproducible acquisition inventory (draft)

The [B6 buyer source and dependency audit](docs/BUYER_ACQUISITION_B6.md) explains how the offline `npm run audit:buyer` command inventories tracked file hashes, npm lockfile licences and outstanding IP, customer-demand, accessibility and production clearance gates. No library metadata, CI success or fictional demonstration establishes transfer rights or a production-ready application.

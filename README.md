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

## Visual prototypes

- [Simplified dashboard concept](demo/dashboard.html) — responsive static HTML with fictional placeholder figures; no live data or connected services.
- [Landing-page concept](index.html) — static presentation concept.

These prototypes are for design review only. They are not a deployed product or evidence of implemented business workflows.

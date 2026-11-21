# ProfitPilot B1 — Evidence-first buyer walkthrough

**Status:** synthetic, local-only, non-production, unmerged draft. **Purpose:** let an acquirer examine a concrete contract-economics workflow rather than assume static dashboard figures are supported by source evidence. B1 is an honest demonstration, **not** evidence of demand, product-market fit, financial/legal authority, or a live SaaS.

## What a buyer can do

Open the standalone demo/buyer-walkthrough.html in a browser. It is a single HTML file with embedded CSS and a deterministic JavaScript engine: no account, server, external JavaScript, API call, external font, uploads, cookies or local storage. The strict Content-Security-Policy prohibits network connections.

The fictional October 2026 Australian-dollar scenario begins with three contracts. Riverside has a held $500 invoice candidate; Northside has a $600 unallocated payroll-pool residual; Harbour has a separate $2,000 *unapproved* variation excluded from billing.

The walkthrough shows three important controls:

1. **Source completeness affects what can be stated:** whole-portfolio confirmed billed, delivery costs, and contribution are shown as **Unavailable** until the required evidence categories are complete; they never silently become $0.
2. **Human review is simulated, never invented:** a fictional confirmation of the Riverside invoice match changes confirmed billed coverage; a fictional Northside allocation moves $600 from a residual to a site cost while preserving the payroll-pool total. Actions are explicitly labelled simulated, remain local to the browser, and generate a sequence-labelled on-screen decision history. Neither action authenticates an actual reviewer or verifies an issuer.
3. **Unapproved scope never becomes revenue:** the Harbour $2,000 variation stays excluded. The demo does not offer a pretend payment, contract approval, legal adjudication, live user, or real business credential.

| Calculation (AUD) | Initial state | After both fictional reviewer actions |
| --- | ---: | ---: |
| Whole-portfolio billed total | Unavailable | $45,000 |
| Partial confirmed billed (clearly incomplete) | $44,500 | $45,000 |
| Whole-portfolio delivery costs | Unavailable | $31,300 |
| Unallocated payroll residual | $600 | $0 |
| Authoritative fictional payroll pool | $26,800 | $26,800 |
| Whole-portfolio contribution | Unavailable | $13,700 |
| Excluded, unapproved variation | $2,000 | $2,000 |
| Contracts with both source categories complete | 1 of 3 | 3 of 3 |

Calculation basis: deterministic integer cents, with *confirmed billed* as a document-supported concept within the fictional scenario, not a conclusion that revenue has been recognised under any accounting standard. Delivery costs are only the fictional allocated payroll and materials; operating overhead, tax, superannuation and other costs are not represented. Contribution is not net profit. Baselines and source IDs are synthetic.

## Inspection and reproducibility

- Product logic: src/buyer-walkthrough-core.js
- Browser/UI source: demo/buyer-walkthrough.shell.html
- Reproducibly generated, portable output: demo/buyer-walkthrough.html
- Generator: scripts/build-buyer-walkthrough.mjs
- Regression tests: tests/buyer-walkthrough.test.js

Commands in a suitable Node.js 22 review environment: npm test; npm run check. The latter verifies that the checked-in standalone file is an exact result of the source and shell, instead of a manually modified presentation. These commands are for buyer/reviewer reproducibility and do not require the current user to own a computer or set up infrastructure.

Tests check the incomplete and completed financial bridges, payroll source conservation, withheld totals, action replay/forgery refusal, exclusion of the unapproved variation, explicit no-production claims, and a small emulated-DOM click path. This **does not** substitute for real iPhone Safari/WebKit accessibility or performance testing, a professional usability study, a third-party security test, or independent financial-method validation.

Export action: local JSON with the current fictional snapshot, listed source identifiers, in-memory reviewer action history, precise readiness gates and explicit warnings. It contains no authentic customer data, signed custody evidence, or protected financial authority. The export is a demo takeaway, **not** a legally valid audit artifact.

## Acquisition due-diligence position

| Buyer question | Current evidence | Outstanding proof |
| --- | --- | --- |
| Can a buyer try the workflow without credentials? | Single-file interactive fictional demo | Real user testing on supported devices |
| Can incomplete records be distinguished from zero? | B1 implementation and negative regression assertions | Independent code/UX review |
| Is a deterministic calculation present? | Versioned integer-cents domain engine and tests | Independent accounting and industry-rule review |
| Are source IDs and decisions visible? | Fictional source references and local decision sequence | Genuine issuer identity, permission, persisted source lineage and audit |
| Does the demo process private customer data? | No upload or external network path designed | Independent static/browser assessment |
| Is the product complete and sellable at a target valuation? | Not established by this technical demonstration | Customer interviews, paid demand, buyer discussions, deployment proof, ownership/license audit and legal clearance |

## Commercial and release boundary

This work intentionally excludes live integrations, customer/employee records, invoices uploaded from real operations, payroll award compliance, actual billing authority, payments, real legal-hold workflows and public deployment. Production deployment and external hosting are separate permissions. Existing security/dispute prototype branches are **draft and stacked**; main remains a prior baseline until separately reviewed and merged. The open validation gates G0–G5 in docs/PROJECT_STATUS.md remain relevant: a polished demo is not customer evidence.

Potential buyer story: ProfitPilot does not merely **show** an attractive contribution number; it explains **why a number is unavailable**, what would make it supportable, which source references were consulted, and what a reviewer decision changes. Treat this as a testable hypothesis until real customers validate it.

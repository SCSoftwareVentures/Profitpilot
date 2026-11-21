# ProfitPilot B2 — Buyer tour and mobile-device acceptance protocol

## Scope / evidence grade

Status: **synthetic buyer walkthrough, implementation submitted for CI; physical iPhone Safari testing NOT PERFORMED**. This document deliberately separates automated static/Node emulation from actual mobile-device behaviour. The source remains a stacked draft PR; no production, external hosting, public payments, real identity, or customer data access is authorised.

### Buyer experience delivered

The portable, dependency-free demo now presents a **three-stage, state-derived guided walkthrough**:

1. **Spot the evidence gap.** An unmatched $500 invoice means the full invoiced portfolio position is withheld; click the fictional Riverside invoice confirmation.
2. **Account for every payroll dollar.** Although invoices are now complete, the Northside $600 payroll residual prevents a full-period delivery cost and contribution; click its fictional allocation.
3. **Review the contribution—and its limits.** The demo reveals fictional $45,000 confirmed billed, $31,300 delivery costs, and $13,700 contribution, while a $2,000 Harbour variation remains excluded pending authorisation.

The stage text derives from the same deterministic decision state as the financial numbers; it cannot advance without the corresponding simulated review. This is *not* proof a real invoice or payroll expense is verified. There is no persisted reviewer identity, decision or operational system.

The JSON evidence summary is now also displayed in a user-selectable **on-page details element**, allowing inspection and copying even if local HTML file downloads are restricted by a mobile browser. The normal JSON download action is retained. No clipboard permission, data upload, external dependency, user tracking or new payment authority is introduced.

### Automated B2 gates

- Run npm test and npm run check, which include tests/buyer-walkthrough.test.js (simulated DOM clicks), tests/buyer-mobile-acceptance.test.js (responsive/accessibility/static guardrails), tests/engine.test.js (existing computation guard), reproducible standalone build and all existing backend/security tests.
- Pass PostgreSQL migration and tenant isolation job, signed synthetic backup/recovery CI, CodeQL with zero findings, and dependency/container vulnerability scan.
- Treat passing CSS/static tests and a fake-DOM click simulation as **partial assurance only**. They cannot prove real iPhone/WebKit behaviour or screen-reader accessibility.

### Actual iPhone acceptance protocol (UNTESTED)

These checks require an actual iPhone and have **not** been executed or claimed to pass. The owner can assess them from the ChatGPT iPhone app by viewing an authorised locally delivered HTML artifact, or a reviewed preview if one becomes available later. Merely viewing GitHub source does not execute HTML.

| ID | Manual task | Expected result | Verification status |
| --- | --- | --- | --- |
| IOS-01 | Open standalone HTML from a supported local workflow | No missing styles, scripts or blocked modules; visible synthetic-only banner | **Not tested on iPhone** |
| IOS-02 | Examine portrait layout at standard text size | All buttons usable, no clipped text, tables scroll within card | **Not tested on iPhone** |
| IOS-03 | Increase iOS text size / accessibility setting | Content reflows without overlapping the decision buttons | **Not tested on iPhone** |
| IOS-04 | Activate fictional invoice review | Tour advances to step 2, billed figure $45,000, contribution unavailable | **Not tested on iPhone** |
| IOS-05 | Activate fictional payroll allocation | Tour advances to step 3, contribution $13,700, residual $0, variation excluded | **Not tested on iPhone** |
| IOS-06 | Open evidence JSON fallback and select text | All synthetic source references and review events are readable without file download | **Not tested on iPhone** |
| IOS-07 | Attempt JSON file export via browser UI | On successful download, expected JSON file is present; on failure, on-page fallback still works | **Not tested on iPhone** |
| IOS-08 | Reset scenario and repeat steps in reverse order (payroll first) | Source readiness must remain truthful; contribution cannot appear until both resolved | **Not tested on iPhone** |
| IOS-09 | VoiceOver and Voice Control test | Headings, buttons, labelled source details and state updates are understandable | **Not tested on iPhone** |
| IOS-10 | Landscape orientation and low-memory repeat actions | No horizontal page overflow outside scrollable table and no stale decision state | **Not tested on iPhone** |

A passed CI run does **not** close IOS-01–10. Screenshots, a device/version record and observed outcome per test are necessary before declaring real mobile compatibility.

### Buyer-diligence positioning and risks

**Supported by code (subject to CI and independent review):** deterministic fictional cents arithmetic, source evidence coverage indicators, state-derived tour guidance, simulated decisions, a no-network single-file HTML package, local selectable evidence export, clear unapproved variation exclusion.

**Unsupported:** paying customer demand, legal/industry accounting compliance, mobile Safari QA, actual supplier source authenticity, production authentication, privacy assessment, production disaster recovery, audited financial outcomes, real signed reviewer approvals and live payment operations.

**Acquisition gate:** Treat the walkthrough as a marketing/technical demonstration only. Before setting an asking valuation or telling buyers it is ready for deployment, obtain at least three independent prospect walk-throughs, collect objections without prompting, document whether they want the feature, seek concrete paid interest, audit all core dependencies/licensing, and reconcile the stacked draft security PRs into a controlled release branch under human review.

This protocol has no hidden background testing and no automatic external publication.

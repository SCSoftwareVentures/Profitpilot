# ProfitPilot — iPhone-First MVP Screen and Workflow Specification

**Status:** proposed interaction specification; no screens in this document are implemented.  
**Primary device:** iPhone Safari / supported iOS browser.  
**Design objective:** a calm, high-trust financial control centre. Prioritise clear status, evidence, next action and safe review over dense dashboards.

## 1. Navigation model

First-release primary navigation:
- Overview
- Contracts
- Imports
- Exceptions
- Reports
- Settings

Use a compact bottom navigation for the five most frequent destinations and a clearly discoverable secondary route for Settings where screen width requires it. Do not add marketplace, payments, ratings, broad CRM or full job management to the first-release navigation.

The six long-term differentiators share common primitives—stable records, audit history, templates, permissions, evidence and search—but are staged separately from the initial financial reconciliation wedge.

## 2. Global design rules

1. Every financial value displays currency, period and basis; tax basis is explicit where relevant.
2. Every headline figure has a visible route to source coverage, included records, exclusions and calculation version.
3. Unknown is not zero. Incomplete is not “all clear”.
4. Candidate, confirmed, approved, rejected, excluded and restated states are visually and semantically distinct.
5. AI suggestions are visibly labelled as suggestions and cannot execute approval actions.
6. Destructive or irreversible actions require a clear confirmation and a safe recovery path.
7. No financial approval is completed by swipe gestures, accidental tap or client-side-only control.
8. Tables become labelled cards or compact row summaries on narrow screens; do not hide key values behind horizontal scrolling.
9. Touch targets, focus, type scaling and screen-reader labels meet the WCAG 2.2 AA target.
10. Status is never communicated by colour alone; use text, iconography and accessible labels.

## 3. Screen specifications

### UX-01 — Workspace setup

**Purpose:** establish business context and initial supported workflow.

Fields: business name, industry, operating model, business size band, number of active sites, primary timezone, reporting currency, user role and intended workflow.

Behaviours:
- Select the commercial-cleaning template only when that operating model matches.
- Show a clear “not yet supported” path for other workflows; do not silently force their data into cleaning assumptions.
- Explain what data is needed and why before the first import.
- Invite a second reviewer and configure role separation where available.
- Record terms/permission acceptance as an event; it does not replace a data-processing agreement or legal review.

### UX-02 — Overview

**Purpose:** show current period health and next action.

Top area:
- selected contract/site/service period;
- data completeness status;
- calculation version and last refreshed timestamp.

Primary metrics, only when their inputs are sufficiently complete:
- eligible revenue;
- included delivery costs;
- management contribution before separately disclosed residuals/exclusions.

Below:
- prominent incomplete/held banner if any required source is absent;
- source coverage summary;
- highest-priority exceptions with owner and due date;
- recent decisions/restatements.

Never show a blank or missing input as $0.00. When not calculable, replace the metric with “Unavailable — missing source” and a route to the missing item.

### UX-03 — Contracts and sites

**Purpose:** manage commercial baseline and operating scope.

List card: customer, contract reference, active sites, service frequency, current version and status.

Detail sections:
- approved scope and exclusions;
- billing basis, price, currency and GST basis;
- site/service-period schedule;
- source references and attachments;
- change history and approvals.

Changing price or scope creates a new version. The old baseline remains accessible and calculations must identify which version they used.

### UX-04 — Imports

**Purpose:** control source intake.

Flow:
1. Choose source type and period.
2. Read the purpose and minimum-data notice.
3. Record authority/permission reference.
4. Register metadata and source checksum.
5. Where secure file storage exists, upload to quarantine and wait for validation/scanning.
6. Review row counts, duplicate status, source totals and parse exceptions.
7. Continue only when the batch state explicitly permits the next action.

Do not display “Uploaded” where only metadata has been registered. A registration-only state must say “Source registered — original file not stored here.” No original payroll/invoice file should be handled until private storage, scanning and retention controls are live and approved.

### UX-05 — Import review and mapping

Show each held row with:
- source row reference;
- raw value and parsed value separately;
- proposed customer/contract/site;
- evidence for the mapping;
- ambiguity/conflict reason;
- reviewer action: accept, reject or hold.

Batch-level summary:
- source row count;
- accepted, held, excluded and duplicate counts;
- source and parsed monetary control totals;
- unreconciled difference;
- mapping/parser version.

If control totals do not reconcile, keep the batch blocked. Never hide rows merely to make the totals match.

### UX-06 — Payroll allocation ledger

Show authoritative pay-period pool total first. Then five mutually exclusive buckets:
- Direct-coded
- Approved allocated
- Non-site
- Unallocated residual
- Explicitly excluded

Each source row opens an evidence detail view. Approved allocation requires method, destination, amount, source reference, reason and authorised reviewer. The user can preview proposed allocations but cannot confuse a proposal with a confirmed allocation.

Before confirmation, show row-level remaining balance, pool reconciliation difference and any over-allocation. Confirmation is denied if any row or pool invariant fails.

### UX-07 — Invoice matching

Candidate card shows customer, contract, site, service period, source line, amount, currency, tax basis and evidence dimensions independently.

States:
- Candidate
- Conflict / held
- Confirmed
- Rejected
- Duplicate / superseded

A match candidate is not counted in coverage until an authorised reviewer confirms it. Amount-only similarity cannot be portrayed as high-confidence evidence. The final coverage view shows numerator, denominator, policy version and exclusions.

### UX-08 — Variations

Capture requested/observed changes with description, date, source evidence and estimated impact if supportable. Show approval authority and state.

Keep the following distinct:
- requested;
- observed;
- candidate;
- approved;
- rejected;
- completed;
- invoiced;
- reconciled.

Do not add candidate value to approved revenue or billable totals. Retrospective approval preserves both event time and approval time.

### UX-09 — Exceptions

Each exception card states:
- what is missing, conflicting or unreconciled;
- affected contract/site/period;
- source evidence and confidence limitation;
- amount or range only if supportable;
- recommended next action;
- assigned owner and due date;
- status and closure evidence.

No exception should claim fraud, non-compliance, negligence or recoverable profit without supporting evidence and human review.

### UX-10 — Reports

A report header identifies business, contract, site, service period, currency, tax basis and calculation version.

Report sections:
1. Data coverage and completeness.
2. Contract baseline.
3. Invoice evidence and eligible match coverage.
4. Payroll pool and five-bucket allocation.
5. Supplier/other delivery costs.
6. Variation state and approved value.
7. Management contribution, only when valid.
8. Exceptions, assumptions and exclusions.
9. Source lineage and reviewer decisions.

Exports preserve the same caveats and identifiers as the on-screen report and are formula-injection safe.

### UX-11 — Settings, access and audit

Show users, tenant memberships, roles, active sessions, export access, notification settings and audit events subject to permissions. Do not expose secrets or raw sensitive payloads in logs.

High-impact permissions and changes require step-up authentication where the security design specifies it.

## 4. Universal states and failure handling

| State | User message intent | Required action |
|---|---|---|
| New workspace | “No verified data yet” | Guide to baseline and approved source bundle |
| Registered, not uploaded | “Metadata registered; original file not stored” | Explain secure file intake is unavailable until implemented |
| Incomplete | “This period is incomplete” | Show missing sources and suppress definitive metrics |
| Held | “Review required” | Show exact row/evidence/reason |
| Unreconciled | “Totals do not match” | Block confirmation and report difference |
| Conflict | “More than one plausible match” | Human review; no auto-confirm |
| Permission denied | “You do not have permission” | No disclosure of restricted record existence/details |
| Offline | “Changes not yet synced” | Queue only safe idempotent drafts; no offline financial approval |
| Sync conflict | “A newer version exists” | Show both versions and require deliberate resolution |
| Calculation failure | “No result was produced” | Preserve diagnostic reference; do not display stale figure as current |
| Restated | “A newer calculation replaces this view” | Preserve prior run and explain reason/version |
| No exceptions found | “No exceptions detected in available data” | Never imply the data is complete or risk-free |

## 5. iPhone interaction and accessibility acceptance

- Test current supported iPhone viewport sizes and Safari versions defined by the test owner.
- Verify safe-area insets, on-screen keyboard, browser zoom and dynamic text.
- Critical actions use full-width controls and clear labels, not tiny icon-only targets.
- Confirm screen-reader reading order and accessible form validation.
- Charts have text summaries and accessible tabular alternatives.
- Error messages identify the field or record and a recovery action.
- Focus remains visible after modals and route changes.
- No status depends solely on colour.
- Interrupted import, backgrounding, app reload and network loss never silently duplicate or lose an accepted source event.
- Offline approval and money movement are prohibited.

## 6. Usability test tasks

Moderated participants should complete without facilitator rescue:
1. Identify why one service period is incomplete.
2. Locate the authoritative payroll total and unallocated residual.
3. Explain why an invoice candidate is not a confirmed match.
4. Find a requested but unapproved variation.
5. Trace a report value to the source and calculation version.
6. Export a traceable period report.
7. Explain what the product does not know.

Record task result, time to first correct insight, errors, facilitator rescue, confidence and participant comments. G4 thresholds remain defined in the master completion register.

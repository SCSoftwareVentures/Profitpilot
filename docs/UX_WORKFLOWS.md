# ProfitPilot — Core UX Workflows

**Status:** workflow specification for design and usability testing; not implemented.

## Design principle
A calm financial control centre, not a crowded administration suite. Users should quickly understand business position, source coverage and the next action requiring attention.

## Initial navigation
Overview · Contracts · Imports · Exceptions · Reports · Settings.

Do not add marketplace, jobs, payments, reviews or customer CRM navigation to the first release.

## Overview
Show only three headline metrics when the period is sufficiently complete:
1. Eligible revenue
2. Delivery costs
3. Contribution before separately disclosed residuals/exclusions

Below: one primary trend chart, a short ranked exception list and compact contract/site snapshot. Every figure reveals period, calculation version, coverage and source basis. Unsupported figures show incomplete/unavailable, not invented estimates.

## Import workflow
1. Select source type and approved period.
2. Confirm permission/authority and data scope.
3. Upload minimum required export.
4. Validate file type, size, schema and period.
5. Show row counts, source totals, duplicates and parse exceptions.
6. Review mapping candidates and unresolved identities.
7. Accept, reject or hold each mapping.
8. Create immutable source snapshot and audit event.
9. Allow mapping reversal through a new version; raw source remains unchanged.

No silent deletion, silent auto-acceptance or hidden unmatched rows.

## Contract baseline
Select business, contract and site; attach source reference and contract version; record approved scope, price, billing basis, service period, exclusions, tax basis and currency; identify missing inputs; confirm a baseline version. Changes create a new version; old baseline remains accessible.

## Labour allocation
Select authoritative payroll pool and period; validate source total; review direct-coded site amounts; review proposed allocation method; separate non-site and unallocated residuals; preview reconciliation invariant; block confirmation if allocation exceeds eligible pool or fails reconciliation; record method, assumptions, reviewer and audit event.

## Invoice matching
Import lines and reconcile to invoice total; generate evidence-linked candidates; show identity, amount, date and period evidence separately; hold ambiguous/conflicting records; require human confirm/reject/pending decision; only confirmed matches count toward coverage.

## Variation
Capture observed/requested change and evidence as candidate; identify authorised approver; record approved/rejected scope and price; link delivery and invoice evidence; reconcile approved amount to billing. Unapproved candidates are never billable revenue.

## Exception management
Each exception states what is inconsistent/missing, supporting source records, confidence, supportable amount/range, available action, owner/due date and closure evidence. Use neutral states; reserve warning emphasis for consequential issues.

## Empty and error states
- New account: explain first step; do not show zero as verified.
- Incomplete period: label incomplete and list missing inputs.
- No match: show unmatched, not zero revenue.
- Failed import: preserve batch/error report and allow safe retry.
- Permission revoked: stop access and explain retention/deletion policy.
- Calculation failure: show no result and preserve diagnostic/source refs.
- No exceptions: say none detected in available data, not risk-free or compliant.

## Accessibility and mobile
Responsive mobile-first tables, keyboard access, visible focus, screen-reader chart labels, status not conveyed by colour alone, suitable touch targets. WCAG 2.2 AA is a proposed acceptance target.

## Usability test tasks
Find a material contract variance; trace its sources; find unallocated payroll residual; resolve ambiguous invoice candidate; identify unapproved variation; export a traceable period report; explain what the dashboard does not know. Record task success, facilitator rescue, time, errors and user confidence.

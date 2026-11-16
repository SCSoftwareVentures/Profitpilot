# ProfitPilot — Concierge Pilot Execution Playbook

**Status:** operational protocol and evidence template; not permission to collect data or begin a pilot.  
**Goal:** test real customer pain, source feasibility, repeatability, usefulness and willingness to pay before authorising software build.

## 1. Pilot sequence

Do not combine all validation into one vague “pilot”. Run the evidence stages separately:

1. **G0 data feasibility:** five complete, authorised export sets from at least three unrelated businesses and hands-on competitive/customer-stack proof.
2. **G1 problem discovery:** 20 interviews across three channels, unaided problem first.
3. **G2 workflow feasibility:** three concierge trials across three businesses, with at least two real decisions informed or changed.
4. **G3 paid demand:** ten qualified buying conversations and three paid concierge engagements or commitments.
5. **G4 prototype usability:** eight moderated sessions, six completing core tasks without rescue and median first insight within 30 minutes.
6. **G5 build GO:** explicit signed decision after prior gates, named owner, legal/privacy plan, delivery capacity and budget.

A business can contribute to more than one gate only when the evidence is independently recorded and the gate's requirements are met. Do not count a friendly conversation as a paid commitment or a synthetic dataset as customer feasibility evidence.

## 2. Customer qualification

A candidate business should match most of the initial hypothesis:
- Australian independent commercial cleaning operator;
- recurring B2B contracts;
- multiple customer sites or materially different service periods;
- accessible owner or operations/finance decision-maker;
- current use of payroll/timesheet and invoicing/accounting systems;
- willingness to describe a recent reconciliation problem;
- ability to provide a narrow, authorised source export if a data feasibility exercise is separately approved.

Record inclusion/exclusion reason. Do not recruit only founder friends; G1 founder-network share must remain <=40%.

## 3. Interview protocol

### Before the call
- Explain that this is discovery, not a product sale or a promise of savings.
- Record participant role, business segment, recruitment channel and consent to notes.
- Do not ask for credentials, live system access or unsolicited sensitive exports.

### Unaided questions
1. Walk me through the last time you checked whether a recurring contract was financially performing as expected.
2. What triggered that review?
3. Which systems or files did you use?
4. What did you have to reconcile manually?
5. What was missing, duplicated, ambiguous or disputed?
6. How long did the work take, and who performed it?
7. What decision did you make as a result?
8. What happened when the figures did not agree?
9. How often has a similar issue happened in the last 90 days?
10. What did the problem cost in time, delayed decisions, missed billing or other measurable impact?
11. What workaround or existing software do you use?
12. What have you already tried or paid for?

Only after unaided pain has been explored should the interviewer show the proposed workflow. Record reactions as reactions, not evidence of pre-existing pain.

### Evidence classification
- **Observed:** directly seen in a permitted workflow or artefact.
- **Reported:** participant's statement about a past event.
- **Measured:** timed or reconciled using an agreed method.
- **Hypothesis:** interviewer interpretation not yet confirmed.
- **Disconfirming:** evidence that weakens the proposed problem or segment.

## 4. Data feasibility operating controls

Before any real export transfer:
- confirm the business representative's authority;
- agree purpose, minimum fields, source period and data categories;
- identify personal/employee information and minimise it;
- complete a written permission/handling record;
- establish secure private transfer and storage outside the public repository;
- define access, retention, deletion/return and incident contact;
- obtain required legal/privacy review and contractual terms;
- identify subprocessors and cross-border processing as applicable.

If a required control is unavailable, do not receive or process real data. Do not upload real customer exports, employee records, payroll, invoices, credentials or contracts to the public GitHub repository, this conversation, or an unapproved environment. The present API only registers metadata and JSON rows; it is not a secure original-file intake system.

## 5. G0 workflow run

For each unique business × source period × bundle:

1. Create an opaque export-set ID and record authority/permission reference.
2. Verify minimum source components: contract/scope, payroll or timesheet, supplier/subcontractor cost evidence where applicable, customer invoice lines.
3. Record source filename, checksum, row count, period, currency and declared tax basis in the secure evidence register.
4. Establish authoritative source totals and parser/mapping versions.
5. Produce one-site contract baseline and payroll reconciliation.
6. Classify payroll source rows using direct-coded, approved allocated, non-site, unallocated and explicitly excluded buckets.
7. Review invoice match candidates using customer/contract/site/service-period/amount/currency/tax evidence; human-confirm only.
8. Produce a variation register and exception/action list.
9. Reconcile source row counts and monetary control totals.
10. Record customer and analyst handling minutes separately, plus waiting time and rework.
11. Have an independent reviewer challenge the denominator, exclusions, source lineage and expected values.
12. Mark PASS only when every per-set G0 condition is met.

A bundle is incomplete if a material required source is missing or source authority is unclear. It cannot be rescued by assumptions or synthetic data.

## 6. Standard customer deliverable

Deliver a controlled report containing:
- agreed scope, period and limitations;
- contract baseline and version;
- source bundle inventory and permission reference;
- source row-count and monetary-control reconciliation;
- payroll pool, five allocation buckets and residual;
- eligible invoice denominator, confirmed numerator and evidence coverage;
- supplier/other cost components and missing categories;
- requested/observed/approved/rejected variations separately;
- management contribution only if complete and comparable;
- exceptions, evidence, responsible owner, due date and customer decision;
- analyst/customer minutes, rework and unresolved limitations;
- customer acknowledgement and outcome.

Do not label a management contribution as net profit, audited profit, statutory profit or tax profit. Do not claim recovered revenue or savings unless the customer outcome is verified.

## 7. G2 usefulness test

For each of the three businesses:
- agree one real decision the output could inform before analysis;
- capture the customer's starting position;
- present the output and trace supporting evidence;
- record whether the customer changed, confirmed or rejected the intended decision;
- capture what evidence changed their mind;
- measure analyst/customer effort and time-to-insight;
- ask whether the output is worth repeating and why.

G2 requires at least two of three businesses to confirm that the output informed or changed a real decision. Positive sentiment alone is insufficient.

## 8. G3 paid concierge test

Conduct ten qualified buying conversations with the actual decision-maker or budget holder. Offer a clearly defined paid engagement with fixed scope, deliverable, data-handling terms, timing and fee.

Record:
- offer shown and exact scope;
- quoted price and any discount;
- buyer role and authority;
- objection and reason;
- paid/committed/declined/no-decision outcome;
- next step and date;
- whether the commitment is binding or merely verbal interest.

Three paid concierge engagements or commitments are required. Do not conflate free trials, letters of interest, verbal enthusiasm or unapproved purchase intentions with paid demand.

## 9. Effort and quality scorecard

| Measure | Calculation |
|---|---|
| Payroll attribution % | (direct-coded + approved allocation) / eligible authoritative pool, with exclusions disclosed |
| Invoice match coverage % | eligible invoice value with medium/high evidence and human-confirmed mapping / total eligible invoice value |
| Source row reconciliation | source row count = accepted + held + explicitly excluded + duplicate-handled rows under the approved counting rule |
| Monetary difference | authoritative source total minus accepted + held + excluded totals under a declared basis |
| Customer effort | preparation + review minutes, separately recorded |
| Analyst effort | active handling minutes, separately recorded |
| Rework | additional handling minutes and repeated steps caused by corrections |
| Time to first insight | elapsed moderated time from starting task to first correct, evidence-supported conclusion |
| Decision utility | customer-confirmed decision informed/changed, with specific decision and rationale |

No denominator or exclusion may be changed after observing the result without documenting a new version and restating the result.

## 10. Stop, pivot and escalation rules

STOP:
- no lawful data route;
- source totals cannot be reconciled consistently;
- no repeatable method for key payroll or invoice records;
- material customer harm or confidentiality risk;
- customer decision requires a statutory/audit conclusion the product cannot support.

PIVOT:
- one export source repeatedly blocks the workflow but another narrow source is viable;
- target segment uses a materially different data stack or purchasing process;
- output does not inform the expected decision but a different evidenced problem emerges.

ESCALATE:
- suspected data exposure, security incident, unauthorised processing, unexpected employee-sensitive content or a material calculation defect. Stop processing and follow the approved incident route.

## 11. Evidence record template

For each trial capture: evidence ID; pseudonymous business ID; participant role; recruitment channel; permission record ID; scope and dates; source inventory; row/monetary controls; parser/mapping/policy versions; reviewer; customer and analyst minutes; outcomes; objections; limitations; decision informed/changed; payment/commitment status; deletion/return confirmation; and next action.

The playbook is not legal advice and does not authorise data collection. Obtain qualified privacy/legal review and approved handling controls before any real export is transferred.

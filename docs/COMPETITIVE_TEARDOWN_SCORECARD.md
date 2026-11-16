# Competitive Teardown and Customer-Stack Scorecard

**Status:** validation instrument; no competitor findings or customer claims are recorded here.
**Purpose:** make G0 competitive proof repeatable, comparable and resistant to confirmation bias.
**Use:** complete one scorecard per product or actual customer tool stack. Use the same scenario, source bundle, operator profile and timing rules wherever practicable.

## 1. Evidence rules

- Record what was directly observed, what was stated by a vendor/customer, and what remains unknown as separate evidence classes.
- A marketing page is discovery evidence, not proof that a capability works in practice.
- Do not mark a capability absent because it was not found in a short demonstration. Use **not tested** or **not evidenced**.
- Record product edition, plan, add-ons, configuration, integrations, date tested and operator skill. A feature available only through a costly add-on must not be represented as included in the base plan.
- Keep screenshots, notes and source references only where collection and retention are authorised. Do not place customer records, personal data, credentials or confidential screenshots in this public repository.
- Never infer a competitor's security posture from marketing language. Record independently verified controls, vendor claims and unknowns separately.
- Do not score a vendor's feature list in isolation. Score the complete workflow and the human effort needed to produce a reliable outcome.

## 2. Standard test scenario

Use a synthetic scenario with:
- one recurring multi-site commercial cleaning contract;
- at least two sites and two service periods;
- a versioned scope and pricing schedule;
- synthetic payroll/timesheet records with direct-coded, approved-allocated, non-site and unallocated amounts;
- supplier/subcontractor cost lines;
- customer invoice lines including clear matches, ambiguous matches, duplicates and unmatched items;
- one requested but not yet approved scope variation;
- one source-period mismatch and one missing-data condition.

Keep the same source records, expected totals, tax basis, rounding rules and task instructions across tests. Store the synthetic fixture and expected-answer key separately from any real customer material.

### Required operator tasks

1. Identify what data must be imported and configure the workflow.
2. Establish the contract, site and service-period baseline.
3. Reconcile source row counts and monetary totals.
4. Attribute labour without forcing non-site or unallocated cost into a site.
5. Match eligible invoice value and explain uncertain/unmatched lines.
6. Identify the unapproved variation without treating it as billable.
7. Produce a traceable one-site variance bridge.
8. Export the result and explain how the business can retrieve or leave with its data.

Record task completion, errors, facilitator intervention, active operator minutes, elapsed waiting time, rework and unresolved exceptions.

## 3. Capability scorecard

Use the scale below for each dimension. Add a short evidence note and source reference; a number without evidence is invalid.

| Score | Meaning |
|---|---|
| 0 | Tested and failed, or demonstrably unavailable for the tested configuration |
| 1 | Possible only through substantial manual work, workaround or specialist intervention |
| 2 | Partially supported; material limitations or manual controls remain |
| 3 | Completed reliably in the tested workflow with traceable evidence |
| NT | Not tested |
| NE | Not evidenced; do not treat as absent |

| Dimension | What to test | Score | Evidence / limitation |
|---|---|---:|---|
| Source coverage | Can the tested configuration obtain the required contract, labour, supplier and invoice data? |  |  |
| Setup effort | Time, skill and configuration required before first useful result |  |  |
| Contract/site/period model | Can records be related without ambiguous or lossy mapping? |  |  |
| Labour attribution | Are direct, approved allocation, non-site and unallocated amounts distinguished? |  |  |
| Invoice reconciliation | Are candidate matches, confidence/evidence and unmatched items visible? |  |  |
| Variation control | Is requested scope change distinguished from authorised and billable change? |  |  |
| Traceability | Can a reviewer navigate from result to source, transformation and decision? |  |  |
| Exception handling | Are missing, conflicting, duplicate and out-of-period records safely held? |  |  |
| Audit history | Are actors, timestamps, versions and material changes retained? |  |  |
| Mobile workflow | Can the required tasks be completed on a phone at realistic field conditions? |  |  |
| Resilience | Are retry, duplicate submission, sync conflict and recovery behaviours clear? |  |  |
| Access and privacy | Are role boundaries, data minimisation, export, retention and deletion evidenced? |  |  |
| Data portability | Can the business export usable records and preserve identifiers/history? |  |  |
| Total cost | Subscription, add-ons, implementation, training, integrations and internal labour |  |  |
| Operational fit | Does it fit the customer's actual roles, systems and approval process? |  |  |

Do not sum scores into a league table unless a later, documented method establishes defensible weights and minimum evidence. A high average must not hide a critical failure in data integrity, privacy, auditability or portability.

## 4. Measurement record

| Measure | Result | Method / notes |
|---|---:|---|
| Operator profile and experience |  |  |
| Configuration and onboarding minutes |  |  |
| Customer preparation minutes |  |  |
| Active operator minutes |  |  |
| Elapsed waiting time |  |  |
| Facilitator rescue count |  |  |
| Rework minutes |  |  |
| Source rows expected / processed |  |  |
| Monetary total expected / reconciled |  |  |
| Labour pool attributable under approved basis |  |  |
| Eligible invoice value matched with medium/high evidence |  |  |
| Material unresolved exceptions |  |  |
| Export/exit test result |  |  |
| Plan, add-ons and estimated total annual cost |  |  |

State denominator, exclusions, tax treatment, currency and rounding method. Do not report a percentage without its numerator and denominator.

## 5. Actual customer-stack assessment

For each of at least two target customers, map the real workflow without collecting unnecessary confidential data:

- Systems used for contracts/scope, rostering/timesheets/payroll, supplier costs, accounting/invoicing and document storage.
- Which system is authoritative for each source field and who owns it.
- Manual exports, spreadsheets, duplicate entry and reconciliation steps.
- Where identifiers, periods, sites or scope versions fail to line up.
- How exceptions are found, reviewed, approved and retained.
- Current time and labour cost, frequency and consequence of the problem.
- What the customer has already tried, including configuration or add-ons.
- What would cause the customer to change, and what would prevent a change.
- Required integrations, data permissions, procurement/security review and switching costs.

Record the customer's words separately from the analyst's interpretation. Ask for a recent concrete example before describing ProfitPilot. Do not lead the customer toward a claimed gap.

## 6. Material-gap evidence

A candidate gap is not validated merely because a competitor lacks a named feature. To count toward G0, the evidence should establish:

1. A recurring, recent and material customer problem.
2. The current workflow and tools have been fairly tested, including reasonable configuration and available add-ons.
3. The problem remains despite those tools or the customer has a quantified reason not to use the available solution.
4. The consequence is measurable (time, cost, risk, missed billing, delayed decision or another explicit outcome).
5. At least two independent target customers describe substantially the same gap without being prompted by the proposed solution.
6. At least one identifiable buyer confirms willingness to pay for solving the problem, with the proposed buying conditions recorded.

If a gap is solved by ordinary configuration, training or a lower-cost existing tool, record that honestly. It may invalidate the product hypothesis rather than create a reason to build.

## 7. Per-product / per-stack evidence header

Copy this block for every assessment:

- Assessment ID:
- Product or customer-stack pseudonym:
- Assessment date:
- Assessor:
- Product edition / plan / add-ons:
- Configuration and integrations:
- Operator role and experience:
- Scenario and fixture version:
- Evidence permission / handling reference:
- Test duration:
- Tasks completed:
- Critical failures:
- Unresolved unknowns:
- Total cost assumptions and period:
- Overall finding: supports current workflow / partial fit / material gap evidenced / inconclusive
- Independent reviewer:
- Review date:

## 8. G0 decision summary

| Requirement | Evidence reference | Result |
|---|---|---|
| Five relevant product teardowns |  | Not assessed |
| Two actual customer-stack assessments |  | Not assessed |
| Two independent customers evidence same material recurring gap |  | Not assessed |
| At least one buyer confirms willingness to pay |  | Not assessed |

**Decision rule:** this scorecard supplies evidence; it does not change G0 thresholds. Missing evidence is **not assessed**, not a pass. Do not claim competitive advantage, product-market fit or customer demand from this template.

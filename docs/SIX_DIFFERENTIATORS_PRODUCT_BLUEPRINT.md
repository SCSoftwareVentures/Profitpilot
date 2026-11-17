# ProfitPilot — Six Differentiators Product Blueprint

**Status:** owner-approved for staged repository implementation and synthetic/test-environment demonstration. No production, real-data or launch authorisation is implied.
**Date:** 16 November 2026
**Scope:** translate the six differentiators previously approved by the founder into bounded product concepts, dependencies, safety rules and validation tests. This document does not claim that any capability is implemented or customer-validated.

## 1. Strategic constraint

ProfitPilot's first commercial hypothesis remains an evidence-led contract-economics workflow for Australian independent commercial cleaning contractors with recurring, multi-site B2B contracts. The initial analysis unit is contract × site × service period.

The owner has authorised continued implementation of these six differentiators as part of preparing the complete project for sale. Build them in a staged, coherent sequence with synthetic fixtures, deterministic tests, explicit evidence states and human approval boundaries. G0–G5 remain mandatory before production deployment or real sensitive-data processing, but do not block repository-level feature engineering or synthetic demonstrations.

The first demonstrable product should remain coherent around contract economics, evidence, exceptions and business commitments. Do not dilute the initial buyer story with a marketplace, full workforce scheduling suite, payroll/award engine, accounting replacement, autonomous approval agent or payment processing. Longer-term expansion should be clearly separated from the initial product scope.

## 2. Six approved differentiators

### 2.1 Job Readiness Engine

**Purpose:** establish whether a job or service commitment is sufficiently defined and resourced before a business accepts or starts it.

**Conceptual workflow**
1. Capture the proposed work, customer, location, requested outcome and timing.
2. Compare the proposal with the information required for that work category.
3. Identify missing scope, access, materials, skills, timing, price, dependencies, permissions and evidence requirements where applicable.
4. Show readiness as explicit satisfied, missing, conflicting, unverified or not-applicable checks.
5. Assign an owner and next action for each blocking gap.
6. Permit a responsible human to proceed with a recorded override and rationale where policy allows.

**Integrity rules**
- A readiness score is a completeness indicator, not a guarantee of safety, profitability, legal compliance or successful delivery.
- Never silently infer missing contractual scope or customer consent.
- Trade- and industry-specific templates must be configurable; similar job types may reuse templates, while materially different industries and corporate workflows need distinct requirements.
- A template version used for a commitment must be preserved with that job.

**Validation:** measure preventable clarification loops, incomplete commitments detected before acceptance, false blockers, override rates and time-to-ready. Validate against real user workflows before selecting a score or threshold.

### 2.2 Promise Ledger

**Purpose:** create a durable, searchable record of commitments made between a business and its customer, including who made each commitment, what was agreed, when it is due and whether it was fulfilled.

**Conceptual record**
- commitment ID and tenant;
- parties and authorised actors;
- originating quote, job, contract or change request;
- precise promise, scope and exclusions;
- due date/time and applicable timezone;
- owner and responsible party;
- acceptance/acknowledgement evidence;
- status, updates, exceptions and outcome;
- immutable event history and source references.

**Integrity rules**
- Distinguish proposed, communicated, accepted, changed, fulfilled, missed, disputed and cancelled commitments.
- A message sent is not proof that the recipient received or accepted it.
- Changes append a new event/version; do not rewrite the historical promise.
- Keep internal tasks distinct from promises made to customers.
- Notify only through authorised channels and respect communication preferences and retention limits.

**Validation:** test whether users can reliably retrieve commitments, identify overdue obligations and resolve disagreements using the record. Measure missed commitments and time spent reconstructing conversation history.

### 2.3 Profit Leak Radar

**Purpose:** surface evidence-backed exceptions that may be eroding contract contribution or causing avoidable commercial loss.

**Initial evidence domains**
- contract price versus invoice outcome;
- approved scope versus observed/requested variations;
- confirmed invoice coverage and unmatched lines;
- direct, allocated, non-site and unallocated labour;
- supplier/subcontractor costs where supported;
- credits, duplicate candidates and period mismatches;
- missing source data and unresolved mapping conflicts.

**Integrity rules**
- Separate verified amount, candidate amount, estimate and unknown.
- Explain each alert with source records, calculation version, assumptions, confidence and recommended human review.
- Do not label a candidate as recovered revenue, savings, fraud, overcharging or verified profit.
- Suppress or qualify alerts when coverage is inadequate or periods/tax bases/currencies are incompatible.
- AI may explain and prioritise evidence; deterministic, versioned calculations remain authoritative.

**Validation:** measure precision and recall of material exceptions against expert-reviewed cases, false-positive burden, time-to-resolution and whether an alert changed a documented decision. Do not optimise for alert volume.

### 2.4 Verified Value Ledger

**Purpose:** maintain a traceable record of value claimed, agreed, delivered, accepted, invoiced and financially realised, without collapsing those different states into one headline number.

**Conceptual value states**
- proposed value;
- quoted value;
- contractually accepted value;
- approved variation value;
- delivered value supported by evidence;
- customer-accepted value;
- invoiced value;
- credited/refunded value;
- provider-confirmed settled value, only in a later legally/provider-approved payment domain.

**Integrity rules**
- Every value event must link to its source, actor, time, currency, tax basis and relevant scope/version.
- Customer acceptance, invoice issue, payment capture, payout instruction and bank settlement are distinct events.
- A photograph, completion declaration or AI extraction is evidence to review, not automatic proof of satisfactory work or value.
- Preserve disputed, partially accepted, credited and reversed values; never silently net them away.
- Do not claim verified savings, profit or funds held unless the evidence and legal/provider structure support that exact claim.

**Validation:** test reconciliation from agreement through delivery and invoice, quantify unresolved value differences, and confirm that users understand the difference between operational, contractual and realised financial value.

### 2.5 SwitchProof Migration

**Purpose:** make it practical for a business to move into ProfitPilot without losing access to its source records, history, identifiers or confidence in the migrated data.

**Conceptual workflow**
1. Inventory source systems, exports, fields, record counts, date ranges and permissions.
2. Profile completeness, duplicates, malformed values, conflicting identifiers and unsupported fields.
3. Map source fields to a versioned canonical model with explicit confidence and exceptions.
4. Preview transformations and reconciliation totals before acceptance.
5. Run a reversible trial migration using minimised, authorised data.
6. Obtain human sign-off on mapping exceptions and reconciliation.
7. Preserve source manifests, checksums, mapping version, migration report and rollback/exit path.

**Integrity rules**
- No silent destructive overwrite, automatic identity merge or irreversible migration.
- Unknown values remain unknown; do not fabricate defaults.
- Keep source identifiers and lineage.
- Define exportability and a documented exit path before onboarding.
- Secure file upload, private object storage, malware scanning, retention/deletion and backup controls are prerequisites before handling real sensitive exports.

**Validation:** use synthetic fixtures first, then appropriately authorised and minimised pilot data only after privacy/security controls are approved. Measure reconciliation accuracy, exception rates, migration effort and successful rollback/export.

### 2.6 Field Knowledge Memory

**Purpose:** preserve useful, permissioned operational knowledge so businesses do not repeatedly rediscover site-specific requirements, customer preferences, access instructions and proven procedures.

**Potential knowledge classes**
- site and customer operating requirements;
- approved scope clarifications and exclusions;
- access and induction requirements;
- equipment/material constraints;
- recurring issue and resolution history;
- safety or compliance documents supplied by an authorised source;
- lessons learned and procedure versions.

**Integrity rules**
- Every item has an owner, source, date, scope, visibility, review/expiry date and confidence.
- Distinguish verified instructions, customer preferences, observations, suggestions and unverified notes.
- Never convert a one-off observation into a universal rule.
- Restrict sensitive access details and personal information; apply least privilege and retention limits.
- Surface stale or conflicting knowledge for review rather than silently choosing one.
- AI retrieval must cite the underlying approved record and must not invent site instructions.

**Validation:** test retrieval accuracy, freshness, user correction, time saved during repeat work and the rate of stale or unsafe instructions surfaced. A knowledge item is not authoritative merely because it was used previously.

## 3. Shared platform foundations

The six capabilities should share common primitives rather than become six disconnected products:

1. **Permanent searchable records:** every job, commitment, decision, evidence item, exception and outcome receives a stable ID and auditable history. Search respects tenant and role permissions.
2. **Industry-aware templates:** onboarding selects an industry and operating model; templates are versioned and configurable. Similar workflows can share templates without forcing materially different trades or enterprise processes into one model.
3. **Event history:** material changes append actor, timestamp, reason, prior/new state and source references.
4. **Evidence provenance:** source, permission basis, confidence, reviewer and transformation history remain discoverable.
5. **Human authority:** AI can extract, explain, suggest and prepare; it cannot approve scope, confirm financial matches, adjudicate disputes or move money.
6. **Mobile-first resilience:** design for phone workflows, intermittent connectivity and safe retry. Offline actions require conflict detection, idempotency and visible sync state before any implementation is approved.
7. **Privacy by design:** data minimisation, explicit access scopes, purpose limitation, retention, export and deletion are part of each workflow.
8. **Accessible UX:** target WCAG 2.2 AA; status must not rely on colour alone.

## 4. Sequencing and dependencies

This is a proposed sequence for validation and later authorised design, not a commitment to build all six at once.

| Sequence | Capability | Dependency / rationale |
|---|---|---|
| Foundation | Permanent records, identity, permissions, audit, search, templates | Required across all six; must be designed and validated first |
| First wedge | Contract/site/service-period economics, quotes/costing/variations/invoices, mobile-safe workflows | Existing beachhead; subject to G0–G5 |
| Early differentiators | Job Readiness Engine, Promise Ledger, Profit Leak Radar | Closest to preventing incomplete commitments, forgotten obligations and evidenced margin leakage |
| Later differentiators | Field Knowledge Memory, Verified Value Ledger | Depend on durable jobs, evidence, customer acceptance and source lineage |
| Migration capability | SwitchProof Migration | Required for scalable onboarding; real-data workflow depends on secure storage and privacy controls |
| Separately gated | Payment orchestration and provider-confirmed value settlement | Written legal and provider approval, safeguarded-funds analysis, ledger/reconciliation and operational controls |

Do not force these capabilities into the initial contract-economics release. Their order may change only when customer evidence demonstrates a stronger priority and the change is recorded.

## 5. Product acceptance framework

Before any feature advances beyond concept:
- named user and material problem are evidenced;
- workflow and non-goals are documented;
- source data and lawful permission basis are identified;
- acceptance criteria are measurable;
- failure modes, abuse cases and human override are specified;
- privacy, security, accessibility and audit requirements are reviewed;
- support, retention, export and deletion are defined;
- unit economics and operational burden are understood;
- customer testing confirms usefulness.

For implementation, definition of done includes code, tests, migrations/rollback, security/privacy controls, audit events, accessible mobile UX, error states, documentation and operational support. A specification is not implementation evidence.

## 6. Decisions preserved

- The six differentiators are approved for inclusion in the long-term ProfitPilot product blueprint.
- Permanent, searchable job and commitment records are a core requirement.
- Signup should configure industry-appropriate templates; similar job types may share templates while different trades and corporate workflows retain distinct requirements.
- The initial commercial beachhead remains contract economics for recurring multi-site commercial cleaning.
- Concierge-first validation and G0–G5 build controls remain binding.
- No real customer, employee, payroll, invoice or confidential commercial data belongs in this repository.
- No production deployment, payment processing or external customer data access is authorised by this document.


## Implementation record — Job Readiness Engine foundation

A first synthetic/test-only domain implementation is provided in `src/job-readiness.js` with unit coverage in `tests/job-readiness.test.js`. It evaluates a versioned checklist using explicit satisfied, missing, conflicting, unverified and permitted not-applicable states. A satisfied check that requires evidence cannot pass without a safe evidence reference. Missing answers remain unverified. The result is either blocked or ready for a human decision; the engine never grants approval or claims a safety/profitability guarantee.

This is a domain foundation only. It is not yet integrated with persisted jobs, site templates, permissions, attachments, audit history or a user-facing workflow. Those remain separate implementation tasks.


## Implementation record — Promise Ledger foundation

A synthetic/test-only state-machine implementation is provided in `src/promise-ledger.js`, with transition and evidence tests in `tests/promise-ledger.test.js`. The prototype enforces a proposed → communicated → accepted progression, explicit evidence for material state changes, unique event IDs, timezone-aware timestamps, chronological append order and terminal fulfilled/cancelled states. It does not send communications or treat a sent message as proof of customer acceptance.

The browser demonstration includes a synthetic Promise Ledger timeline. Persistence, authenticated actor attribution, event-store/database enforcement, customer notification integrations, search, due-date workflows and a complete user-facing review process remain unimplemented.


## Implementation record — Profit Leak Radar foundation

A synthetic/test-only evaluator is provided in `src/profit-leak-radar.js` with unit tests in `tests/profit-leak-radar.test.js`. It classifies a potential exception only when the supplied record has a recognised exception type, positive canonical money, explicit currency/tax basis/period, evidence references and a caller-declared complete source-coverage state. When coverage or any required dimension is missing, monetary exposure is withheld. Even a complete candidate has `verifiedLoss: null` and `recoveredValue: null`; human review remains mandatory.

The dashboard demonstrates one candidate and one incomplete-coverage exception. The caller's coverage declaration is not independently certified by this primitive. Persistence, source-manifest verification, domain-specific detection rules, reviewer workflow and measured alert precision/recall remain outstanding.


## Implementation record — Verified Value Ledger foundation

A synthetic/test-only event model is provided in `src/verified-value-ledger.js`, with tests in `tests/verified-value-ledger.test.js`. It records quoted, contracted, variation-approved, delivered, customer-accepted, invoiced, credited, refunded, settled and disputed amounts as distinct event types. Each event requires a stable scope, currency, tax basis, period, actor/source identifiers, timezone-aware timestamp, reason and evidence reference. Summaries remain partitioned by scope and reporting dimensions. Unrecorded states return `null`, not zero; credits/refunds remain separate and no net total is produced.

The dashboard includes a synthetic lifecycle table. This is not independent verification of customer acceptance, delivery, invoicing or bank settlement. Durable database persistence, authenticated actor attribution, source reconciliation, reviewer controls and reversal/restatement workflows remain unimplemented.


## Implementation record — SwitchProof Migration foundation

A pre-migration profiler is provided in `src/switchproof-migration.js` with synthetic tests in `tests/switchproof-migration.test.js`. It requires a source manifest, permission reference, checksum, expected row count, explicit mapping version, source-key mapping, required-field mappings, currency/tax basis/period and source control total. It detects duplicate source keys, missing required values, malformed amounts/dates, currency mismatches, row-count differences and control-total mismatches. The output contains exception codes and row numbers, not raw source row content.

A passing profile means only that the supplied synthetic/in-memory rows reconcile to the supplied metadata and declared mappings. It does not independently verify the checksum or permission, copy data, approve mappings or perform a migration. Durable quarantine, private storage, malware scanning, reversible transformation, target reconciliation and human migration approval remain outstanding.

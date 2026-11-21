# ProfitPilot B4 — Aggregate G0 feasibility evaluator (draft)

**Purpose:** Turn the G0 data-feasibility thresholds into deterministic checks without collecting payroll, contract or employee source files. This is an evidence-administration helper, not proof of a successful pilot, demand, certified security or permission to build the SaaS.

## Implemented

- Pure, non-networked ESM evaluator in src/g0-feasibility.js, with adversarial and boundary tests in tests/g0-feasibility.test.js.
- Accepts at most 100 aggregate export-set records with pseudonymous keys, source period, bundle key, declared authorisation/completeness and, when available, nonnegative integer cents and time measurements.
- Each complete, unique, authorised set passes only with positive payroll and invoice denominators, at least 80% payroll attribution using a declared approved allocation basis, at least 80% invoice matching with declared medium/high evidence, customer time at most 120 minutes, analyst time at most 180 minutes, and affirmative source-row, monetary, tax and rounding reconciliation flags.
- Duplicate export-set IDs and duplicate business × period × bundle keys exclude **all** colliding records; no arbitrary first-record preference. Missing metrics, zero denominators and incomplete reconciliations fail rather than become zero or 100%.
- Aggregate numeric thresholds: at least five unique complete authorised export sets, at least three pseudonymous business keys and at least 80% of eligible sets passing *every* per-set check.
- Competitive counts are separate declarations: five hands-on product teardowns, two actual customer stacks, two independent recurring gaps and one buyer declaring willingness to pay.

## Critical boundaries

A passing numeric comparison is NOT G0 approval. The evaluator always outputs independentlyVerified=false, demandValidated=false, softwareBuildAuthorized=false and g0Decision=BLOCKED_PENDING_INDEPENDENT_EVIDENCE_REVIEW. G1–G5, signed build authorisation, source permission and buyer willingness remain separate external evidence gates.

A declared authorisation flag or quality score is NOT authenticated. Neither competitor review evidence nor underlying exports are checked by this engine. No real customer or employee data should be placed in this prototype. It only accepts aggregate amounts and restricted pseudonymous keys; even compliant-looking keys can conceal identifying information. Appropriate authority, lawful transfer, review and retention remain externally required.

## Input contract

The evaluateG0 function accepts a plain object with exactly two properties, sets and competition.

Each set has exactly exportSetId, businessKey, period (YYYY-MM), bundleKey, authorized, complete and metrics. Metrics is either null or an object with payrollPoolCents, payrollAttributableCents, invoiceEligibleCents, invoiceMatchedCents, customerMinutes, analystMinutes and the following six Boolean declarations: rowCountsReconciled, monetaryTotalsReconciled, taxBasisDocumented, roundingDocumented, allocationBasisApproved, matchedEvidenceMediumHigh.

Competition has productsTested, customerStacksTested, independentCustomerGaps and buyersConfirmingWillingness, all bounded whole-number counts. All money inputs are integer cents; exact BigInt cross multiplication avoids accidentally rounding 79.99% to 80%.

The output identifies source-set exclusions, per-record failed checks and overall declared numeric threshold outcomes. No persisted evidence, identity verification, audit signature, production API, payment workflow or new hosting has been introduced.

## Tests and handover

The regular npm test command automatically picks up tests/g0-feasibility.test.js. The CI branch security, PostgreSQL, container and buyer-package checks must still be reviewed at the exact commit before claiming this branch tested. Buyer B3 remains a fictional four-file offline demonstration and does not dynamically incorporate this B4 module.

A prospective acquirer must examine the five authorised export-set dossiers, independent business identities, consent evidence, competitor teardown records, actual target-customer objections, paid commitments, IP/license inventory and named technical/legal owners. This module proves only that the **declared G0 threshold arithmetic and fail-closed bookkeeping are executable and testable**.

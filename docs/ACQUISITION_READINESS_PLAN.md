# ProfitPilot — Acquisition Readiness Plan

**Purpose:** prepare ProfitPilot as a transferable software asset for a potential outright sale, licence or strategic acquisition.
**Owner's commercial objective:** explore a possible sale in the AUD 30,000–50,000 range. This is an aspiration, not an appraisal, market-supported valuation or buyer commitment.
**Budget constraint:** AUD 500 maximum initial spend and AUD 100 maximum recurring monthly spend unless the owner explicitly changes those limits.
**Evidence rule:** never claim a feature, control, certification, customer, revenue or valuation that has not been verified.

## 1. Intended asset

The intended asset is a well-documented, demonstrable and technically coherent software product focused initially on contract-economics reconciliation and exception control for Australian independent commercial cleaning contractors with recurring multi-site B2B contracts.

A buyer should receive enough material to understand the product, run it in a controlled environment, assess its limitations, continue development and decide independently whether to commercialise it.

The product must not be described as a deployed SaaS business, accounting system, payroll processor, audited financial product or production-ready service unless the relevant evidence exists.

## 2. Acquisition-readiness workstreams

### AR-01 — Product completeness
- Implement and demonstrate the agreed initial workflows end to end.
- Remove dead ends, placeholder controls and misleading success states.
- Provide a synthetic demonstration environment with clearly labelled sample data.
- Keep unsupported industries and out-of-scope functions explicit.
- Maintain a feature inventory distinguishing implemented, partial, planned and blocked capabilities.

**Exit evidence:** buyer can follow the core product journeys without developer intervention; known limitations are visible.

### AR-02 — Financial correctness
- Complete the DEC, TAX, PAY, PAYLED, INV, CON, VAR and IMP acceptance coverage.
- Preserve decimal-string monetary boundaries and exact-cent arithmetic.
- Make currency, tax basis, reporting period, source coverage and policy version explicit.
- Preserve unknown, zero, negative, held, candidate, confirmed and excluded states.
- Never produce a definitive contribution or margin from incomplete material sources.
- Obtain qualified review for accounting, payroll and tax assumptions before representing outputs as dependable financial results.

**Exit evidence:** traceable acceptance results, synthetic golden fixtures, explicit policy decisions and independent expected-result review.

### AR-03 — Security and privacy
- Close code-level security findings and retain exact-head CI evidence.
- Complete private file storage, quarantine, malware scanning, access controls, retention and deletion before any real source-file intake.
- Complete production identity, MFA, managed secrets, shared rate limiting, audit, backups, monitoring and incident response before production operation.
- Obtain independent penetration testing and remediation retest.
- Obtain Australian privacy/legal review for intended data and customer segments.

**Exit evidence:** independent reports, remediation records and operational evidence. Automated CI alone is insufficient.

### AR-04 — Transferability and intellectual property
- Create a complete inventory of source code, product specifications, designs, documentation, trademarks, domains and other assets actually owned or controlled.
- Record contributors, employment/contractor arrangements, assignments and permissions.
- Inventory every direct and transitive dependency, licence and notice.
- Identify third-party services, credentials and accounts that cannot be transferred automatically.
- Confirm the repository and its history contain no secrets, customer data or confidential third-party material.
- Prepare a transfer checklist for repositories, domains, cloud accounts, signing keys, build pipelines and support handover.

**Exit evidence:** a qualified reviewer can establish chain of title and identify all transfer restrictions. Do not imply that repository possession alone proves ownership of every asset.

### AR-05 — Reproducible engineering handover
- Maintain a supported runtime and locked dependencies.
- Document local setup, environment variables, migrations, seed data and test commands.
- Record architecture, trust boundaries, data flows, APIs, deployment assumptions and operational runbooks.
- Preserve CI results against exact commit SHAs.
- Provide a known-issues register and prioritised roadmap.
- Demonstrate a clean setup from a fresh clone using synthetic data.

**Exit evidence:** an independent engineer can reproduce the build and tests and explain the system without relying on the original developer.

### AR-06 — Commercial evidence
- Validate the target customer and recurring problem through structured interviews.
- Obtain evidence of workflow feasibility and willingness to pay.
- Test pricing assumptions and the cost to serve.
- Record competitor comparisons and the product's defensible differentiation.
- Do not present survey interest, informal compliments or hypothetical subscription revenue as actual traction.

**Exit evidence:** documented customer evidence, quantified outcomes and a defensible commercial thesis. Customer evidence may materially improve buyer confidence but must be obtained with appropriate consent and privacy controls.

## 3. Buyer information pack

Prepare a controlled data room containing:
1. Executive product overview and target customer/problem.
2. Live or recorded synthetic product demonstration.
3. Feature inventory and workflow map.
4. Architecture and data-flow diagrams.
5. API/OpenAPI documentation and database schema/migrations.
6. Exact-head CI history and financial acceptance traceability.
7. Security/privacy posture, independent assessments and open risks.
8. Dependency and open-source licence inventory.
9. IP ownership and contributor assignment records.
10. Product roadmap, effort estimates and known blockers.
11. Customer discovery, pilot outcomes and commercial evidence where authorised.
12. Transfer, deployment and post-sale handover plan.

No personal, payroll, customer, invoice, credential or confidential business records belong in a public repository or an unapproved buyer pack.

## 4. Potential transaction structures

- **Asset sale:** transfer the agreed source code, IP rights and specified assets for a negotiated price.
- **Exclusive licence:** retain ownership but grant a buyer defined exclusive commercial rights, territory, field or term.
- **Non-exclusive licence:** license the product to multiple parties under defined conditions.
- **Strategic acquisition/partnership:** combine an upfront payment with a defined development or commercial arrangement.

Any transaction requires qualified legal and tax advice. The agreement should define exactly what is transferred, third-party exclusions, warranties, liabilities, support period, payment conditions, escrow/holdback and any earn-out measurement.

## 5. Valuation discipline

The AUD 30,000–50,000 objective is a negotiation target only. No valuation is established by this plan.

A buyer's offer will depend on factors including:
- completeness and quality of the actual software;
- technical debt and remaining development cost;
- security, privacy and legal exposure;
- ownership and transferability of IP;
- evidence of customer demand and willingness to pay;
- differentiation versus building or buying alternatives;
- strategic fit, integration cost and buyer urgency.

An unlaunched product may receive a low offer or no offer. Do not spend money solely to make a target valuation appear plausible.

## 6. Financial guardrails

- Initial project spend must not exceed AUD 500.
- Recurring monthly spend must not exceed AUD 100.
- Prefer existing repository, CI and no-cost development facilities.
- No paid agency, marketing campaign, certification, cloud commitment or subscription without explicit owner approval.
- Record actual costs and renewals; cancel or avoid services that are not essential.
- Independent security, legal and accounting reviews are recognised external funding gates, not assumed to fit inside the current budget.

## 7. Release and authority boundary

Acquisition preparation does not authorise production deployment, customer data intake, payroll ingestion, customer communications, payments, merge to the protected production branch or transfer of ownership.

The owner retains authority over any external contact, buyer disclosure, repository access grant, sale, licence, assignment, merge or deployment.

**Current state:** acquisition readiness is a development objective. All workstream exit evidence must be recorded separately; this document does not assert that any workstream is complete.

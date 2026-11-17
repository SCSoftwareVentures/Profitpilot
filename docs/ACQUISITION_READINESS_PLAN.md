# ProfitPilot — Acquisition Readiness Plan

**Purpose:** prepare ProfitPilot for an outright sale or strategic acquisition as a complete, demonstrable, technically coherent and transferable software asset. The owner does not intend to launch or operate the product as a standalone business.
**Commercial objective:** maximise evidence-backed strategic value. AUD 30,000–50,000 was an initial reference target, not a ceiling, minimum, appraisal, market-supported valuation or buyer commitment. No predetermined upper valuation limit is set.
**Budget direction:** the owner has removed the previous AUD 500 initial / AUD 100 monthly project budget caps. Product scope and engineering priorities must not be constrained by those former caps. This does not authorise purchases, paid subscriptions, contractor engagements, external services or other financial commitments; obtain the owner's explicit approval before incurring actual spend.
**Evidence rule:** never claim a feature, control, certification, customer, revenue or valuation that has not been verified.

## 1. Intended asset

The intended asset is a well-documented, demonstrable and technically coherent software product focused initially on contract-economics reconciliation and exception control for Australian independent commercial cleaning contractors with recurring multi-site B2B contracts.

A buyer should receive a coherent, working demonstration and reproducible engineering package, with enough source, architecture, test evidence and handover material to evaluate, run, extend and commercialise the asset without depending on the current owner. Optimise for transferability and buyer confidence rather than preparing the owner to operate a live SaaS business.

The product must not be described as a deployed SaaS business, accounting system, payroll processor, audited financial product or production-ready service unless the relevant evidence exists.

## 2. Acquisition-readiness workstreams

### AR-01 — Product completeness
- Implement and demonstrate the coherent core workflows end to end, with realistic synthetic fixtures.
- Remove dead ends, placeholder controls, broken navigation and misleading success states.
- Provide a polished buyer-facing demonstration that runs reliably from documented setup instructions.
- Keep unsupported industries and out-of-scope functions explicit.
- Maintain a feature inventory distinguishing implemented, partial, planned and blocked capabilities.
- Prioritise functionality and documentation that make the asset easy for an acquiring engineering team to understand and continue.

**Exit evidence:** a buyer can run and inspect the core product journeys from a clean setup without developer intervention; known limitations are visible.

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

### AR-06 — Buyer and market evidence
- Research the target customer, recurring problem, competitive alternatives and strategic buyer categories.
- Document the value hypothesis, potential cost savings and differentiators without inventing measured outcomes.
- Where authorised and feasible, collect consent-based discovery evidence that can be lawfully transferred or independently repeated by a buyer.
- Do not make owner-operated launch, recurring revenue or a live customer pilot a prerequisite for a sale-ready asset.
- Do not present survey interest, informal compliments or hypothetical subscription revenue as actual traction.

**Exit evidence:** a credible buyer thesis, competitive map and clearly separated verified evidence, assumptions and unvalidated opportunities.

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

## 6. Resourcing and expenditure authority

- The previous AUD 500 initial and AUD 100 recurring monthly caps have been withdrawn by the owner; they are not constraints on product scope or engineering planning.
- Prioritise the work required to make the complete asset technically sound, demonstrable, secure by design and straightforward to transfer.
- Actual expenditure remains subject to explicit owner approval. Do not purchase services, subscribe, engage contractors, commission certification or create financial commitments without that approval.
- Record any approved spend, renewals, dependencies and cancellation obligations.
- Distinguish work that can be completed within repository engineering from independent reviews or services that require an external provider.

## 7. Release and authority boundary

Acquisition preparation is not an owner-operated product launch. It does not authorise production deployment, real customer/employee/payroll data intake, external customer communications, buyer outreach, paid services, merge to a protected release branch or transfer of ownership. A buyer-ready local demonstration, synthetic test environment and documented deployment pathway are appropriate deliverables; a live production service is not a prerequisite unless separately approved.

The owner retains authority over any external contact, buyer disclosure, repository access grant, sale, licence, assignment, merge or deployment.

**Current state:** acquisition readiness is a development objective. All workstream exit evidence must be recorded separately; this document does not assert that any workstream is complete.

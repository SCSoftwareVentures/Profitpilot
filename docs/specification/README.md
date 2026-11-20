# ProfitPilot — Architecture and specification baseline A1

**Date:** 20 November 2026. **Baseline:** V8.6.1 plus the A1 design supplements. **Status:** engineering design baseline for a transferable synthetic prototype; not G5 approval, production readiness, legal clearance or market validation.

## Scope and precedence

The existing [product overview](../PRODUCT_OVERVIEW.md), [validation gates](../VALIDATION_GATES.md) and [architecture principles](../ARCHITECTURE_PRINCIPLES.md) remain authoritative for business validation, scope boundaries and safety. This package supplies the detailed engineering decisions missing from those documents. Actual implemented interfaces are documented in [OpenAPI](../../api/openapi.yaml); proposed interfaces in this package are not deployed. In a conflict the more restrictive security, legal or release condition prevails; record the conflict before changing scope.

- A: synthetic contract-economics prototype and buyer demonstration.
- B: financially useful core wedge, conditional on G0–G5 for real customer use.
- C: optional transaction-coordination design, not a commitment to first-release implementation.
- D: separately gated SecurePay design; no actual custody, collection, payout or provider credentials in prototype.
- A buyer may acquire the source asset before operational launch; acquisition does not establish G0–G6, production readiness or ownership rights beyond a signed transfer.

## Specification index

1. [System design and decisions](SYSTEM_DESIGN.md)
2. [Functional modules and workflows](FUNCTIONAL_REQUIREMENTS.md)
3. [Data contracts, states and interfaces](DATA_AND_INTERFACES.md)
4. [SecurePay and dispute design](SECUREPAY.md)
5. [Security, privacy, performance and operations](QUALITY_AND_OPERATIONS.md)
6. [Acceptance traceability and buyer handover](ACCEPTANCE_AND_HANDOVER.md)
7. [Machine-readable requirement catalogue](requirements.json)

Each requirement has a stable ID, phase, dependency, verification method and current evidence state. CI checks catalogue integrity and references; it cannot certify prose completeness, validate market demand or replace implementation tests.

## Change control

A change proposal identifies affected requirements and ADRs, rationale, compatibility, data/privacy risk, migration and rollback, acceptance tests, and decision owner. Technical implementation can refine provisional decisions without bypassing G5 or the provider/legal gate. Unapproved production targets remain planning defaults, not contractual SLAs. No live personal data is permitted in this public repository.

A1 closes the internal design-coverage work item, not external decisions requiring representative exports, a licensed/appropriate payment partner, independent reviewers, customer research or formal release authority.

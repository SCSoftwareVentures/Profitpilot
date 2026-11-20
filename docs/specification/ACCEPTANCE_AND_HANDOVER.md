# Acceptance, release evidence and acquisition handover

## AH-01 — Evidence levels and release controls

Design-complete means requirement ID, owner role, scope, dependency, state/negative path, acceptance method and documented limitations. Implemented means code exists; verified means specific immutable commit and retained test result; operationally verified requires target environment proof. Legal/provider review and customer validation are separate evidence classes. Missing proof is blocked or unverified, not pass.

Synthetic asset handover can be evaluated independently from live-operation readiness. Preserve all G0–G6 validation gates. Do not present a source acquisition as a SaaS with customers, guaranteed value, revenue, certified security or approved payment custody.

## AH-02 — Acceptance traceability

| Family | Required verification |
|---|---|
| SD | architecture boundary review, dependency/ownership audit, deployment and migration review |
| FR-01–02 | identity/role/object negatives, version conflict and revocation tests |
| FR-03–05, DI | upload/parser boundaries, same/different digest, issuer alias and cross-batch duplicate conflicts, concurrent confirmations, decimal and rollback tests |
| FR-06–08 | authorised variation, coverage calculation, immutable restatement and exception lifecycle |
| FR-09–15, SP | synthetic browser journeys, participant scope, independent review and remedy, provider simulator, ledger invariant and notification retry |
| QO | security threat coverage, data minimisation and retention, load/accessibility, recovery, supply-chain and incident evidence |
| AH | clean buyer install, inventory and known limitations, actual CI, transfer rights review |

Machine catalogue enumerates every family member. Automated catalogue tests do not execute unmet feature acceptance criteria.

## AH-03 — Buyer deliverables

- Source repository snapshot at immutable revision; documented build prerequisites, env template without credentials, migrations and demo fixture.
- Architecture and domain/API specifications; scope, assumptions, data model, decisions and traceability; updated README and capability inventory.
- Reproducible clean install, browser demo with connected implemented core where available, test commands, full CI evidence, known failures and deployment guide.
- Security and privacy evidence index: threat model, isolation tests, dependency inventory, unresolved risks, settings and operational requirements; no sensitive data.
- Buyer acquisition pack: transferable IP/license inventory (including dependencies), third-party obligations, credentials to provision separately, ownership and repository visibility/transfer plan, supported feature matrix and excluded claims.
- Roadmap and effort/risk register for unimplemented modules, operational cost assumptions, external approvals and validation obligations.
- Explicit buyer acceptance of asset condition; no secret transfer in public repository and no legal or valuation representation without review.

## AH-04 — Release checklist and exclusions

Run syntax/unit, database migrations/RLS, authenticated API integration, Docker image and health smoke; add browser, performance, supply-chain, restore, and independent checks as implementation progresses. Record commit, job results, skipped tests, configuration and exact artifacts. Test on clean install and upgrade with synthetic data. Do not label production-ready if critical/high vulnerabilities, incorrect financial calculations, cross-tenant disclosure, untraceable evidence, broken recovery, inaccessible critical flow or missing required approvals remain.

Current architecture baseline is a design milestone. Cross-batch invoice canonical enforcement, full core workflows, integrated UI, provider simulator/live adapter, security operations and packaging verification are not complete. No external research or legal review performed in this design pass.

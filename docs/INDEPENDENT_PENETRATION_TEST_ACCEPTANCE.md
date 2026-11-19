# Independent penetration-test acceptance dossier
Prepared 18 November 2026. Technical owner: Sammy Chehade.
Status: READY FOR ENGAGEMENT PREPARATION; independent testing NOT PERFORMED.
This document does not authorize attacks, spending, staging deployment or live inputs.

## Evidence baseline
- Exact core development commit c09ebd36a3102690df763bf956c783d9190e116f: [CI #1895](https://github.com/luxhustle01-ux/Profitpilot/actions/runs/44239910112) succeeded; signed candidate provenance was skipped on the core branch.
- Verified database job exposes synthetic payroll review and confirmation acceptance, tenant isolation, session revocation, audit integrity, security catalogue drift checks, encrypted restore, and TLS.
- Actual ClamAV control and dependency/image scanning jobs passed on that run. Automated scans do not prove absence of vulnerabilities.
- Draft PR #38 (security) and stacked PR #40 (core) remain unmerged. Do not treat this baseline as final product acceptance. Later changes require new exact-head evidence.
- Additional synthetic valid-signature negative tests were committed at 0422b93ef9f822de1414c35ce81e6e6d00650b6b; obtain exact-head passing logs before relying upon them.

## Engagement authorization and assets
Owner must identify the independent tester, confirm absence of implementation conflicts, approve a written rules-of-engagement agreement and authorize a specific non-public production-like staging target and test window. Require explicit permitted hosts/ports, source addresses, roles, test limits, emergency contact, encrypted evidence retention and removal schedule. Do not test public third-party services, other tenants' real data, production or vendor infrastructure without separate authorization. No production credentials, database dumps, real evidence or detailed exploitable findings in this public repository.

Provide synthetic tenants A and B with owner, admin, analyst, reviewer and read-only identities, two independent sessions per sensitive user, restricted worker identities, simulated quarantined files and financial records. Provide the selected signed candidate, configuration inventory with secrets redacted, data flows, route inventory and the existing scope in PRODUCTION_SECURITY_ACCEPTANCE.md. Provide a separate permitted tester environment only after owner approval.

## Minimum test work orders
| ID | Independent tester must verify | Existing first-party reference |
|---|---|---|
| PT-01 | Authentication, issuer/audience, session fixation, MFA, recovery and revocation against actual configured IdP | Identity/session tests; 023, 038, 046 migrations |
| PT-02 | Object-level access and horizontal/vertical escalation across every exposed route including export and UI | API integration, tenant-isolation and policy catalogue tests |
| PT-03 | Worker-role credential compromise, SQL scope, privilege escalation, drift and restore boundaries | Private privilege catalogue, restricted worker and drift tests |
| PT-04 | Financial authorization, replay, source substitution, duplicate approval and race attempts | Payroll review/attested confirmation SQL tests; invoice mapping tests |
| PT-05 | File intake, quarantine, scanner, parser limits, approval races and retention | Genuine ClamAV, encrypted quarantine and promotion tests |
| PT-06 | TLS, reverse proxy trust, request framing, CSRF/CORS/CSP, browser storage and error handling | TLS and production container tests; actual edge unverified |
| PT-07 | Resource exhaustion and distributed rate-limits within agreed safe bounds | Concurrency, actor containment and budget tests |
| PT-08 | Audit mutation, backup confidentiality, restore and revocation regression | Signed checkpoint and synthetic backup/restore tests |
| PT-09 | Supply-chain substitution, secret exposure, artifact provenance and deployment configuration | Reachable-history, lockfile, scanners, signed candidate gate |
| PT-10 | Retest each unresolved issue and every subsequently exposed feature | Independent tester reports, not CI alone |

## Acceptable closure evidence
For each work order: tested exact SHA and deployed artifact hashes, scope/environment, date, named tester, methodology, pass/fail/not-tested and limitations. For each finding: opaque ID, affected feature, severity and rationale, sanitized reproduction, impact, remedy, fix SHA, independent retest and disposition. Keep private report and raw evidence in controlled storage. Public status may record approved opaque references only.

Do not declare a pass if any work order is not tested without documented scope exception and risk approval. Require no unresolved critical/high findings, independent retest of fixes, owner decision on residual medium/low findings, and a written signed report referencing the exact candidate. The final report must be produced by an independent professional, not the implementation assistant or a CI scanner. Material changes invalidate affected evidence.

## Release blockers and explicit boundaries
- No independent tester has been appointed; no approved staging target or signed independent report exists in the evidence reviewed.
- Customer-facing payroll API and final application workflows are not complete. The private database functions cannot substitute for penetration testing of future user-facing paths.
- This is a first-party engagement dossier, not a pen-test report, security certificate or launch approval. Keep production disabled. No approval, hiring or expenditure was performed here.

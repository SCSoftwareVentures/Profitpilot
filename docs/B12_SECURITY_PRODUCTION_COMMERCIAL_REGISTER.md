# ProfitPilot B12: security, production and commercial evidence register

Snapshot: 21 November 2026. This is a dated internal technical evidence assessment, not legal advice, independent certification, production sign-off or proof of real customer demand. No customer, payroll or payment data may be placed in this public repository.

## Verified technical evidence at the preceding candidate

CI: https://github.com/SCSoftwareVentures/Profitpilot/actions/runs/44883535073
Exact SHA: da1001469bfd0e1e2b8dd661a38311cb97c9fc57
Retained vulnerability artifact ID: 14699226414, Grype 0.104.1, database built 2026-11-21T06:20:06Z.

- Node.js 22: 165 tests; 162 pass, 0 fail, 3 intentionally skipped.
- PostgreSQL migrations, tenant RLS, synthetic encrypted restore: passed.
- CodeQL extended JavaScript analysis: passed.
- Disposable Compose bootstrap and legacy-volume migration rehearsal: passed.
- Container security: FAILED. Release dossier and buyer packages correctly skipped.
- API image: zero reported vulnerability matches.
- Protected ClamAV image: 14 findings, 10 High and 4 Medium; packages libcrypto3 and libssl3, both Alpine 3.5.9-r1, each matched to seven distinct CVEs. No fix version in the retained Grype advisory database.

CVEs: CVE-2026-124709, CVE-2026-107494, CVE-2026-121482, CVE-2026-95690, CVE-2026-84786, CVE-2026-107493, CVE-2026-35190.

B12 strengthens the CI scan evidence gate: compare against independently Docker-inspected image IDs, exact expected targets, scanner version, fresh valid vulnerability database, non-filtered full scan and zero ignored matches. This does NOT fix any vulnerability. Full security clearance still requires a safe upstream or independently reviewed alternative, clean matching image scans and all five engineering jobs passing at the exact final SHA. No severity suppressions, fabricated package metadata or disabling the protected scanner.

## Production release blockers

| Gate | Required independently reviewable evidence | Current state |
| --- | --- | --- |
| Live identity and access | Real MFA provider, revocation, expiry, privilege separation and tenant cross-access tests | NOT VERIFIED |
| TLS and secret custody | Audited HTTPS and DB TLS, secret mount/rotation, encrypted storage, key backup | NOT VERIFIED |
| Penetration and native code | Independent pen test, C scanner analysis, remediation and retest | NOT VERIFIED |
| Scanner operation | Authentic signature-update chain, detection samples, monitoring, failure handling | NOT VERIFIED |
| Recovery and operations | Independent backup custody, measured RPO/RTO, restore, rollback, owner, incident procedures | NOT VERIFIED |
| Australian law/privacy | Qualified privacy, employment, consumer, retention and processor legal review | NOT VERIFIED |
| iPhone/browser | Physical Safari/WebKit IOS-01 through IOS-10, VoiceOver, text sizing and screenshot evidence | NOT VERIFIED |
| Production performance | Representative load, resilience, degraded service, alerts and support processes | NOT VERIFIED |
| SecurePay live funds | Independent Australian specialist and provider written approval for financial flows | NOT VERIFIED |
| Final owner approval | Exact-commit independent review and signed release acceptance | NOT VERIFIED |

Local CI and a fictional demo cannot close these external gates. No production deployment, live payments, independent compliance certification or real-data processing is authorised.

## Competition: public vendor capability claims, not independent test results

These sources establish that core cleaning-contractor profitability features are already marketed. They do not establish feature completeness or performance.

| Vendor | Stated overlap | Direct evidence |
| --- | --- | --- |
| CleanERP | Commercial cleaning payroll, finance and site profit | https://www.cleanerp.com.au/ |
| BrightGo | Cleaning contract job costing, labour allocation and budget versus actual | https://www.brightgo.com/ |
| freshOps and Xero | Site-level profit and loss tracking using linked invoices and time sheets | https://help.freshops.com.au/en/articles/3063528-what-does-the-xero-payroll-integration-do |
| CleanManager | Cleaning industry quotes, scheduling, payroll and invoicing | https://cleanmanager.com/pricing |
| Eaco | Commercial cleaning rosters, audits and client portal | https://www.eaco.me/ |

Differentiation claim: BLOCKED. Only permitted, comparable hands-on trials can demonstrate whether ProfitPilot provides superior source-lineage reconciliation, honest incomplete-period handling, exception traceability, setup effort, cost or accuracy. Record product/plan, configured integrations, task scenario, numbers, missing data, time, reviewer and measured difference. Five marketing-page readings do not satisfy five hands-on teardowns.

## Commercial validation: no qualifying real-world evidence supplied

The established gates in VALIDATION_GATES.md are the controlling standards.

| Gate | Existing acceptance criteria | Verified evidence |
| --- | --- | --- |
| G0 lawful data | At least 5 complete authorised unique export sets from at least 3 unrelated businesses; at least 80% pass ALL source coverage, payroll, invoice, reconciliation and effort checks | NOT VERIFIED |
| G0 competition | Five hands-on competitor teardowns, two actual customer tool stacks, two independently observed material unsolved recurring gaps, at least one buyer willing to pay | NOT VERIFIED |
| G1 | 20 interviews / 3 channels, at most 40% founder network, 12 unprompted same-pain cases, 8 quantified examples | NOT VERIFIED |
| G2 | 3 independent concierge trials, at least 2 of 3 real decision-use confirmations | NOT VERIFIED |
| G3 | 10 qualified buying conversations and at least 3 paid concierge engagements or signed paid commitments | NOT VERIFIED |
| G4 | 8 moderated usability sessions; at least 6 unassisted completions; median first insight at most 30 minutes | NOT VERIFIED |
| G5 | Signed software-build GO, named owner, legal/privacy plans and approved budget after earlier gates pass | NOT VERIFIED |
| G6 | 3 paid software pilots, weekly use, measurable effort reduction, no unresolved critical defects and support economics | NOT VERIFIED |

Do not interpret "not verified" as a factual zero in the world; no qualifying independent records have been supplied to this audit. Do not count synthetic data, generic competitor reviews, compliments or an asking price as paid demand.

## Source-asset sale versus production service

A truthful as-is code asset can be offered without claiming a finished SaaS, but buyer diligence still requires contributor/IP chain of title, third-party licence and notice compliance (including ClamAV and native components), rights to transfer, secret-free delivery, exact-source reproduction, buyer objections and actual price indications. The existing B6 npm metadata audit is not a legal ownership or redistribution opinion. Asking AUD 30,000-50,000 is not evidence that a buyer will pay it.

## Prioritised next evidence collection: zero additional spend

1. Security: vendor patch or independently reviewed safe replacement for protected OpenSSL dependencies; rebuild, validate real native scanner and pass exact-head CI with no suppressions.
2. Source sale: separately confirm contributor rights, third-party notices, buyer-facing technical limits and a reproducible signed-source handover.
3. Commercial: conduct permission-based independent customer conversations and comparable product teardowns using a standard synthetic scenario; never claim superiority from public pages alone.
4. Data feasibility: secure written export authorisation, approved lawful private storage/handling and responsible reviewer BEFORE accepting any confidential source exports. If no such route exists, stop the real-data G0 test.
5. iPhone: arrange an authorised, secure, zero-cost preview/delivery method and physically complete IOS-01 through IOS-10 with device/version/screenshots; no deployment without explicit approval.
6. Live release: independent security, Australian legal and operational reviews. Log unresolved findings and do not override them with enthusiasm.

Release disposition: SECURITY BLOCKED; PRODUCTION NOT VERIFIED; REAL DEMAND NOT VERIFIED; SALE NOT APPROVED. No merging, production deployment, buyer outreach, spending or notifications are authorised by this register.

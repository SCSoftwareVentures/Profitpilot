# Sensitive security workflows and production acceptance

Status: implementation candidate; no real customer data, deployment, independent approval or activation. This document supplements the strict Australian compliance standard and the external security acceptance register.

## Candidate endpoints
The existing production release interlock still denies all business operations. The following endpoints are synthetic development capabilities, not permission to ingest actual payroll. Each requires a verified identity, active session and tenant membership, recent MFA, appropriate role, strict JSON, exact scoped signing and repeat database authorization. Underlying private tables and internal procedures remain inaccessible to the application role. Migration 048 adds only five reviewed security-definer capabilities, with an exact grant inventory and catalog fingerprint.

| Capability | Route suffix within /v1/tenants/{tenantId} | Scope |
|---|---|---|
| Submit payroll reconciliation | POST /payroll/runs/{runId}/submit | Owner/admin/analyst; pre-existing complete synthetic run; explicit submit |
| Review | GET /payroll/proposals/{proposalId} | Owner/admin/reviewer; aggregates and digest only; detect changed evidence |
| Confirm | POST /payroll/proposals/{proposalId}/confirm | Independent reviewer, exact reviewed digest, fresh MFA and explicit intent; immutable receipt |
| Own account access | GET /privacy/account | Own persisted account and selected membership only; no arbitrary target ID |
| Account correction | POST /privacy/account/correct-email | Explicit confirmation; issuer-attested verified email; exact signed claim; newer authentication required for repeat correction |
| Invoice staging preview | POST /privacy/invoices/{batchId}/disposal-preview | Owner/admin; eligible due approved rejected/failed staging; scope digest |
| Controlled disposal | POST /privacy/invoices/{batchId}/disposals/{orderId} | Owner/admin; request, independent decision, one-time consumption within 15 minutes; recompute scope, check hold and retention, atomically delete only unreferenced eligible staging |

The opt-in reviewer workbench at /candidate/security/ is enabled only in non-production with SYNTHETIC_SECURITY_UI_ENABLED=true. It uses no persistent credential storage, external requests or raw payroll fields. Enter only an ephemeral synthetic access token. It is not a production identity integration. Tests exercise the real JWT path and file delivery; full Safari device acceptance remains separate.

## Explicit limitations
- The account access response is not a complete APP 12 response. Former/inactive users, other personal data, customer records, representatives, reasonable refusals and access/correction complaints require the approved human-assisted privacy process. The correction endpoint addresses only a verified contact email for the same identity, not other records, identity changes or financial evidence.
- The temporary privilege is a scoped one-use capability, not broad database role elevation. No authority is automatically granted to staff, incident recovery operators or other administrative workflows. Separate independently reviewed authorisation remains required.
- Confirmed payroll correction, supersession and legally authorised disposal of retained financial evidence are not implemented; no real payroll intake. Do not bypass immutable receipts or delete referenced records. Approval of a privacy work order alone grants no generic export, correction or deletion.
- Production monitoring and incident response still require independently approved actual monitoring destination, on-call processes, and real infrastructure.
- Source scanning, dependency and image vulnerability scanning are scheduled in CI on the default branch once integrated; no claim of already-scheduled default branch execution.
- Full release approval must bind the exact reviewed build and actual configuration after feature completion.

## Protected acceptance workflow (no deployment)
The manual workflow production-acceptance.yml accepts only a successful exact-main push CI candidate and its exact attempt. It checks the GitHub environment configuration for protected branches and reviewer protection with self-review prohibited, downloads the exact attested scanned artifacts, verifies GitHub provenance and byte hashes, then verifies the private approval bundle. Configure the protected environment independently; do not store keys or legal reports in this public repository. If configuration, evidence or approvals are absent, the workflow must fail. The actual protected environment has not been created or validated in this branch.

The script verify-production-acceptance.js requires four distinct externally pinned Ed25519 public keys: qualified Australian counsel, independent security assessor, operational reviewer and owner. Counsel and owner must sign all twelve AU legal gates. Assessor, operations reviewer and owner must sign all seven production gates, exact commit, actual scope/configuration digest, candidate manifest digest, exact legal approval bundle digest and freshness. Each production gate binds distinct private evidence by SHA-256; acceptance expires no later than 30 days or legal approval expiry. Synthetic keys are tests only.

The protected workflow does not deploy, publish secrets, unlock the runtime, or automatically approve real processing. A final integration and genuine approved deployment procedure remain mandatory. A valid signature proves possession of a key and integrity of the statement, not a person's qualifications, testing independence, accuracy of findings or completeness of the real environment.

## Current release state
Draft stacked PR #40. All new code needs exact-head CI and separate independent acceptance before its use as a buyer-ready production candidate. No expenditure, main merge, external engagement, environment activation or live deployment authorised.


## Privacy case lifecycle and payroll supersession (migrations 049–051)

The candidate now provides two authenticated privacy case endpoints and a synthetic workbench section for request, verified staff intake, acknowledgement, independently evidenced resolution/refusal, and case status. Active members may open and view their own self-service cases; owner/admin staff may record verified intake and manage case status. A separate authorised member must record the outcome, after acknowledgement. No response document, personal details of a third party, raw payroll data or free-text evidence is collected through these functions. Use private, separately approved channels for identifying evidence and actual responses. Capacity limits do not excuse a missed legal request; offer assisted intake if the API denies capacity. The 20-day escalation flag is an internal target, not a universal statutory deadline. A record of refusal is not a determination that the refusal is lawful.

Confirmed payroll corrections use a new reconciled proposal, a reservation, an exact scope digest, an independently approved short-lived one-time privileged work order and a separate fresh-MFA confirmation proof. The replacement and supersession link commit together; originals, receipts and audit history stay immutable. Reserved replacements cannot use ordinary confirmation. The current site summary omits superseded runs; overlapping saved calculations made before correction are conservatively blocked from read/export and must be recalculated. This is an operator-only internal capability: no new correction endpoint or normal user workflow is exposed. The operator must verify that the replacement covers the same population as the original; matching period/currency and different evidence do not by themselves establish population equivalence. Unexecuted reservations remain blocked and must not be bypassed.

The v2 signed security recovery inventory adds a bounded, opaque sensitive-state fingerprint over account email metadata, security-work records, privacy-case records, payroll review receipts, reservations and supersession links. A mismatch with the authoritative source keeps the restore isolated; it is not automatically replayed or repaired. The private inventory must never be published. Legacy v1 inventory bundles are rejected; a new signed authoritative bundle is required. This does not replace the existing archive, audit checkpoint, hold, tombstone and revocation checks.

Verified baseline: CI #2015 passed the privacy-case authenticated integration and payroll supersession database tests, with signed candidate provenance. Later recovery and UI changes require exact-head CI. The current release remains locked.

Still required: comprehensive legally reviewed record classification/retention and authorised disposal of confirmed financial records (including backup handling); actual fulfilment of complex rights requests and representatives/former users via the assisted process; operator correction interface and full multi-tenant workflow acceptance; actual identity-provider, infrastructure and production recovery validation; independent security and Australian legal approvals and separately configured protected release environment. No real customer records, deployment, merge or expense.

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

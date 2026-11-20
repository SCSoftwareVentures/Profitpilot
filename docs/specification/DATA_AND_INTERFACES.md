# Canonical model, state transitions and interface contracts

## DI-01 — Common data contract

Use opaque UUID, tenant_id, created_at (UTC instant), actor and correlation IDs on owned records. Record service-period date and source timezone separately; never infer date from upload timestamp. Money: decimal strings in public JSON, exact NUMERIC or minor units internally, explicit ISO currency and tax basis, no floating-point authoritative arithmetic. Null is unknown; zero is known zero. API response uses stable opaque IDs, no private fields or credentials. Every mutation checks membership/object scope and version; state transitions and critical audit record commit atomically. Retention deletion is privileged governed erasure, not routine UPDATE/DELETE.

## DI-02 — Entity keys and associations

| Entity group | Key relationships and constraints |
|---|---|
| Membership | UNIQUE(tenant_id,user_id); external identity subject unique; role state is explicit; same-tenant creator/reviewer/approver references |
| Contract/site | tenant/business parent; version identity and effective range; disallow overlap before approval; alias unique per namespace or held |
| Source | batch tenant/source/hash/metadata replay key; receipt batch FK and digest/size/count; raw row unique(tenant,batch,row_number); no silent mutation |
| Payroll | source record stable scoped source_ref; allocation source FK; confirmed run unique per pool; exact source/bucket totals and residual |
| Invoice | proposed tenant/direction/issuer-namespace/reference unique canonical identity; all evidence candidates retained and linked to raw row/receipt; credits/reversals reference original, do not overwrite |
| Match | proposed candidate and append-only review history; at most one confirmed match per eligible invoice line; supersession through reviewed version |
| Report | input snapshot IDs and method/version; immutable result; unique restatement relation; exclusions and confidence evidence |
| Transaction | customer/business participants; accepted quote/scope version and job; milestone, evidence and approval references; no unrelated tenant browsing |
| Dispute | job/milestone scope, parties, severity, notice, evidence snapshot, agreed or reviewer-set dates, decision, appeal and remedy execution reference |
| Payment | immutable provider event ID scoped to provider account; internal intent/payout/refund IDs; idempotency key + payload hash; ledger transaction balanced per currency and unique business-event key |

Current invoice uniqueness conflates issuers; do not relax until representative semantics, conflict inventory and migration tests pass. Confirmed invoice/cost states are not permission to release funds. Source authenticity levels: client_declared, byte_verified, issuer_authenticated (future, independently validated); never promote without evidence. Preserve original reference, leading zeros and case; aliases are review signals only.

## DI-03 — State machines (target)

| Aggregate | Allowed progression and guards |
|---|---|
| Batch | uploaded -> review -> accepted/rejected; held conflicts remain reviewable; original-file receipt seals rows; exact replay returns prior receipt. Current prototype may use narrower state transitions. |
| Mapping | candidate -> held/rejected/confirmed by permitted reviewer; correction supersedes via new version; retain prior decision. |
| Allocation | draft -> confirmed after exact reconciliation; correction creates new reviewed run, excludes superseded financial impact. |
| Invoice identity | candidate -> held/confirmed/rejected; missing issuer, alias or unresolved collision blocks confirm; concurrent inserts unique and atomic; credit/reversal explicitly linked. |
| Contract | draft -> approved -> superseded/archived; approval fixes version and effective range. |
| Variation | requested/observed -> candidate -> approved/rejected -> completed -> invoiced -> reconciled; authorised approval and delivery/billing evidence required. |
| Calculation | requested -> completed/incomplete/failed; new run for correction; prior immutable output remains accessible. |
| Job | draft -> offered -> accepted -> in_progress -> completion_submitted -> accepted/rectification/disputed -> closed; approved scope version immutable. |
| Dispute and payment | see SECUREPAY.md; separate commercial, dispute, provider and settlement states. |

Invalid transitions deny with conflict, no partial writes. Applicable DB transaction uses row/version lock and constraints; don't rely on the order of network events.

## DI-04 — Proposed service/API contracts

Existing implemented routes remain in api/openapi.yaml. Future operations listed here are design targets, not exposed API promises. Use /v1/tenants/{tenantId}, JSON request/response with documented schema, bounded limit and cursor, stable error code, correlation ID; bearer token required except signed provider callbacks. All create/transition calls take an idempotency key where retry can duplicate effects. Same key + same payload returns original outcome; changed payload returns 409. Use expectedVersion or If-Match for mutable records; stale approvals return 409. Error semantics: 400 malformed, 401 missing/invalid auth, 403 role denied, 404 unavailable scoped object, 409 state/conflict, 413 limit, 415 format, 422 semantic failure, 429 throttle, 503 unavailable with safe retry. No stack trace or secret in response.

| Future resource/action | Request minimum | Response / conditions |
|---|---|---|
| memberships/invite, revoke | target identity, role, reason, expectedVersion | membership ID/status; owner/admin delegated scope |
| contracts/{id}/versions and approve | scope, price, basis, period, evidence, reason | version ID/status; non-overlap and explicit authority |
| invoices/identity-candidates and resolve | raw-row IDs, issuer namespace, reference, evidence, reason | conflict group and reviewed identity; no automatic inclusion |
| variations and decision | contract version, requested scope/price, authorised evidence | immutable decision and billing linkage |
| reports/{id}/restatements, export | prior run, input refs, reason, format | new run/export ID; sanitised CSV and scoped short-lived link |
| jobs/quotes and accept | exact immutable version, participant, acknowledgement | acceptance snapshot and actor |
| jobs/{id}/evidence | kind, source, consent, hash, artifact ID | quarantined/verified status, never decisive proof alone |
| disputes/{id}/responses, rectify, decision, appeal | allegation/response evidence, deadline, reason, amount breakdown | case version and decision record; independent reviewer |
| securepay/intents, release-requests, refunds | job milestone, exact amount/currency, idempotency, reviewer decision | provider reference and status, no settlement claim |
| provider/webhooks | provider-signed raw body and event identity | verify, safely persist/dedupe, reconcile; no browser trust |
| privacy/requests, support/access | subject/case, purpose, scope, authority | audited status and expiry |

Adapter contract: capabilities, version, scopes, read/write direction, limits, pagination, time/identity semantics, idempotency, retry/backoff, replay and reconciliation, disconnect and credential revocation. Do not assume supplier invoice reference or payroll source_ref semantics until source owners validate them.

## DI-05 — Calculation and reporting

Follow CORE_CALCULATION_SPEC.md. Eligible revenue minus direct, approved allocated, attributable supplier/subcontract and other included delivery costs equals management contribution. Show incomplete if sources/bases unresolved; margin only when denominator meaningful and completeness stated. Preserve exact input IDs, policy/formula versions, amounts, rounding, excluded records, source provenance, reviewer, timestamp and output digest in future snapshot. Current implementation has partial source coverage and is not a statutory profit calculation. Retain rounding remainder separately and reconcile to original pool; unknown currency/tax basis blocks unlike-basis aggregation.

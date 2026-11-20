# SecurePay — transaction and dispute design (separately gated)

This is a proposed architecture and acceptance specification, not a license, provider agreement, legal opinion or implemented feature. No custody, escrow claim, real payment acceptance, payouts or live keys until specialist Australian legal review and written provider approval. Customer rights and provider deadlines override internal targets.

## SP-01 — Agreement and transaction record

Before payment request, both parties see business identity, job description, exclusions, versioned itemised scope/price, tax/currency, milestone acceptance criteria, agreed dates, cancellation/refund/rectification terms, evidence requirements and complaints path. Capture exact accepted version, party identity, timestamp and acknowledgement. Changes require versioned acceptance of scope/price; no silent expansion. Customer access is explicitly scoped to their job; never expose worker/payroll records.

Maintain independent states for job, dispute, internal payment eligibility, provider funding and actual settlement. Provider-hosted collection/tokenisation only. Do not store PAN/CVC. Commercial acceptance alone cannot trigger payout without the approved authorisation path.

## SP-02 — Severity and response targets

| Level | Classification | Proposed initial response SLA |
|---|---|---|
| 1 low | minor/fixable defect, proportionate rectification opportunity | 2 business days |
| 2 medium | material issue, partial non-performance or meaningful disagreement | 3 business days |
| 3 high | serious or substantially defective work, safety or major financial issue | 1 business day |

Targets apply to acknowledgement/initial response, not mandatory final resolution. A calendar with agreed local timezone/business days and holidays is required; calculate from logged receipt and published rules; escalation if missed, never automatic transfer. Urgent safety risks immediately routed to appropriate support/emergency channel. Provider or legal deadlines take precedence; no indefinite hold. Reviewer classifies and may reclassify with reason and notice.

## SP-03 — Dispute procedure

1. Customer identifies disputed milestone, allegation, evidence and requested remedy; show non-platform rights and complaint options. Notify business with scoped evidence and response deadline.
2. Business provides reasoned response, counter-evidence and rectification offer if appropriate. Preserve both sides' original submissions; evidence timestamps and hashes are provenance, not proof of satisfactory work.
3. For fixable defects, parties agree a reasonable rectification deadline; independent reviewer sets a reasonable deadline if agreement fails, considering scope, availability, urgency and rights. Record agreement/decision, timezone, conditions and amendments.
4. Serious/material issues receive reasoned independent investigation, both parties' submissions, documented conflicts of interest and evidence evaluation. Permit accessible submissions and procedural response; no unilateral opaque AI decision.
5. Reviewer records findings, amounts, reasons, authority, remedy and clear appeal route. Outcomes may include satisfactory rectification and full payment without deduction, proportionate partial payment/deduction, refund, or other lawful remedy. No automatic penalties or waiver of rights.
6. Separate disputed and undisputed amounts where legally/provider permitted; execute approved actions only through provider adapter after explicit required human approval. Late response or missed rectification deadline triggers escalation, not automatic funds transfer.
7. Appeal/reopen with new evidence, correction or procedural issue; different eligible reviewer when practicable. Freeze only affected action where applicable, preserve prior decision and avoid indefinite restrictions.

## SP-04 — Provider and ledger contract

Provider state: created -> authorised -> captured/funded -> funds available under approved structure -> release requested -> payout instructed -> settled; branch for expired authorisation, failed capture, payout failure, reversal, refund and chargeback. Internal intent stores amount/currency, opaque provider account, external IDs, status/version, reconciliation timestamps and idempotency key. Webhooks validate signature/timestamp, dedupe key scoped to provider account, quarantine mismatched amounts or unexpected state, fetch authoritative provider state when permitted. Out-of-order events cannot regress settled state without explicit reversal events. Retry pending operations with same key, reconcile provider reports and bank settlement references separately.

Illustrative subledger design (not accounting advice): immutable balanced journal per currency, provider-clearing and merchant-payable/refund/reserve accounts as determined by provider/legal/accounting review. Use transaction ID and unique event key, debit total equals credit total, counter-entry on reversal; never edit posted journal. No release beyond available eligible reconciled amount; compare settled/refunded/chargeback amounts and fees, route mismatch to reviewer. Funding, payout instruction and bank settlement are different facts. Daily reconciliation is a proposed operational target, not proof of operation.

## SP-05 — Verification and gate

Synthetic simulator must cover happy path, duplicate and out-of-order webhooks, invalid signature, expiry, part release/refund, conflicting idempotency payload, payout failed/reversed, chargeback, provider timeout, ledger imbalance, disallowed actor, reviewer conflict, all severity paths, agreed and externally set rectification date, appeal and missed SLA escalation without transfer. Before live implementation: provider capabilities and funds flow, Australian consumer/financial-services/privacy and AML/CTF applicability, insolvency, fee/dispute economics, support staffing, identity checks, reconciliation and incident procedures all require appropriate review. No production endpoint or live provider enabled by this specification.

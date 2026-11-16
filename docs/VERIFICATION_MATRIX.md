# ProfitPilot — Verification Matrix

**Status:** planned and partly prototype-executable checks. A row marked “not run” is not evidence of a pass.

| ID | Area | Test | Expected result | Evidence status |
|---|---|---|---|---|
| ENG-01 | Money | Round decimal amount to cents | Deterministic cent rounding | Included in browser runner; execution not yet verified |
| CSV-01 | Import | Quoted commas and escaped quotes | Correct field preservation | Included in browser runner; execution not yet verified |
| CSV-02 | Import | Unclosed quote | Reject file | Included in browser runner; execution not yet verified |
| CSV-03 | Import | Duplicate headings | Reject file | Included in browser runner; execution not yet verified |
| CSV-04 | Import | Missing site/date/amount | Row held with reason | Included in browser runner; execution not yet verified |
| PAY-01 | Payroll | Allocation buckets reconcile | Exact pool reconciliation | Included in browser runner; execution not yet verified |
| PAY-02 | Payroll | Site allocation exceeds pool | Block confirmation | Included in browser runner; execution not yet verified |
| INV-01 | Matching | Amount-only similarity | Never high confidence | Included in browser runner; execution not yet verified |
| INV-02 | Matching | Valid identity/date/amount | Candidate only; human confirmation required | Included in browser runner; execution not yet verified |
| CAL-01 | Metrics | Contract aggregation | Stable totals and margin | Included in browser runner; execution not yet verified |
| TEN-01 | Security | User A requests tenant B object | Deny with no data leakage | Not implemented; server required |
| TEN-02 | Security | Tenant context absent/invalid | Deny by default | Not implemented; server required |
| TEN-03 | Security | Pooled DB connection switches tenant | No context leakage | Not implemented; DB deployment required |
| AUTH-01 | Identity | Expired/revoked session | Reject request | Not implemented; identity provider required |
| AUTH-02 | Identity | Analyst attempts owner-only action | Deny and audit | Not implemented; server required |
| IMP-01 | Import | Same file uploaded twice | Idempotent batch, no duplicate costs | Engine/schema design only; server persistence required |
| IMP-02 | Import | Malformed or oversized file | Reject safely; preserve diagnostic | Partial browser demo limit only |
| IMP-03 | Import | CSV formula payload in export | Escape spreadsheet formulas | Not implemented |
| AUD-01 | Audit | Reviewer confirms match | Append actor, reason, timestamp | Schema only; not executed |
| CAL-02 | Calculations | Changed mapping after prior run | New version/restatement; prior run preserved | Specification only |
| TAX-01 | Tax basis | GST-inclusive vs unknown | Do not silently combine | Specification only |
| PRIV-01 | Privacy | Retention/deletion request | Defined workflow and verified deletion | Not implemented |
| OPS-01 | Resilience | Restore from backup | RPO/RTO demonstrated | Not implemented |
| SEC-01 | Security | Independent penetration test | Findings remediated and retested | External review required |

## Release gates

### Prototype acceptance
- Core screen navigation works on supported mobile browsers.
- Synthetic import produces clear valid/held row counts.
- Calculation outputs match independently calculated expected values.
- No live or personal data is used.
- Known limitations are visible in product and README.

### Private pilot readiness
- Private repository and controlled deployment.
- Server-side identity and tenant isolation.
- RLS and object-level authorisation tests.
- Secure upload, malware scan, retention and deletion.
- Complete test execution with retained evidence.
- Privacy/legal review and participant permission.
- Incident response, backup/restore and support process.

### Production release
- Independent penetration test and remediation.
- Native browser/device compatibility evidence.
- Customer acceptance and operational support.
- Legal/privacy/contract review.
- Monitoring, incident response, data export/deletion and recovery.
- Commercial unit economics and documented launch approval.

No release gate is considered passed by this document alone.

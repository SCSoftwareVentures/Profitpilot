# SecurePay SP-S3: tenant-scoped synthetic reviewer separation

Adds append-only internal **reviewer assessments**, not real dispute adjudication. POST and GET use `/v1/tenants/:tenantId/prototype/securepay-cases/:caseId/reviewer-assessments`.

POST accepts only `clientRequestId` (UUID) and `reviewReference` (opaque token). The authenticated reviewer UUID comes from signed database actor context, never from caller input. A reviewer cannot have opened the case or authored any of its recorded evidence; both API and database RLS enforce separation. The case must include an operator-reported matching claim, business reply and review note. These are **not independently verified submissions by the customer/business**. The table stores an append-only SHA-256 fingerprint and count of the evidence snapshot seen in one repeatable-read transaction (at most 500 rows), with idempotent request conflict checks. GET is restricted to tenant owner/admin/reviewer and paginated to 100 records.

No reviewer conflict-of-interest clearance beyond internal actor separation, real-party verification, source provenance, binding decision, legal clearance or payment execution is established. Hashes are not externally anchored and a privileged database administrator can replace the whole register. `decision_authority=false` and `payment_authority=false` are database constraints. Protected deployment mode blocks this synthetic prototype route entirely.

Next: independently validated customer and tradesperson identity/job binding, reviewer appointment and conflict declarations, provenance and custody, transactional event journal and concurrency/adversarial testing, provider and Australian legal approval, and customer-facing workflows. No real funds until independently authorised.

# SecurePay — SP-S1 decision engine (synthetic only)

This commit adds an isolated, deterministic decision-state module and Node.js regression tests. There is no deployed dispute API, database persistence, actual case evidence storage, holiday-calendar authority or payment provider integration.

Human classification of low/medium/high requires an evidence reference and targets first response in two/three/one business days respectively. Without an operator-verified calendar, the engine deliberately reports no enforceable date. Missed targets trigger an explicit human escalation only. Fixable defects require customer agreement on a reasonable rectification date or independent review on documented impasse. Decisions require a business response, both parties' evidence and a reviewer distinct from named parties. Appeals require a separate reviewer. No automatic fund transfers are possible.

Records contain opaque evidence references, integer-cent proposals, SHA-256 event/state checks and idempotency keys. These hashes are not independent tamper-proof audit custody: anyone controlling the whole state could rewrite and rehash it. Actor roles are caller-supplied in this synthetic module, and MUST NOT be used as real authorisation.

Next: PostgreSQL tenant RLS, evidence provenance and append-only persistence; verified identity, role and reviewer-conflict policies; HTTP request and concurrency tests; calendar governance and privacy controls; UX, provider architecture and Australian legal review. No real money, escrow or payment capability until written provider and legal approval.

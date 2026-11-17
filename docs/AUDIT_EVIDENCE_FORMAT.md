# ProfitPilot — Audit Evidence Format (Illustrative)

**Status:** Illustrative field-level example only. The rows below are synthetic and are not copied from a customer environment or represented as actual production audit events.

The current prototype appends tenant-scoped audit events to a hash chain. The schema includes event identity, tenant, actor, action, object type and ID, reason, correlation ID, metadata, timestamp, chain position, previous hash and event hash.

## Example event shape

```json
{
  "id": "00000000-0000-4000-8000-000000000001",
  "tenant_id": "00000000-0000-4000-8000-000000000002",
  "actor_user_id": "00000000-0000-4000-8000-000000000003",
  "action": "privacy_request_submitted",
  "object_type": "privacy_request",
  "object_id": "00000000-0000-4000-8000-000000000004",
  "reason": "Member submitted a privacy request",
  "correlation_id": null,
  "metadata": {
    "requestType": "access"
  },
  "created_at": "2026-11-17T00:00:00Z",
  "chain_position": 12,
  "previous_hash": "<synthetic-previous-hash-hex>",
  "event_hash": "<synthetic-event-hash-hex>"
}
```

The UUIDs, timestamp, chain position and hash placeholders above are illustrative, not a captured event. A real event hash is calculated by the database trigger over the event fields and prior hash; it must not be hand-authored.

## Verification model

- Each tenant has an ordered chain position.
- Each event stores the previous event hash.
- The database computes the current event hash on insert.
- Runtime application permissions prohibit ordinary audit-event UPDATE/DELETE.
- A verification function recomputes the chain and reports validity, count and first invalid event.

## Limitations

A hash chain makes unauthorised modification detectable within the assumptions of the database and privileged roles; it is not equivalent to an independently anchored immutable ledger. A sufficiently privileged database operator or compromised control plane may still affect the trust boundary. Production alerting, external anchoring, retention, access monitoring and independent review remain necessary.

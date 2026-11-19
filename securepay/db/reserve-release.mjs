/**
 * Atomic milestone release reservation. Caller supplies a transaction-scoped
 * pg client after BEGIN, with tenant identity already verified by server auth.
 * No external payment provider is invoked here.
 */
export async function reserveRelease(client,{tenantId,milestoneId,customerId,authorizationRef,idempotencyKey,requestId,verifyAndConsume}) {
 if(!client?.query||!tenantId||!milestoneId||!customerId||!authorizationRef||!idempotencyKey||!requestId||typeof verifyAndConsume!=="function")
   throw new Error("SecurePay reservation unavailable");
 const {rows}=await client.query(
  "SELECT id, amount_cents, status FROM securepay_milestones WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
  [tenantId,milestoneId]);
 const m=rows[0];
 if(!m||m.status!=="approved")throw new Error("Milestone not eligible");
 const verified=await verifyAndConsume({client,tenantId,milestoneId,customerId,authorizationRef,amountCents:m.amount_cents,requestId});
 if(verified!==true)throw new Error("Authorization rejected");
 const inserted=await client.query(
  "INSERT INTO securepay_release_requests (id,tenant_id,milestone_id,idempotency_key,amount_cents,authorization_ref,status) VALUES ($1,$2,$3,$4,$5,$6,'pending') RETURNING id",
  [requestId,tenantId,milestoneId,idempotencyKey,m.amount_cents,authorizationRef]);
 await client.query(
  "UPDATE securepay_milestones SET status='release_pending',version=version+1,updated_at=now() WHERE tenant_id=$1 AND id=$2",
  [tenantId,milestoneId]);
 return {releaseRequestId:inserted.rows[0].id,milestoneId,amountCents:m.amount_cents};
}
// CRITICAL: run within a database transaction and ROLLBACK on any error.
// verifyAndConsume MUST atomically consume a single-use, scoped PIN proof
// using the SAME transaction client. Do not retry with a new idempotency key.
// DB policies and provider dispatch/outbox integration remain separate gates.

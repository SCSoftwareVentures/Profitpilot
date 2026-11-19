/**
 * One-use SecurePay authorization proof consumption.
 * Must execute within the SAME PostgreSQL transaction as reserveRelease.
 * Proofs must be created only after server-side PIN verification with
 * rate limiting, authenticated customer identity and short expiry.
 * Never store raw PINs or reusable PIN hashes in this table.
 */
export async function consumeReleaseProof(client,{tenantId,milestoneId,customerId,authorizationRef,amountCents,requestId}) {
 if(!client?.query||![tenantId,milestoneId,customerId,authorizationRef,requestId].every(x=>typeof x==="string"&&x.length>0)||
    !Number.isSafeInteger(Number(amountCents))||Number(amountCents)<=0)
   throw new Error("Invalid SecurePay authorization scope");
 const result=await client.query(
  `UPDATE securepay_release_proofs
     SET consumed_at=now(), consumed_request_id=$6
   WHERE tenant_id=$1 AND milestone_id=$2 AND customer_id=$3
     AND proof_ref=$4 AND amount_cents=$5 AND consumed_at IS NULL
     AND expires_at>now()
   RETURNING proof_ref`,
  [tenantId,milestoneId,customerId,authorizationRef,String(amountCents),requestId]);
 return result.rowCount===1;
}

/**
 * Server-side release authorization boundary for SecurePay.
 * No PIN or token is accepted as proof without an injected verifier.
 * Caller must persist authorization consumption atomically with a locked
 * milestone state transition and a unique provider idempotency key.
 */
export async function authorizeMilestoneRelease({
  milestone, customerId, authorizationRef, verifyAndConsume, requestId
}) {
  if (!milestone || milestone.status !== "approved") throw new Error("Milestone not approved");
  if (!customerId || !authorizationRef || !requestId || typeof verifyAndConsume !== "function")
    throw new Error("Release authorization unavailable");
  const verified = await verifyAndConsume({
    authorizationRef, customerId, milestoneId:milestone.id,
    amountCents:milestone.amountCents, requestId
  });
  if (verified !== true) throw new Error("Release authorization rejected");
  // This object is an instruction candidate, NOT a provider transfer.
  // The persistence layer must atomically enforce uniqueness and lock state.
  return Object.freeze({
    milestoneId:milestone.id,
    amountCents:milestone.amountCents,
    idempotencyKey:requestId,
    authorizedCustomerId:customerId
  });
}

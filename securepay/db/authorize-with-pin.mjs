// Internal service only. The caller MUST derive tenant/customer from an
// authenticated, step-up verified session, never from client-supplied IDs.
// No live payment dispatch, no bearer proof returned to the client.
import {randomUUID} from "node:crypto";
import {verifyPinCredential} from "../domain/pin-credential.mjs";
import {reserveRelease} from "./reserve-release.mjs";
import {consumeReleaseProof} from "./consume-release-proof.mjs";
import {resolvePayer} from "./change-pin.mjs";
const denied=()=>({ok:false,code:"AUTHORIZATION_DENIED"});
// Only use with a transaction whose caller commits returned denials, so failed
// attempt counters persist. Throwing errors must roll back the entire transaction.
async function authorizeInTransaction(c,scope,pepper) {
  const {tenantId,milestoneId,customerId,pin,requestId,idempotencyKey,expectedAmountCents}=scope;
  if(!Buffer.isBuffer(pepper)||pepper.length<32||
     ![tenantId,milestoneId,customerId,requestId,idempotencyKey].every(x=>typeof x==="string"&&x.length>0)||
     !Number.isSafeInteger(expectedAmountCents)||expectedAmountCents<=0)
     throw new Error("PIN authorization unavailable");
    // Acquire milestone before credential/attempt lock to keep a fixed lock order.
    const {rows:[m]}=await c.query("SELECT status,amount_cents,payer_customer_id FROM securepay_milestones WHERE tenant_id=$1 AND id=$2 FOR UPDATE",[tenantId,milestoneId]);
    if(!m||m.status!=="approved"||m.payer_customer_id!==customerId||String(m.amount_cents)!==String(expectedAmountCents)){
      return denied();
    }
    const {rows:[k]}=await c.query("SELECT salt,pin_hash,failed_attempts,locked_until FROM securepay_customer_pins WHERE tenant_id=$1 AND customer_id=$2 FOR UPDATE",[tenantId,customerId]);
    if(!k){return denied();}
    // Read time after taking the lock (a preceding transaction may have just locked the account).
    const {rows:[t]}=await c.query("SELECT clock_timestamp() AS ts");
    if(k.locked_until&&k.locked_until>t.ts){return denied();}
    const valid=await verifyPinCredential({tenantId,customerId,pin,pepper},{salt:k.salt,pinHash:k.pin_hash});
    if(!valid){
      const count=k.locked_until?1:k.failed_attempts+1;
      await c.query("UPDATE securepay_customer_pins SET failed_attempts=$3,locked_until=CASE WHEN $3>=5 THEN clock_timestamp()+interval '15 minutes' ELSE NULL END WHERE tenant_id=$1 AND customer_id=$2",[tenantId,customerId,count]);
      // Failed attempts MUST survive denial.
      return denied();
    }
    await c.query("UPDATE securepay_customer_pins SET failed_attempts=0,locked_until=NULL WHERE tenant_id=$1 AND customer_id=$2",[tenantId,customerId]);
    const authorizationRef=randomUUID();
    await c.query("INSERT INTO securepay_release_proofs(proof_ref,tenant_id,milestone_id,customer_id,amount_cents,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '5 minutes')",[authorizationRef,tenantId,milestoneId,customerId,String(expectedAmountCents)]);
    // Create AND consume proof in the same transaction. No reusable token leaves service.
    const result=await reserveRelease(c,{tenantId,milestoneId,customerId,requestId,idempotencyKey,authorizationRef,
      verifyAndConsume:({client,...s})=>consumeReleaseProof(client,s)});
    return {ok:true,...result};
}
export async function authorizePayerInTransaction(c,scope,pepper) {
  const {tenantId,subject,milestoneId,pin,requestId,idempotencyKey,expectedAmountCents}=scope;
  const customerId=await resolvePayer(c,{tenantId,subject});
  if(!customerId)return denied();
  return authorizeInTransaction(c,{tenantId,customerId,milestoneId,pin,requestId,idempotencyKey,expectedAmountCents},pepper);
}
// Isolated database fixture / legacy internal adapter. Never expose a route
// accepting a raw customerId; use the verified-subject transaction entry above.
export async function authorizeWithPin(pool,scope,pepper) {
  if(!pool?.connect)throw new Error("PIN authorization unavailable");
  const c=await pool.connect();let active=false,discard;
  try{
    await c.query("BEGIN");active=true;
    const result=await authorizeInTransaction(c,scope,pepper);
    await c.query("COMMIT");active=false;return result;
  }catch(e){
    if(active)try{await c.query("ROLLBACK");}catch(r){discard=r;throw new AggregateError([e,r],"PIN transaction rollback failed");}
    throw e;
  }finally{c.release(discard);}
}

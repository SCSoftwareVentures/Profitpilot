// No real delivery provider is configured by this module. A trusted sandbox
// sink must deduplicate by the stable event key, including ambiguous timeouts.
import {randomUUID} from "node:crypto";
export function makeNotificationWorker({pool,sink,namespace}){
 if(!pool?.query||typeof sink?.send!=="function"||typeof namespace!=="string"||!/^[a-z0-9-]{1,64}$/.test(namespace))
  throw Error("Notification worker unavailable");
 return Object.freeze({async runOnce(){
  const lease=randomUUID();
  const {rows}=await pool.query("SELECT * FROM securepay_private.claim_notification($1::uuid)",[lease]);
  const job=rows[0];if(!job)return {status:"idle"};
  const {notification_id:id,tenant_id:tenantId,customer_id:customerId,event_type:eventType}=job;
  // Do not pass PINs, authentication secrets, or arbitrary customer-provided text.
  const idempotencyKey=namespace+":securepay-security:"+tenantId+":"+id;
  let result;
  try{
   result=await sink.send({idempotencyKey,tenantId,customerId,eventType});
   if(typeof result?.reference!=="string"||result.reference.length<1||result.reference.length>200)throw Error("Invalid delivery receipt");
  }catch{
   const {rows:[r]}=await pool.query("SELECT securepay_private.finish_notification($1::bigint,$2::uuid,false,NULL) AS ok",[id,lease]);
   return {status:r?.ok?"retry_or_dead_letter":"lease_lost",notificationId:id};
  }
  // If this database write fails, leave the lease outstanding. A later
  // re-delivery must pass the identical key to a deduplicating provider.
  const {rows:[r]}=await pool.query("SELECT securepay_private.finish_notification($1::bigint,$2::uuid,true,$3::text) AS ok",[id,lease,result.reference]);
  return {status:r?.ok?"delivered":"lease_lost",notificationId:id};
 }});
}

// Call from a sandbox scheduler. No real mail/SMS integration or external account.
import {randomUUID} from "node:crypto";
export function makeEscalationWorker({escalationPool,notificationPool,sink,namespace}){
 if(!escalationPool?.query||!notificationPool?.query||typeof sink?.send!=="function"||typeof namespace!=="string"||!/^[a-z0-9-]{1,64}$/.test(namespace))throw Error("Escalation worker unavailable");
 let running=false;
 return Object.freeze({async runOnce(){
  if(running)return {status:"busy"};running=true;
  try{
   const {rows:[scan]}=await escalationPool.query("SELECT securepay_private.scan_dispute_deadlines(50) AS cases");
   const lease=randomUUID(),{rows:[job]}=await notificationPool.query("SELECT * FROM securepay_private.claim_escalation($1::uuid)",[lease]);
   if(!job)return {status:"idle",escalatedCases:scan.cases};
   const {notification_id:id,tenant_id:tenantId,case_id:caseId,kind,due_at:dueAt}=job;
   let result;try{result=await sink.send({idempotencyKey:namespace+":securepay-escalation:"+tenantId+":"+id,tenantId,caseId,kind,dueAt:new Date(dueAt).toISOString()});if(typeof result?.reference!=="string"||!/^[a-zA-Z0-9._:-]{1,200}$/.test(result.reference))throw Error("Invalid delivery reference");}
   catch{const {rows:[r]}=await notificationPool.query("SELECT securepay_private.finish_escalation($1,$2,false,NULL) AS ok",[id,lease]);return {status:r?.ok?"retry_or_dead_letter":"lease_lost",notificationId:id,escalatedCases:scan.cases};}
   const {rows:[r]}=await notificationPool.query("SELECT securepay_private.finish_escalation($1,$2,true,$3) AS ok",[id,lease,result.reference]);
   return {status:r?.ok?"delivered":"lease_lost",notificationId:id,escalatedCases:scan.cases};
  }finally{running=false;}
 }});
}

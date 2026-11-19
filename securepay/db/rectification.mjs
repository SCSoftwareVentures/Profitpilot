// Bounded sandbox evidence and rectification operations. Actor secrets are
// provisioned by a trusted administrator; never expose them to clients.
import {createHmac,createHash,randomUUID} from "node:crypto";
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const check=(...ids)=>{if(!ids.every(x=>typeof x==="string"&&uuid.test(x)))throw Error("Invalid repair scope");};
const expires=()=>Math.floor(Date.now()/1000)+15;
export function makeRectificationActor({pool,actorId,key}){
 if(!pool?.query||!Buffer.isBuffer(key)||key.length!==32)throw Error("Repair authority unavailable");
 check(actorId);
 const mac=(parts)=>createHmac("sha256",key).update(parts.join(":")).digest("hex");
 return Object.freeze({
  async storePhoto({photoId=randomUUID(),tenantId,milestoneId,caseId,mediaType,content}){
   check(photoId,tenantId,milestoneId,caseId);
   if(!Buffer.isBuffer(content)||content.length<8||content.length>2097152||!["image/jpeg","image/png"].includes(mediaType))throw Error("Invalid evidence");
   const digest=createHash("sha256").update(content).digest("hex"),exp=expires();
   const sig=mac(["sp-photo-v1",photoId,tenantId,milestoneId,caseId,actorId,mediaType,digest,exp]);
   const {rows:[r]}=await pool.query("SELECT securepay_private.store_dispute_photo($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$6::text,$7::text,$8::bytea,$9::bigint,$10::text) AS ok",[photoId,tenantId,milestoneId,caseId,actorId,mediaType,digest,content,exp,sig]);
   return r.ok?{ok:true,photoId,digest}:{ok:false};
  },
  async readPhoto({photoId,tenantId,milestoneId,caseId}){
   check(photoId,tenantId,milestoneId,caseId);
   const exp=expires(),args=[photoId,tenantId,milestoneId,caseId,actorId,exp];
   const {rows:[r]}=await pool.query("SELECT * FROM securepay_private.read_dispute_photo($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$6::bigint,$7::text)",[...args,mac(["sp-photo-read-v1",...args])]);
   if(!r)return null;
   if(createHash("sha256").update(r.content).digest("hex")!==r.digest)throw Error("Evidence integrity failure");
   return {mediaType:r.media_type,digest:r.digest,content:r.content};
  },
  async repair({eventId=randomUUID(),tenantId,milestoneId,caseId,action,details,dueEpoch=null,photoId=null}){
   check(eventId,tenantId,milestoneId,caseId);
   if(!["propose","reviewer_plan","accept_plan","submit_repair","accept_repair","escalate"].includes(action)||typeof details!=="string"||!details.trim()||details.length>4000||details.includes("\0")||
      (dueEpoch!==null&&!Number.isSafeInteger(dueEpoch)))throw Error("Invalid repair action");
   if(photoId!==null)check(photoId);
   const exp=expires();
   const sig=mac(["sp-repair-v1",eventId,tenantId,milestoneId,caseId,actorId,action,Buffer.from(details).toString("hex"),dueEpoch??"-",photoId??"-",exp]);
   const {rows:[r]}=await pool.query("SELECT securepay_private.repair_action($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$6::text,$7::text,$8::bigint,$9::uuid,$10::bigint,$11::text) AS ok",[eventId,tenantId,milestoneId,caseId,actorId,action,details,dueEpoch,photoId,exp,sig]);
   return {ok:r.ok===true,moneyMoved:false};
  }
 });
}
export async function scanDisputeDeadlines(pool,batchSize=50){
 if(!pool?.query||!Number.isInteger(batchSize)||batchSize<1||batchSize>100)throw Error("Invalid escalation batch");
 const {rows:[r]}=await pool.query("SELECT securepay_private.scan_dispute_deadlines($1::integer) AS escalated",[batchSize]);
 return r.escalated;
}

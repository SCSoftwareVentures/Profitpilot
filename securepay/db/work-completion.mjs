import {createHmac,createHash,randomUUID} from "node:crypto";
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const ids=(...x)=>{if(!x.every(v=>typeof v==="string"&&uuid.test(v)))throw Error("Invalid completion scope");};
const expiry=()=>Math.floor(Date.now()/1000)+15;
export function makeWorkCompletionOwner({pool,actorId,key,scanner}){
 ids(actorId);
 if(!pool?.query||!Buffer.isBuffer(key)||key.length!==32||typeof scanner?.attest!=="function")throw Error("Completion authority unavailable");
 const mac=args=>createHmac("sha256",key).update(args.join(":")).digest("hex");
 return Object.freeze({
  async status({tenantId,milestoneId}){
   ids(tenantId,milestoneId);const exp=expiry(),args=[tenantId,milestoneId,actorId,exp];
   const {rows:[r]}=await pool.query("SELECT securepay_private.owner_work_status($1,$2,$3,$4,$5) AS result",[...args,mac(["sp-work-status-v1",...args])]);
   return r?.result?{ok:true,view:r.result}:{ok:false};
  },
  async start({completionId=randomUUID(),tenantId,milestoneId}){
   ids(completionId,tenantId,milestoneId);const exp=expiry(),args=[completionId,tenantId,milestoneId,actorId,exp];
   const {rows:[r]}=await pool.query("SELECT securepay_private.start_work_completion($1,$2,$3,$4,$5,$6) AS ok",[...args,mac(["sp-work-start-v1",...args])]);
   return r.ok?{ok:true,completionId}:{ok:false};
  },
  async upload({photoId=randomUUID(),completionId,tenantId,milestoneId,mediaType,content}){
   ids(photoId,completionId,tenantId,milestoneId);
   if(!Buffer.isBuffer(content)||content.length<8||content.length>2097152||!["image/png","image/jpeg"].includes(mediaType))throw Error("Invalid completion evidence");
   const original=Buffer.from(content),originalDigest=createHash("sha256").update(original).digest("hex");
   let proof;try{proof=await scanner.attest({photoId,tenantId,milestoneId,caseId:completionId,actorId,mediaType,content:Buffer.from(original)});}catch{return {ok:false};}
   if(!proof||proof.originalDigest!==originalDigest||proof.originalMediaType!==mediaType||!Buffer.isBuffer(proof.content)||proof.content.length>2097152)return {ok:false};
   const normalized=Buffer.from(proof.content),digest=createHash("sha256").update(normalized).digest("hex"),exp=expiry();
   if(proof.digest!==digest||(mediaType==="image/png"&&!normalized.equals(original)))return {ok:false};
   const scope=[photoId,completionId,tenantId,milestoneId,actorId,digest,mediaType,originalDigest];
   const {rows:[r]}=await pool.query("SELECT securepay_private.store_work_photo($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) AS ok",[...scope,normalized,exp,mac(["sp-work-photo-v1",...scope,exp]),proof.exp,proof.signature]);
   return r.ok?{ok:true,photoId,digest}:{ok:false};
  },
  async submit({completionId,tenantId,milestoneId,comments=""}){
   ids(completionId,tenantId,milestoneId);
   if(typeof comments!=="string"||comments.length>2000||comments.includes("\0"))throw Error("Invalid completion comments");
   const exp=expiry(),scope=[completionId,tenantId,milestoneId,actorId];
   const {rows:[r]}=await pool.query("SELECT securepay_private.submit_work_completion($1,$2,$3,$4,$5,$6,$7) AS ok",[...scope,comments,exp,mac(["sp-work-submit-v1",...scope,Buffer.from(comments).toString("hex"),exp])]);
   return {ok:r.ok===true,moneyMoved:false};
  }
 });
}

import {createHmac,createHash,randomUUID} from "node:crypto";
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const ids=(...xs)=>{if(!xs.every(x=>typeof x==="string"&&uuid.test(x)))throw Error("Invalid review scope");};
export function makeReviewer({pool,tenantId,actorId,key}){
 ids(tenantId,actorId);if(!pool?.query||!Buffer.isBuffer(key)||key.length!==32)throw Error("Invalid reviewer authority");
 const mac=x=>createHmac("sha256",key).update(x.join(":")).digest("hex"),expiry=()=>Math.floor(Date.now()/1000)+15;
 return Object.freeze({
  async queue(){const args=[tenantId,actorId,expiry()];const {rows:[r]}=await pool.query("SELECT securepay_private.reviewer_queue($1,$2,$3,$4) AS result",[...args,mac(["sp-review-queue-v1",...args])]);return r?.result??null;},
  async read(caseId){ids(caseId);const args=[tenantId,caseId,actorId,expiry()];const {rows:[r]}=await pool.query("SELECT securepay_private.reviewer_case($1,$2,$3,$4,$5) AS result",[...args,mac(["sp-review-case-v1",...args])]);return r?.result??null;},
  async photo({caseId,photoId,source}){ids(caseId,photoId);if(!["dispute","completion"].includes(source))throw Error("Invalid source");const args=[tenantId,caseId,actorId,photoId,source,expiry()];const {rows:[r]}=await pool.query("SELECT securepay_private.reviewer_photo($1,$2,$3,$4,$5,$6,$7) AS result",[...args,mac(["sp-review-photo-v1",...args])]);const x=r?.result;if(!x)return null;const b=Buffer.from(x.content,"base64");if(x.photoId!==photoId||b.length<8||b.length>2097152||b.toString("base64")!==x.content||b.subarray(0,8).toString("hex")!=="89504e470d0a1a0a"||createHash("sha256").update(b).digest("hex")!==x.digest)throw Error("Invalid evidence response");return {photoId,digest:x.digest,content:x.content};},
  async decide({caseId,action,reason,payoutCents,refundCents,stateDigest}){ids(caseId);if(!["decide","finalize"].includes(action)||typeof reason!=="string"||reason.trim().length<10||reason.length>4000||reason.includes("\0")||![payoutCents,refundCents].every(x=>Number.isSafeInteger(x)&&x>=0)||typeof stateDigest!=="string"||!/^[a-f0-9]{64}$/.test(stateDigest))throw Error("Invalid review decision");
   const e=randomUUID(),exp=expiry(),args=[e,tenantId,caseId,actorId,action,reason,payoutCents,refundCents,stateDigest,exp];
   const sig=mac(["sp-review-decision-v1",e,tenantId,caseId,actorId,action,Buffer.from(reason).toString("hex"),payoutCents,refundCents,stateDigest,exp]);
   const {rows:[r]}=await pool.query("SELECT securepay_private.reviewer_decision($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) AS ok",[...args,sig]);return {ok:r?.ok===true,moneyMoved:false};
  }
 });
}

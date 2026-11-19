// Strict participant response projection; do not forward raw database objects.
import {createHash} from "node:crypto";
const id=x=>typeof x==="string"&&/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(x),hash=x=>typeof x==="string"&&/^[a-f0-9]{64}$/.test(x);
const text=(x,n)=>typeof x==="string"&&x.length<=n;
const cents=x=>typeof x==="string"&&/^(0|[1-9][0-9]{0,18})$/.test(x);
const date=x=>x===null||typeof x==="string"&&x.length<=40&&Number.isFinite(Date.parse(x));
const bool=x=>typeof x==="boolean";
function invalid(){throw Error("Invalid participant response");}
export function projectParticipant(op,result,milestoneId,role,body){
 if(!result||!id(milestoneId))invalid();
 if(op==="photo"||op==="upload"){
  if(!id(result.photoId)||!hash(result.digest))invalid();
  if(op==="upload")return {photoId:result.photoId,digest:result.digest};
  if(result.photoId!==body.photoId||typeof result.content!=="string"||result.content.length>2796204)invalid();
  const b=Buffer.from(result.content,"base64");if(b.length<8||b.length>2097152||b.toString("base64")!==result.content||b.subarray(0,8).toString("hex")!=="89504e470d0a1a0a"||createHash("sha256").update(b).digest("hex")!==result.digest)invalid();
  return {photoId:result.photoId,digest:result.digest,content:result.content};
 }
 if(op!=="view"){if(result.recorded!==true)invalid();return {recorded:true};}
 const c=result.case;if(!c||!hash(result.stateDigest)||!id(c.caseId)||c.milestoneId!==milestoneId||c.role!==role||!["open","decided","appealed","final","authorized","settled"].includes(c.status)||!["minor","moderate","serious"].includes(c.severity)||!["none","proposed","active","submitted","accepted","escalated"].includes(c.repairPhase)||!(c.repairPhotoId===null||id(c.repairPhotoId))||!["funded","held","settled","released"].includes(c.fundingStatus))invalid();
 for(const k of ["repairDueAt","repairReviewDueAt","responseDueAt","ownerRespondedAt"])if(!date(c[k]))invalid();
 for(const k of ["customerEvidence","ownerEvidence","customerAck","ownerAck","customerAppealEvidence","ownerAppealEvidence","negotiated"])if(!bool(c[k]))invalid();
 for(const k of ["amountCents","confirmedPayoutCents","confirmedRefundCents","remainingCents"])if(!cents(c[k]))invalid();
 if(BigInt(c.confirmedPayoutCents)+BigInt(c.confirmedRefundCents)+BigInt(c.remainingCents)!==BigInt(c.amountCents))invalid();
 if(![c.payoutCents,c.refundCents].every(x=>x===null||cents(x))||(c.payoutCents===null)!==(c.refundCents===null))invalid();
 if(c.decision!==null&&(!id(c.decision?.eventId)||!text(c.decision.reason,4000)||!hash(c.decision.digest)||c.payoutCents===null||BigInt(c.payoutCents)+BigInt(c.refundCents)!==BigInt(c.amountCents)))invalid();
 if(!Array.isArray(c.events)||c.events.length>200||!Array.isArray(c.photos)||c.photos.length>12||!Array.isArray(c.linkedPhotos)||c.linkedPhotos.length>60)invalid();
 const photos=(xs,source)=>xs.map(p=>{if(!id(p?.photoId)||!hash(p.digest)||!bool(p.purged)||!bool(p.mine)||p.source!==source)invalid();return {photoId:p.photoId,digest:p.digest,purged:p.purged,source,mine:p.mine};});
 const events=c.events.map(e=>{if(!id(e?.eventId)||!text(e.action,60)||!text(e.details,4000)||!date(e.at)||!(e.digest===null||hash(e.digest))||!["owner","customer","independent"].includes(e.role))invalid();return {eventId:e.eventId,action:e.action,details:e.details,at:e.at,digest:e.digest,role:e.role};});
 const keys=["caseId","milestoneId","role","status","severity","repairPhase","repairPhotoId","repairDueAt","repairReviewDueAt","responseDueAt","ownerRespondedAt","customerEvidence","ownerEvidence","customerAck","ownerAck","customerAppealEvidence","ownerAppealEvidence","amountCents","payoutCents","refundCents","fundingStatus","confirmedPayoutCents","confirmedRefundCents","remainingCents","negotiated"];
 return {stateDigest:result.stateDigest,case:{...Object.fromEntries(keys.map(k=>[k,c[k]])),decision:c.decision===null?null:{eventId:c.decision.eventId,reason:c.decision.reason,digest:c.decision.digest},events,photos:photos(c.photos,"dispute"),linkedPhotos:photos(c.linkedPhotos,"completion")}};
}

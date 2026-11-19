// Non-executing correction assessment; each signer owns its own key.
import {createHmac,randomUUID} from "node:crypto";
import {signEnvelope} from "./key-envelope.mjs";
const id=x=>typeof x==="string"&&/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(x),hash=x=>typeof x==="string"&&/^[a-f0-9]{64}$/.test(x),amount=x=>Number.isSafeInteger(x)&&x>=0;
const mac=(key,payload)=>{if(!Buffer.isBuffer(key)||key.length!==32)throw Error("Invalid authority key");return createHmac("sha256",key).update(payload.join(":")).digest("hex");};
export function makeCorrectionActor({pool,tenantId,actorId,key,role}){
 if(!id(tenantId)||!id(actorId)||!pool?.query||!["administrator","reconciler"].includes(role)||!Buffer.isBuffer(key)||key.length!==32)throw Error("Invalid correction authority");
 const expiry=()=>Math.floor(Date.now()/1000)+15;
 const read=async correctionId=>{if(!id(correctionId))throw Error("Invalid correction reference");const args=[tenantId,correctionId,actorId,expiry()];return (await pool.query("SELECT securepay_private.correction_read($1,$2,$3,$4,$5) AS result",[...args,mac(key,["sp-correction-read-v1",...args])])).rows[0]?.result??null;};
 if(role==="reconciler")return Object.freeze({read});
 return Object.freeze({read,async request({caseId,actorOne,actorTwo,payoutCents,refundCents,reason,correctionId=randomUUID()}){
  if(![caseId,actorOne,actorTwo,correctionId].every(id)||actorOne===actorTwo||!amount(payoutCents)||!amount(refundCents)||typeof reason!=="string"||reason.trim().length<10||reason.length>1000||reason.includes("\0"))throw Error("Invalid correction proposal");
  const exp=expiry(),args=[correctionId,tenantId,caseId,actorId,actorOne,actorTwo,payoutCents,refundCents,reason,exp];
  const sig=mac(key,["sp-correction-request-v1",...args.slice(0,8),Buffer.from(reason).toString("hex"),exp]);
  return (await pool.query("SELECT securepay_private.correction_request($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) AS result",[...args,sig])).rows[0]?.result??null;
 }});
}
function fields(p){
 if(![p.correctionId,p.tenantId,p.caseId,p.settlementId,p.actorOne,p.actorTwo].every(id)||p.actorOne===p.actorTwo||!amount(p.payoutCents)||!amount(p.refundCents)||!hash(p.stateDigest)||!hash(p.evidenceDigest)||!Number.isSafeInteger(p.expires))throw Error("Invalid correction packet");
 return ["sp-correction-endorse-v1",p.correctionId,p.tenantId,p.caseId,p.settlementId,p.payoutCents,p.refundCents,p.stateDigest,p.evidenceDigest,p.actorOne,p.actorTwo,p.expires];
}
export function prepareCorrection(tenantId,view,evidenceDigest){
 if(view?.status!=="pending"||!view.current||!view.snapshot?.safeToEndorse)throw Error("Current safe correction required");
 const p={correctionId:view.correctionId,tenantId,caseId:view.caseId,settlementId:view.snapshot.settlementId,actorOne:view.actorOne,actorTwo:view.actorTwo,payoutCents:Number(view.snapshot.proposedPayoutCents),refundCents:Number(view.snapshot.proposedRefundCents),stateDigest:view.stateDigest,evidenceDigest,expires:Math.floor(Date.now()/1000)+25};fields(p);return Object.freeze(p);
}
export function signCorrectionProvider(p,key,keyId="primary"){return signEnvelope(key,keyId,fields(p).join(":"));}
export function signCorrectionReconciler(p,actorId,key){if(![p.actorOne,p.actorTwo].includes(actorId))throw Error("Wrong reconciler");return mac(key,fields(p));}
export async function endorseCorrection(pool,p,provider,first,second){
 fields(p);const {rows:[r]}=await pool.query("SELECT securepay_private.correction_endorse($1,$2,$3,$4,$5,$6,$7,$8,$9) AS ok",[p.correctionId,p.tenantId,p.caseId,p.stateDigest,p.evidenceDigest,p.expires,provider,first,second]);
 return {ok:r?.ok===true,moneyMoved:false};
}

// Sandbox reconciliation only. Provider and independent reviewers must sign
// the same immutable packet independently; never expose their keys to clients.
import {createHmac,randomUUID} from "node:crypto";
import {signEnvelope} from "./key-envelope.mjs";
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const hex=/^[a-f0-9]{64}$/;
function payload(p){
 const ids=[p.resolutionId,p.settlementId,p.tenantId,p.milestoneId,p.caseId,p.actorOne,p.actorTwo];
 if(!ids.every(x=>typeof x==="string"&&uuid.test(x))||p.actorOne===p.actorTwo||
 !["confirm","retry_once","clear_conflict","lift_hold"].includes(p.action)||
 (p.action==="lift_hold")!==(p.legId===null)||(["confirm","clear_conflict"].includes(p.action))!==(p.receipt!==null)||
 [p.legId,p.receipt].some(x=>x!==null&&(typeof x!=="string"||!uuid.test(x)))||
 !hex.test(p.stateDigest)||!hex.test(p.evidenceDigest)||typeof p.reason!=="string"||p.reason.trim().length<10||p.reason.length>1000||
 p.reason.includes("\0")||!Number.isSafeInteger(p.expires))throw Error("Invalid reconciliation packet");
 return ["sp-recovery-v1",p.resolutionId,p.settlementId,p.tenantId,p.milestoneId,p.caseId,p.legId??"-",p.action,p.receipt??"-",p.stateDigest,p.evidenceDigest,Buffer.from(p.reason).toString("hex"),p.actorOne,p.actorTwo,p.expires].join(":");
}
export async function prepareRecovery(pool,{settlementId,tenantId,milestoneId,caseId,legId=null,action,receipt=null,evidenceDigest,reason,actorOne,actorTwo}){
 const {rows:[r]}=await pool.query("SELECT securepay_private.recovery_state($1::uuid,$2::uuid,$3::uuid,$4::uuid) AS digest",[settlementId,tenantId,milestoneId,caseId]);
 if(!r?.digest)throw Error("Reconciliation scope unavailable");
 const p={resolutionId:randomUUID(),settlementId,tenantId,milestoneId,caseId,legId,action,receipt,stateDigest:r.digest,evidenceDigest,reason,actorOne,actorTwo,expires:Math.floor(Date.now()/1000)+25};
 payload(p);return Object.freeze(p);
}
export function signProviderRecovery(packet,key,keyId="primary"){return signEnvelope(key,keyId,payload(packet));}
export function signReviewerRecovery(packet,actorId,key){
 if(![packet.actorOne,packet.actorTwo].includes(actorId)||!Buffer.isBuffer(key)||key.length!==32)throw Error("Reviewer authority unavailable");
 return createHmac("sha256",key).update(payload(packet)).digest("hex");
}
export async function applyRecovery(pool,p,providerSignature,firstSignature,secondSignature){
 payload(p);
 const args=[p.resolutionId,p.settlementId,p.tenantId,p.milestoneId,p.caseId,p.legId,p.action,p.receipt,p.stateDigest,p.evidenceDigest,p.reason,p.actorOne,p.actorTwo,p.expires,providerSignature,firstSignature,secondSignature];
 const {rows:[r]}=await pool.query("SELECT securepay_private.recover_settlement($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$6::uuid,$7::text,$8::uuid,$9::text,$10::text,$11::text,$12::uuid,$13::uuid,$14::bigint,$15::text,$16::text,$17::text) AS ok",args);
 return {ok:r.ok===true,mode:"sandbox",moneyMoved:false};
}

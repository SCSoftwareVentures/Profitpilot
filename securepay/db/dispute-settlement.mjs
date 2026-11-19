// Synthetic actor keys are provisioned by a trusted administrator. No real identity
// onboarding, provider network, custody or transfers. Never expose these signers.
import {createHmac,randomUUID} from "node:crypto";
import {signEnvelope,validKeyId} from "./key-envelope.mjs";
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
function checkIds(...ids){if(!ids.every(x=>typeof x==="string"&&uuid.test(x)))throw Error("Invalid dispute scope");}
function checkKey(pool,key){if(!pool?.query||!Buffer.isBuffer(key)||key.length!==32)throw Error("Dispute authority unavailable");}
function cents(n){return n===null||(Number.isSafeInteger(n)&&n>=0);}
const expiry=()=>Math.floor(Date.now()/1000)+15;
const mac=(key,parts)=>createHmac("sha256",key).update(parts.join(":")).digest("hex");
const response=ok=>({ok:ok===true,mode:"sandbox",moneyMoved:false});
export function makeDisputeActor({pool,key,actorId}){
 checkKey(pool,key);checkIds(actorId);
 return Object.freeze({async action({eventId=randomUUID(),tenantId,milestoneId,caseId,action,details,evidenceDigest=null,payoutCents=null,refundCents=null}){
  checkIds(eventId,tenantId,milestoneId,caseId);
  if(!["open","evidence","decide","finalize","ack","appeal"].includes(action)||typeof details!=="string"||details.length>4000||details.includes("\0")||
     !(evidenceDigest===null||/^[a-f0-9]{64}$/.test(evidenceDigest))||!cents(payoutCents)||!cents(refundCents))throw Error("Invalid dispute action");
  const x=expiry(),sig=mac(key,["sp-dispute-v1",eventId,tenantId,milestoneId,caseId,actorId,action,Buffer.from(details).toString("hex"),evidenceDigest??"-",payoutCents??"-",refundCents??"-",x]);
  const {rows:[r]}=await pool.query("SELECT securepay_private.dispute_action($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$6::text,$7::text,$8::text,$9::bigint,$10::bigint,$11::bigint,$12::text) AS ok",[eventId,tenantId,milestoneId,caseId,actorId,action,details,evidenceDigest,payoutCents,refundCents,x,sig]);
  return response(r.ok);
 }});
}
export function makeSettlementAuthorizer({pool,key,actorId}){
 checkKey(pool,key);checkIds(actorId);
 return Object.freeze({async authorize({settlementId,tenantId,milestoneId,caseId,payoutCents,refundCents}){
  checkIds(settlementId,tenantId,milestoneId,caseId);
  if(payoutCents===null||refundCents===null||!cents(payoutCents)||!cents(refundCents))throw Error("Invalid settlement amounts");
  const x=expiry(),args=[settlementId,tenantId,milestoneId,caseId,actorId,payoutCents,refundCents,x];
  const {rows:[r]}=await pool.query("SELECT securepay_private.authorize_settlement($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$6::bigint,$7::bigint,$8::bigint,$9::text) AS ok",[...args,mac(key,["sp-settlement-v1",...args])]);
  return response(r.ok);
 }});
}
export function makeSettlementProvider({pool,key,keyId="primary"}){
 checkKey(pool,key);if(!validKeyId(keyId))throw Error("Invalid provider key ID");
 return Object.freeze({async dispatch({settlementId,tenantId,milestoneId,caseId}){
  checkIds(settlementId,tenantId,milestoneId,caseId);
  const {rows:[r]}=await pool.query("SELECT securepay_private.begin_settlement_dispatch($1::uuid,$2::uuid,$3::uuid,$4::uuid) AS ok",[settlementId,tenantId,milestoneId,caseId]);
  return response(r.ok);
 },async confirm({settlementId,tenantId,milestoneId,caseId,receipt,payoutCents,refundCents}){
  checkIds(settlementId,tenantId,milestoneId,caseId,receipt);
  if(payoutCents===null||refundCents===null||!cents(payoutCents)||!cents(refundCents))throw Error("Invalid settlement amounts");
  const x=expiry(),args=[settlementId,tenantId,milestoneId,caseId,receipt,payoutCents,refundCents,x];
  const sig=signEnvelope(key,keyId,["sp-settlement-receipt-v1",...args].join(":"));
  const {rows:[r]}=await pool.query("SELECT securepay_private.confirm_settlement($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$6::bigint,$7::bigint,$8::bigint,$9::text) AS ok",[...args,sig]);
  return response(r.ok);
 }});
}

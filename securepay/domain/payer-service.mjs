// Unmounted customer service boundary. HTTP auth middleware must supply the
// verified identity; never populate it from request data.
// No live dispatch or external provider access.
import {randomUUID} from "node:crypto";
import {withPayer} from "../db/with-payer.mjs";
import {authorizePayerInTransaction} from "../db/authorize-with-pin.mjs";
import {changePin,resolvePayer} from "../db/change-pin.mjs";
import {validKeyId} from "../db/key-envelope.mjs";
import {issueRecoveryGrant} from "../db/recovery-grant.mjs";
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
function exact(body,keys){
 return body!==null&&typeof body==="object"&&!Array.isArray(body)&&
 Object.keys(body).length===keys.length&&keys.every(k=>Object.hasOwn(body,k));
}
export function makePayerService({pool,signingKey,pepper,recoveryKey,verifyRecovery,contextKeyId="primary",commandAuthority,recoveryKeyId="primary"}){
 if(!pool?.connect||!Buffer.isBuffer(signingKey)||signingKey.length!==32||!validKeyId(contextKeyId)||
    !Buffer.isBuffer(pepper)||pepper.length<32||signingKey.equals(pepper))
  throw new Error("SecurePay service unavailable");
 if(commandAuthority&&(!Buffer.isBuffer(commandAuthority.key)||commandAuthority.key.length!==32||!validKeyId(commandAuthority.id)||commandAuthority.key.equals(signingKey)||commandAuthority.key.equals(pepper)))throw Error("SecurePay command authority unavailable");
 const recoveryEnabled=recoveryKey!==undefined||verifyRecovery!==undefined;
 if(recoveryEnabled&&(!Buffer.isBuffer(recoveryKey)||recoveryKey.length!==32||recoveryKey.equals(signingKey)||recoveryKey.equals(pepper)||!validKeyId(recoveryKeyId)||(commandAuthority&&recoveryKey.equals(commandAuthority.key))||typeof verifyRecovery!=="function"))
  throw new Error("SecurePay recovery unavailable");
 function context(identity,tenantId){
  const now=Math.floor(Date.now()/1000);
  if(!identity||typeof identity.subject!=="string"||!identity.subject||identity.subject.length>512||!Number.isSafeInteger(identity.authTime)||identity.authTime>now||identity.authTime<now-300)
   throw Object.assign(new Error("Authentication required"),{status:401});
  if(typeof tenantId!=="string"||!uuid.test(tenantId))
   throw Object.assign(new Error("Invalid request"),{status:400});
  return {subject:identity.subject,tenantId,signingKey,contextKeyId,authTime:identity.authTime};
 }
 // Hold the same identity lock as PIN recovery, so a concurrent reset
 // cannot race an authenticated request past the revocation cutoff.
 const authenticated=(ctx,fn,stepUpTime=ctx.authTime)=>withPayer(pool,ctx,async c=>{
  const customerId=await resolvePayer(c,ctx);
  if(!customerId)return {ok:false};
  const {rows:[r]}=await c.query("SELECT (session_revoked_at IS NULL OR (to_timestamp($3)>session_revoked_at AND to_timestamp($4)>session_revoked_at)) AS valid FROM securepay_payer_identities WHERE tenant_id=$1 AND customer_id=$2",[ctx.tenantId,customerId,ctx.authTime,stepUpTime]);
  if(r?.valid!==true)return {ok:false};
  return fn(c);
 });
 const bad=()=>{throw Object.assign(new Error("Invalid request"),{status:400});};
 return Object.freeze({
  async view({identity,tenantId,milestoneId,body}){
   const ctx=context(identity,tenantId);
   if(typeof milestoneId!=="string"||!uuid.test(milestoneId)||!exact(body,[]))bad();
   return authenticated(ctx,async c=>{
    const {rows:[r]}=await c.query("SELECT * FROM securepay_private.payer_milestone_view($1,$2)",[tenantId,milestoneId]);
    if(!r)return {ok:false};
    return {ok:true,view:{milestoneId:r.milestone_id,amountCents:r.amount_cents,status:r.status,fundingStatus:r.funding_status,isFinal:r.is_final,requestStatus:r.request_status}};
   });
  },
  async reserve({identity,tenantId,milestoneId,body}){
   const ctx=context(identity,tenantId);
   if(typeof milestoneId!=="string"||!uuid.test(milestoneId)||
      !exact(body,["pin","expectedAmountCents","idempotencyKey"])||
      typeof body.pin!=="string"||!/^[0-9]{6}$/.test(body.pin)||
      !Number.isSafeInteger(body.expectedAmountCents)||body.expectedAmountCents<=0||
      typeof body.idempotencyKey!=="string"||!uuid.test(body.idempotencyKey))bad();
   return authenticated(ctx,c=>authorizePayerInTransaction(c,{tenantId,subject:ctx.subject,milestoneId,
      pin:body.pin,expectedAmountCents:body.expectedAmountCents,idempotencyKey:body.idempotencyKey,requestId:randomUUID()},pepper,commandAuthority));
  },
  async issueGrant({identity,tenantId,body}){
   const ctx=context(identity,tenantId);
   if(!recoveryEnabled)throw Object.assign(new Error("Recovery unavailable"),{status:503});
   if(!exact(body,["purpose","stepUpToken"])||!["enroll","recover"].includes(body.purpose)||
      typeof body.stepUpToken!=="string"||body.stepUpToken.length>4096||!body.stepUpToken)bad();
   let assertion;
   try{assertion=await verifyRecovery(body.stepUpToken,{subject:ctx.subject,tenantId,purpose:body.purpose});}
   catch{return {ok:false};}
   return authenticated(ctx,c=>issueRecoveryGrant(c,{tenantId,subject:ctx.subject,purpose:body.purpose,assertion},recoveryKey,recoveryKeyId),assertion.authTime);
  },
  async setPin({identity,tenantId,body}){
   const ctx=context(identity,tenantId);
   if(!exact(body,["pin","purpose","grantRef"])||!["enroll","recover"].includes(body.purpose)||
      typeof body.pin!=="string"||!/^[0-9]{6}$/.test(body.pin)||
      typeof body.grantRef!=="string"||!uuid.test(body.grantRef))bad();
   return authenticated(ctx,c=>changePin(c,{tenantId,subject:ctx.subject,
     pin:body.pin,purpose:body.purpose,grantRef:body.grantRef},pepper,commandAuthority));
  }
 });
}

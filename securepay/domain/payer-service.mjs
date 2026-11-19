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
  async fundedCancellation({identity,tenantId,planId,body}){
   const ctx=context(identity,tenantId);if(typeof planId!=="string"||!uuid.test(planId)||!exact(body,[]))bad();
   return authenticated(ctx,async c=>{
    const {rows:[r]}=await c.query("SELECT securepay_private.payer_funded_cancel_view($1,$2) AS view",[tenantId,planId]);
    return r?.view?{ok:true,fundedCancellation:r.view}:{ok:false};
   });
  },
  async acceptFundedCancellation({identity,tenantId,planId,body}){
   const ctx=context(identity,tenantId);if(typeof planId!=="string"||!uuid.test(planId)||!exact(body,["offerId","offerDigest","payoutCents","refundCents"])||typeof body.offerId!=="string"||!uuid.test(body.offerId)||typeof body.offerDigest!=="string"||!/^[a-f0-9]{64}$/.test(body.offerDigest)||!Number.isSafeInteger(body.payoutCents)||body.payoutCents<0||!Number.isSafeInteger(body.refundCents)||body.refundCents<=0)bad();
   return authenticated(ctx,async c=>{
    const caseId=randomUUID();
    const {rows:[r]}=await c.query("SELECT securepay_private.accept_funded_cancel($1,$2,$3,$4,$5,$6,$7,$8) AS ok",[tenantId,planId,body.offerId,caseId,randomUUID(),body.offerDigest,body.payoutCents,body.refundCents]);
    return r?.ok?{ok:true,negotiatedCase:caseId}:{ok:false};
   });
  },
  async appealNegotiated({identity,tenantId,planId,body}){
   const ctx=context(identity,tenantId);if(typeof planId!=="string"||!uuid.test(planId)||!exact(body,["offerId","decisionId","reason","evidenceDigest"])||![body.offerId,body.decisionId].every(x=>typeof x==="string"&&uuid.test(x))||typeof body.reason!=="string"||body.reason.trim().length<10||body.reason.length>2000||body.reason.includes("\0")||typeof body.evidenceDigest!=="string"||!/^[a-f0-9]{64}$/.test(body.evidenceDigest))bad();
   return authenticated(ctx,async c=>{
    const {rows:[r]}=await c.query("SELECT securepay_private.payer_appeal_negotiated($1,$2,$3,$4,$5,$6,$7) AS ok",[tenantId,planId,body.offerId,randomUUID(),body.decisionId,body.reason,body.evidenceDigest]);
    return r?.ok?{ok:true,negotiatedAppealed:true}:{ok:false};
   });
  },
  async acknowledgeNegotiated({identity,tenantId,planId,body}){
   const ctx=context(identity,tenantId);if(typeof planId!=="string"||!uuid.test(planId)||!exact(body,["offerId","decisionId","payoutCents","refundCents"])||![body.offerId,body.decisionId].every(x=>typeof x==="string"&&uuid.test(x))||![body.payoutCents,body.refundCents].every(x=>Number.isSafeInteger(x)&&x>=0))bad();
   return authenticated(ctx,async c=>{
    const {rows:[r]}=await c.query("SELECT securepay_private.payer_ack_negotiated($1,$2,$3,$4,$5,$6,$7) AS ok",[tenantId,planId,body.offerId,randomUUID(),body.decisionId,body.payoutCents,body.refundCents]);
    return r?.ok?{ok:true,negotiatedAcknowledged:true}:{ok:false};
   });
  },
  async contract({identity,tenantId,planId,body}){
   const ctx=context(identity,tenantId);if(typeof planId!=="string"||!uuid.test(planId)||!exact(body,[]))bad();
   return authenticated(ctx,async c=>{
    const {rows:[r]}=await c.query("SELECT securepay_private.payer_contract_view($1,$2) AS contract",[tenantId,planId]);
    return r?.contract?{ok:true,contract:r.contract}:{ok:false};
   });
  },
  async acceptChange({identity,tenantId,planId,body}){
   const ctx=context(identity,tenantId);if(typeof planId!=="string"||!uuid.test(planId)||!exact(body,["changeId","changeDigest","expectedTotalCents"])||typeof body.changeId!=="string"||!uuid.test(body.changeId)||typeof body.changeDigest!=="string"||!/^[a-f0-9]{64}$/.test(body.changeDigest)||!Number.isSafeInteger(body.expectedTotalCents)||body.expectedTotalCents<0)bad();
   return authenticated(ctx,async c=>{
    const {rows:[r]}=await c.query("SELECT securepay_private.accept_contract_change($1,$2,$3,$4,$5) AS ok",[tenantId,planId,body.changeId,body.changeDigest,body.expectedTotalCents]);
    return r?.ok?{ok:true,changeAccepted:body.changeId}:{ok:false};
   });
  },
  async plan({identity,tenantId,planId,body}){
   const ctx=context(identity,tenantId);if(typeof planId!=="string"||!uuid.test(planId)||!exact(body,[]))bad();
   return authenticated(ctx,async c=>{
    const {rows:[r]}=await c.query("SELECT securepay_private.payer_plan_view($1,$2) AS plan",[tenantId,planId]);
    return r?.plan?{ok:true,plan:r.plan}:{ok:false};
   });
  },
  async acceptPlan({identity,tenantId,planId,body,requireQuote=false}){
   const ctx=context(identity,tenantId);if(typeof planId!=="string"||!uuid.test(planId)||!exact(body,["planDigest","expectedTotalCents"])||typeof body.planDigest!=="string"||!/^[a-f0-9]{64}$/.test(body.planDigest)||!Number.isSafeInteger(body.expectedTotalCents)||body.expectedTotalCents<=0)bad();
   return authenticated(ctx,async c=>{
    if(requireQuote){
     const {rows:[v]}=await c.query("SELECT securepay_private.payer_plan_view($1,$2) AS plan",[tenantId,planId]);
     if(!v?.plan?.quote)return {ok:false};
    }
    const {rows:[r]}=await c.query("SELECT securepay_private.accept_payment_plan($1,$2,$3,$4) AS ok",[tenantId,planId,body.planDigest,body.expectedTotalCents]);
    return r?.ok?{ok:true,planAccepted:planId}:{ok:false};
   });
  },
  async view({identity,tenantId,milestoneId,body}){
   const ctx=context(identity,tenantId);
   if(typeof milestoneId!=="string"||!uuid.test(milestoneId)||!exact(body,[]))bad();
   return authenticated(ctx,async c=>{
    const {rows:[r]}=await c.query("SELECT * FROM securepay_private.payer_milestone_view($1,$2)",[tenantId,milestoneId]);
    if(!r)return {ok:false};
    return {ok:true,view:{milestoneId:r.milestone_id,amountCents:r.amount_cents,status:r.status,fundingStatus:r.funding_status,isFinal:r.is_final,requestStatus:r.request_status}};
   });
  },
  async completion({identity,tenantId,milestoneId,body}){
   const ctx=context(identity,tenantId);
   if(typeof milestoneId!=="string"||!uuid.test(milestoneId)||!exact(body,[]))bad();
   return authenticated(ctx,async c=>{
    const {rows:[r]}=await c.query("SELECT securepay_private.payer_completion_view($1,$2) AS completion",[tenantId,milestoneId]);
    return r?.completion?{ok:true,completion:r.completion}:{ok:false};
   });
  },
  async photo({identity,tenantId,milestoneId,body}){
   const ctx=context(identity,tenantId);
   if(!uuid.test(milestoneId)||!exact(body,["photoId"])||typeof body.photoId!=="string"||!uuid.test(body.photoId))bad();
   return authenticated(ctx,async c=>{
    const {rows:[r]}=await c.query("SELECT * FROM securepay_private.payer_work_photo($1,$2,$3)",[tenantId,milestoneId,body.photoId]);
    if(!r)return {ok:false};
    return {ok:true,photo:{photoId:body.photoId,digest:r.digest,content:r.content.toString("base64")}};
   });
  },
  async approve({identity,tenantId,milestoneId,body}){
   const ctx=context(identity,tenantId);
   if(!uuid.test(milestoneId)||!exact(body,["completionId","manifestDigest","expectedAmountCents","version"])||
    typeof body.completionId!=="string"||!uuid.test(body.completionId)||typeof body.manifestDigest!=="string"||!/^[a-f0-9]{64}$/.test(body.manifestDigest)||
    !Number.isSafeInteger(body.expectedAmountCents)||body.expectedAmountCents<=0||typeof body.version!=="string"||!/^(0|[1-9][0-9]{0,18})$/.test(body.version)||BigInt(body.version)>=9223372036854775807n)bad();
   return authenticated(ctx,async c=>{
    const {rows:[r]}=await c.query("SELECT securepay_private.approve_work_completion($1,$2,$3,$4,$5,$6) AS ok",[tenantId,milestoneId,body.completionId,body.manifestDigest,body.expectedAmountCents,body.version]);
    return r?.ok?{ok:true,workApproved:true}:{ok:false};
   });
  },
  async reject({identity,tenantId,milestoneId,body}){
   const ctx=context(identity,tenantId);
   if(!uuid.test(milestoneId)||!exact(body,["completionId","manifestDigest","version","reason"])||!uuid.test(body.completionId)||typeof body.manifestDigest!=="string"||!/^[a-f0-9]{64}$/.test(body.manifestDigest)||typeof body.version!=="string"||!/^(0|[1-9][0-9]{0,18})$/.test(body.version)||BigInt(body.version)>=9223372036854775807n||typeof body.reason!=="string"||body.reason.trim().length<10||body.reason.length>2000||body.reason.includes("\0"))bad();
   return authenticated(ctx,async c=>{
    const {rows:[r]}=await c.query("SELECT securepay_private.reject_work_completion($1,$2,$3,$4,$5,$6) AS ok",[tenantId,milestoneId,body.completionId,body.manifestDigest,body.version,body.reason]);
    return r?.ok?{ok:true,workRejected:true}:{ok:false};
   });
  },
  async dispute({identity,tenantId,milestoneId,body}){
   const ctx=context(identity,tenantId);
   if(!uuid.test(milestoneId)||!exact(body,["caseId","severity","manifestDigest","version","reason"])||!uuid.test(body.caseId)||!["minor","moderate","serious"].includes(body.severity)||typeof body.manifestDigest!=="string"||!/^[a-f0-9]{64}$/.test(body.manifestDigest)||typeof body.version!=="string"||!/^(0|[1-9][0-9]{0,18})$/.test(body.version)||BigInt(body.version)>=9223372036854775807n||typeof body.reason!=="string"||body.reason.trim().length<10||body.reason.length>2000||body.reason.includes("\0"))bad();
   return authenticated(ctx,async c=>{
    const {rows:[r]}=await c.query("SELECT securepay_private.payer_open_work_dispute($1,$2,$3,$4,$5,$6,$7,$8) AS ok",[tenantId,milestoneId,body.caseId,randomUUID(),body.severity,body.reason,body.manifestDigest,body.version]);
    return r?.ok?{ok:true,disputeOpened:body.caseId}:{ok:false};
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

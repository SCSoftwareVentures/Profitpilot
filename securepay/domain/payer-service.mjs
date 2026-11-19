// Unmounted customer service boundary. HTTP auth middleware must supply the
// verified identity; never populate it from request data.
// No live dispatch or external provider access.
import {randomUUID} from "node:crypto";
import {withPayer} from "../db/with-payer.mjs";
import {authorizePayerInTransaction} from "../db/authorize-with-pin.mjs";
import {changePin} from "../db/change-pin.mjs";
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
function exact(body,keys){
 return body!==null&&typeof body==="object"&&!Array.isArray(body)&&
 Object.keys(body).length===keys.length&&keys.every(k=>Object.hasOwn(body,k));
}
export function makePayerService({pool,signingKey,pepper}){
 if(!pool?.connect||!Buffer.isBuffer(signingKey)||signingKey.length<32||
    !Buffer.isBuffer(pepper)||pepper.length<32||signingKey.equals(pepper))
  throw new Error("SecurePay service unavailable");
 function context(identity,tenantId){
  if(!identity||typeof identity.subject!=="string"||!identity.subject||identity.subject.length>512)
   throw Object.assign(new Error("Authentication required"),{status:401});
  if(typeof tenantId!=="string"||!uuid.test(tenantId))
   throw Object.assign(new Error("Invalid request"),{status:400});
  return {subject:identity.subject,tenantId,signingKey};
 }
 const bad=()=>{throw Object.assign(new Error("Invalid request"),{status:400});};
 return Object.freeze({
  async reserve({identity,tenantId,milestoneId,body}){
   const ctx=context(identity,tenantId);
   if(typeof milestoneId!=="string"||!uuid.test(milestoneId)||
      !exact(body,["pin","expectedAmountCents","idempotencyKey"])||
      typeof body.pin!=="string"||!/^[0-9]{6}$/.test(body.pin)||
      !Number.isSafeInteger(body.expectedAmountCents)||body.expectedAmountCents<=0||
      typeof body.idempotencyKey!=="string"||!uuid.test(body.idempotencyKey))bad();
   return withPayer(pool,ctx,c=>authorizePayerInTransaction(c,{tenantId,subject:ctx.subject,milestoneId,
      pin:body.pin,expectedAmountCents:body.expectedAmountCents,idempotencyKey:body.idempotencyKey,requestId:randomUUID()},pepper));
  },
  async setPin({identity,tenantId,body}){
   const ctx=context(identity,tenantId);
   if(!exact(body,["pin","purpose","grantRef"])||!["enroll","recover"].includes(body.purpose)||
      typeof body.pin!=="string"||!/^[0-9]{6}$/.test(body.pin)||
      typeof body.grantRef!=="string"||!uuid.test(body.grantRef))bad();
   return withPayer(pool,ctx,c=>changePin(c,{tenantId,subject:ctx.subject,
     pin:body.pin,purpose:body.purpose,grantRef:body.grantRef},pepper));
  }
 });
}

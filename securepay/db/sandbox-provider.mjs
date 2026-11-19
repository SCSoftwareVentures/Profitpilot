// Synthetic provider boundary only. Never configure a real payment API here.
import {randomUUID} from "node:crypto";
import {signEnvelope,validKeyId} from "./key-envelope.mjs";
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export function makeSandboxProvider({pool,key,keyId="primary"}){
 if(!pool?.query||!Buffer.isBuffer(key)||key.length!==32||!validKeyId(keyId))throw Error("Sandbox provider unavailable");
 return Object.freeze({
  async event({eventId=randomUUID(),tenantId,milestoneId,kind,fundingRef,requestId=null,amountCents,transactionRef=null}){
   if(![eventId,tenantId,milestoneId,fundingRef].every(x=>typeof x==="string"&&uuid.test(x))||
      !Number.isSafeInteger(amountCents)||amountCents<=0||!["funded","held","released","failed"].includes(kind)||
      [requestId,transactionRef].some(x=>x!==null&&(typeof x!=="string"||!uuid.test(x))))
     throw Error("Invalid synthetic provider event");
   const expiry=Math.floor(Date.now()/1000)+30;
   const parts=[eventId,tenantId,milestoneId,kind,fundingRef,requestId??"-",amountCents,transactionRef??"-",expiry];
   const signature=signEnvelope(key,keyId,["sp-sandbox-provider-v1",...parts].join(":"));
   const {rows:[r]}=await pool.query("SELECT securepay_private.provider_event($1::uuid,$2::uuid,$3::uuid,$4::text,$5::uuid,$6::uuid,$7::bigint,$8::uuid,$9::bigint,$10::text) AS result",[eventId,tenantId,milestoneId,kind,fundingRef,requestId,amountCents,transactionRef,expiry,signature]);
   return {status:r.result,eventId,mode:"sandbox",moneyMoved:false};
  },
  async beginDispatch({tenantId,milestoneId,requestId}){
   if(![tenantId,milestoneId,requestId].every(x=>typeof x==="string"&&uuid.test(x)))throw Error("Invalid synthetic dispatch");
   const {rows:[r]}=await pool.query("SELECT securepay_private.provider_begin_dispatch($1::uuid,$2::uuid,$3::uuid) AS ok",[tenantId,milestoneId,requestId]);
   return {ok:r.ok===true,mode:"sandbox",moneyMoved:false};
  }
 });
}

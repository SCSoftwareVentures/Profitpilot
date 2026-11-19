import {createHash,createHmac,randomUUID} from "node:crypto";
import {jwtVerify} from "jose";
import {resolvePayer} from "./change-pin.mjs";
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
export function createRecoveryVerifier({issuer,audience,requiredAcr,keyResolver}){
 if(!issuer||!audience||!requiredAcr||!keyResolver)throw new Error("Recovery authority unavailable");
 return async(token,{subject,tenantId,purpose})=>{
  const {payload}=await jwtVerify(token,keyResolver,{issuer,audience,algorithms:["RS256","ES256"],
    requiredClaims:["sub","exp","iat","auth_time","acr","jti"],maxTokenAge:"2m",clockTolerance:3});
  const now=Math.floor(Date.now()/1000);
  if(payload.sub!==subject||payload.acr!==requiredAcr||payload.tenant_id!==tenantId||payload.purpose!=="securepay-pin-"+purpose||
     !["enroll","recover"].includes(purpose)||!Number.isInteger(payload.auth_time)||payload.auth_time<now-120||payload.auth_time>now||
     !Number.isInteger(payload.exp)||payload.exp<=now||payload.exp>now+300||typeof payload.jti!=="string"||!payload.jti||payload.jti.length>200)
    throw new Error("Recovery assertion denied");
  return Object.freeze({digest:createHash("sha256").update(JSON.stringify([issuer,payload.jti])).digest("hex"),expires:payload.exp,authTime:payload.auth_time});
 };
}
export async function issueRecoveryGrant(c,{tenantId,subject,purpose,assertion},key){
 if(!Buffer.isBuffer(key)||key.length!==32||!["enroll","recover"].includes(purpose)||!uuid.test(tenantId)||
    !assertion||typeof assertion.digest!=="string"||!/^[a-f0-9]{64}$/.test(assertion.digest)||!Number.isSafeInteger(assertion.expires))
   return {ok:false};
 const customerId=await resolvePayer(c,{tenantId,subject});
 if(!customerId)return {ok:false};
 const grantRef=randomUUID(),commandExp=Math.min(assertion.expires,Math.floor(Date.now()/1000)+15);
 const args=[tenantId,customerId,purpose,assertion.digest,grantRef,assertion.expires,commandExp];
 const sig=createHmac("sha256",key).update(["sp-grant-v1",...args].join(":")).digest("hex");
 const {rows:[r]}=await c.query("SELECT securepay_private.issue_pin_grant($1::uuid,$2::uuid,$3::text,$4::text,$5::uuid,$6::bigint,$7::bigint,$8::text) AS id",[...args,sig]);
 return r.id?{ok:true,grantRef:r.id}:{ok:false};
}

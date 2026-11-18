import {createHmac,createHash,randomBytes} from "node:crypto";
import {hasRecentMfa} from "./auth.js";

const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const digest=/^[a-f0-9]{64}$/;
const denied=()=>{throw Object.assign(new Error("Sensitive operation authority unavailable"),{status:403});};

function signedFields(identity,env,now){
 if(!Number.isSafeInteger(now)||now<=0||!hasRecentMfa(identity,now)||
 identity.issuedAt>now+5||identity.issuedAt<now-905||
 typeof identity.subject!=="string"||!identity.subject||identity.subject.length>255||/\p{C}/u.test(identity.subject)||
 typeof identity.sessionId!=="string"||!identity.sessionId||identity.sessionId.length>255||/\p{C}/u.test(identity.sessionId))denied();
 const keyId=env.TENANT_CONTEXT_HMAC_KEY_ID||"primary",secret=env.TENANT_CONTEXT_HMAC_SECRET||"";
 if(!/^[a-f0-9]{64,128}$/i.test(secret)||secret.length%2!==0||
 !/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(keyId))denied();
 const args=[String(identity.authTime),String(identity.issuedAt),createHash("sha256").update(identity.sessionId,"utf8").digest("hex"),String(now+20),randomBytes(16).toString("hex"),keyId];
 return {args,sign:payload=>createHmac("sha256",Buffer.from(secret,"hex")).update(payload.join("\n")).digest("hex")};
}
function signedAction(domain,fields,identity,env,now){
 const {args,sign}=signedFields(identity,env,now);
 return [...fields,...args,sign([domain,...fields,identity.subject,...args])];
}
// Server-side only. Callers must independently verify session, explicit user
// intent and tenant membership and use the exact persisted digest. The DB
// rechecks authorization. No customer route or privilege grant is introduced.
export function payrollConfirmationProof(tenant,proposal,evidenceDigest,identity,env=process.env,now=Math.floor(Date.now()/1000)){
 if(!uuid.test(tenant)||!uuid.test(proposal)||!digest.test(evidenceDigest)||/^0+$/.test(evidenceDigest))denied();
 return signedAction("profitpilot-payroll-confirm-v1",[tenant,proposal,evidenceDigest],identity,env,now);
}
export function securityWorkProof(tenant,order,kind,scope,step,identity,env=process.env,now=Math.floor(Date.now()/1000)){
 if(!uuid.test(tenant)||!uuid.test(order)||!digest.test(scope)||/^0+$/.test(scope)||
 !["privacy_access","privacy_correction","privacy_disposal","privileged_operation","incident_recovery"].includes(kind)||
 !["request","approve","reject","consume"].includes(step))denied();
 return signedAction("profitpilot-security-work-v1",[tenant,order,kind,scope,step],identity,env,now);
}

export function sensitiveApiProof(tenant,target,action,scope,identity,env=process.env,now=Math.floor(Date.now()/1000)){
 if(!uuid.test(tenant)||!uuid.test(target)||!digest.test(scope)||
 !["payroll_submit","payroll_read","account_read","account_correct_email","invoice_disposal_preview"].includes(action)||
 (action==="account_correct_email" ? /^0+$/.test(scope) : !/^0+$/.test(scope)))denied();
 return signedAction("profitpilot-sensitive-api-v1",[tenant,target,action,scope],identity,env,now);
}

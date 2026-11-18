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

export function privacyCaseProof(tenant,caseId,action,kind,reason,evidence,identity,env=process.env,now=Math.floor(Date.now()/1000)){
 if(!uuid.test(tenant)||!uuid.test(caseId)||!["privacy_case_request","privacy_case_intake","privacy_case_status","privacy_case_acknowledge","privacy_case_resolve","privacy_case_refuse"].includes(action))denied();
 const opening=["privacy_case_request","privacy_case_intake"].includes(action),outcome=["privacy_case_resolve","privacy_case_refuse"].includes(action);
 if(opening? !["access","correction","disposal","complaint"].includes(kind)||reason!==null :kind!==null)denied();
 if(outcome? !((action==="privacy_case_resolve"?["fulfilled","partially_fulfilled"]:["lawful_refusal","retention_required","identity_not_verified"]).includes(reason)):reason!==null)denied();
 if(action==="privacy_case_intake"||outcome){if(typeof evidence!=="string"||!digest.test(evidence)||/^0+$/.test(evidence))denied();}else if(evidence!==null)denied();
 const scope=opening||outcome?createHash("sha256").update(["privacy-rights-v1",action,kind??"",reason??"",evidence??""].join("\n")).digest("hex"):"0".repeat(64);
 return signedAction("profitpilot-sensitive-api-v1",[tenant,caseId,action,scope],identity,env,now);
}

const correctionReasons=["allocation_error","source_correction","duplicate_source","privacy_correction"];
function correctionInput(tenant,oldRun,proposal,reason,evidence){
 if(![tenant,oldRun,proposal].every(x=>typeof x==="string"&&uuid.test(x))||!correctionReasons.includes(reason)||typeof evidence!=="string"||!digest.test(evidence)||/^0+$/.test(evidence))denied();
}
export function payrollCorrectionPreviewProof(tenant,oldRun,proposal,reason,evidence,identity,env=process.env,now=Math.floor(Date.now()/1000)){
 correctionInput(tenant,oldRun,proposal,reason,evidence);
 const scope=createHash("sha256").update(["payroll-correction-preview-v1",oldRun,proposal,reason,evidence].join("\n")).digest("hex");
 return [...signedAction("profitpilot-sensitive-api-v1",[tenant,oldRun,"payroll_correction_preview",scope],identity,env,now),proposal,reason,evidence];
}
export function payrollCorrectionStatusProof(tenant,order,identity,env=process.env,now=Math.floor(Date.now()/1000)){
 if(![tenant,order].every(x=>typeof x==="string"&&uuid.test(x)))denied();
 return signedAction("profitpilot-sensitive-api-v1",[tenant,order,"payroll_correction_status","0".repeat(64)],identity,env,now);
}
export function payrollCorrectionStepProof(tenant,order,oldRun,proposal,reason,evidence,scope,step,proposalDigest,identity,env=process.env,now=Math.floor(Date.now()/1000)){
 correctionInput(tenant,oldRun,proposal,reason,evidence);
 if(typeof order!=="string"||!uuid.test(order)||typeof scope!=="string"||!digest.test(scope)||/^0+$/.test(scope)||!["request","approve","reject","consume"].includes(step))denied();
 if(step==="consume"?typeof proposalDigest!=="string"||!digest.test(proposalDigest)||/^0+$/.test(proposalDigest):proposalDigest!==null)denied();
 const {args,sign}=signedFields(identity,env,now);
 const proof=sign(["profitpilot-security-work-v1",tenant,order,"privileged_operation",scope,step,identity.subject,...args]);
 let confirmNonce=null,confirmSignature=null;
 if(step==="consume"){
  confirmNonce=randomBytes(16).toString("hex");
  const confirmationArgs=args.map((value,index)=>index===4?confirmNonce:value);
  confirmSignature=sign(["profitpilot-payroll-confirm-v1",tenant,proposal,proposalDigest,identity.subject,...confirmationArgs]);
 }
 return [tenant,order,oldRun,proposal,reason,evidence,scope,step,...args,proof,confirmNonce,confirmSignature];
}

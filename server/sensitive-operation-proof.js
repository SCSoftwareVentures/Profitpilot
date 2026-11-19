import {createHmac,createHash,randomBytes} from "node:crypto";
import {hasRecentMfa} from "./auth.js";
import {invoiceIntakeFields} from "../src/invoice-intake.js";
import {invoiceCreditFields,invoiceCreditReversalFields} from "../src/invoice-credit.js";
import {supplierCostFields} from "../src/supplier-cost.js";
import {sharedCostFields,sharedCostCorrectionFields} from "../src/shared-cost.js";
import {workspaceJobFields} from "../src/workspace-jobs.js";
import {WORKSPACE_KINDS,workspaceRecordFields,workspaceVersionFields} from "../src/workspace-records.js";
import {canonicalAllocationMapping} from "../src/payroll-allocation-mapping.js";

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

export function privacyDeliveryPreviewProof(tenant,caseId,order,input,identity,env=process.env,now=Math.floor(Date.now()/1000)){
 privacyDeliveryInput(tenant,caseId,order,input);
 const scope=createHash("sha256").update(["privacy-delivery-preview-v1",caseId,...input].join("\n")).digest("hex");
 return [...signedAction("profitpilot-sensitive-api-v1",[tenant,order,"privacy_delivery_preview",scope],identity,env,now),caseId,...input];
}
export function privacyDeliveryStatusProof(tenant,caseId,order,identity,env=process.env,now=Math.floor(Date.now()/1000)){
 if(![tenant,caseId,order].every(x=>typeof x==="string"&&uuid.test(x)))denied();
 const scope=createHash("sha256").update(["privacy-delivery-status-v1",caseId].join("\n")).digest("hex");
 return [...signedAction("profitpilot-sensitive-api-v1",[tenant,order,"privacy_delivery_status",scope],identity,env,now),caseId];
}
function privacyDeliveryInput(tenant,caseId,order,input){
 if(![tenant,caseId,order].every(x=>typeof x==="string"&&uuid.test(x))||!Array.isArray(input)||input.length!==7||
 !["self","assisted_subject","authorized_representative","former_user"].includes(input[0])||
 !input.slice(1).every(x=>typeof x==="string"&&digest.test(x)&&!/^0+$/.test(x))||input[1]===input[2])denied();
}
export function privacyDeliveryStepProof(tenant,caseId,order,input,scope,step,identity,env=process.env,now=Math.floor(Date.now()/1000)){
 privacyDeliveryInput(tenant,caseId,order,input);
 const signed=securityWorkProof(tenant,order,"privileged_operation",scope,step,identity,env,now);
 return [tenant,caseId,order,...input,scope,step,...signed.slice(5)];
}

function receiptIds(tenant,caseId,release,review){
 if(![tenant,caseId,release,review].every(x=>typeof x==="string"&&uuid.test(x))||release===review)denied();
}
function receiptInput(tenant,caseId,release,review,input){
 receiptIds(tenant,caseId,release,review);
 if(!Array.isArray(input)||input.length!==4||!input.every(x=>typeof x==="string"&&digest.test(x)&&!/^0+$/.test(x))||input[0]===input[1])denied();
}
export function privacyReceiptPreviewProof(tenant,caseId,release,review,input,identity,env=process.env,now=Math.floor(Date.now()/1000)){
 receiptInput(tenant,caseId,release,review,input);
 const scope=createHash("sha256").update(["privacy-receipt-preview-v1",caseId,release,...input].join("\n")).digest("hex");
 return [...signedAction("profitpilot-sensitive-api-v1",[tenant,review,"privacy_receipt_preview",scope],identity,env,now),caseId,release,...input];
}
export function privacyReceiptStatusProof(tenant,caseId,release,review,identity,env=process.env,now=Math.floor(Date.now()/1000)){
 receiptIds(tenant,caseId,release,review);
 const scope=createHash("sha256").update(["privacy-receipt-status-v1",caseId,release].join("\n")).digest("hex");
 return [...signedAction("profitpilot-sensitive-api-v1",[tenant,review,"privacy_receipt_status",scope],identity,env,now),caseId,release];
}
export function privacyReceiptStepProof(tenant,caseId,release,review,input,scope,step,identity,env=process.env,now=Math.floor(Date.now()/1000)){
 receiptInput(tenant,caseId,release,review,input);
 const signed=securityWorkProof(tenant,review,"privileged_operation",scope,step,identity,env,now);
 return [tenant,caseId,release,review,...input,scope,step,...signed.slice(5)];
}

const dispatchReasons=["identity_uncertain","key_compromise","recipient_changed","authority_withdrawn","security_incident","ambiguous_dispatch"];
const dispatchDigest=x=>typeof x==="string"&&digest.test(x)&&!/^0+$/.test(x);
export function privacyDispatchStatusProof(tenant,caseId,release,identity,env=process.env,now=Math.floor(Date.now()/1000)){
 if(![tenant,caseId,release].every(x=>typeof x==="string"&&uuid.test(x)))denied();
 const scope=createHash("sha256").update(["profitpilot-privacy-dispatch-status-v1",caseId,release].join("\n")).digest("hex");
 return [...signedAction("profitpilot-sensitive-api-v1",[tenant,release,"privacy_dispatch_status",scope],identity,env,now),caseId];
}
export function privacyDispatchStepProof(tenant,caseId,release,step,input,identity,env=process.env,now=Math.floor(Date.now()/1000)){
 if(![tenant,caseId,release].every(x=>typeof x==="string"&&uuid.test(x))||!["reserve","burn","revoke"].includes(step)||!Array.isArray(input)||input.length!==5)denied();
 const [challenge,signer,deadline,reason,evidence]=input;
 if(step==="revoke"?(challenge!==null||signer!==null||deadline!==null||!dispatchReasons.includes(reason)||!dispatchDigest(evidence)):
 (!dispatchDigest(challenge)||!dispatchDigest(signer)||!Number.isSafeInteger(deadline)||deadline<1||deadline>4102444800||reason!==null||evidence!==null))denied();
 const action="privacy_dispatch_"+step;
 const scope=createHash("sha256").update(["profitpilot-privacy-dispatch-v1",caseId,release,action,...input.map(x=>x??"")].join("\n")).digest("hex");
 const signed=signedAction("profitpilot-sensitive-api-v1",[tenant,release,action,scope],identity,env,now);
 return [tenant,caseId,release,action,...input,scope,...signed.slice(4)];
}

function intakeIds(tenant,batch,order){if(![tenant,batch,order].every(x=>typeof x==="string"&&uuid.test(x)))denied();}
const intakeDig=x=>typeof x==="string"&&digest.test(x)&&!/^0+$/.test(x);
function intakeFields(input){
 if(!input||![input.poolId,input.sourceNamespace].every(x=>typeof x==="string"&&uuid.test(x))||
 typeof input.controlTotal!=="string"||!/^(0|[1-9][0-9]{0,11})\.[0-9]{2}$/.test(input.controlTotal)||
 !Number.isSafeInteger(input.rowCount)||input.rowCount<1||input.rowCount>200||
 ![input.authorityDigest,input.policyDigest,input.controlDigest,input.fileSha256].every(intakeDig)||
 !Array.isArray(input.rows)||input.rows.length!==input.rowCount)denied();
 return [input.poolId,input.sourceNamespace,input.controlTotal,input.rowCount,input.authorityDigest,input.policyDigest,input.controlDigest];
}
export function payrollIntakePreviewProof(tenant,batch,order,input,identity,env=process.env,now=Math.floor(Date.now()/1000)){
 intakeIds(tenant,batch,order);const f=intakeFields(input);
 const scope=createHash("sha256").update(["payroll-intake-preview-v1",batch,...f,input.fileSha256].join("\n")).digest("hex");
 return [...signedAction("profitpilot-sensitive-api-v1",[tenant,order,"payroll_intake_preview",scope],identity,env,now),batch,...f,JSON.stringify(input.rows),input.fileSha256];
}
export function payrollIntakeStatusProof(tenant,batch,order,identity,env=process.env,now=Math.floor(Date.now()/1000)){
 intakeIds(tenant,batch,order);
 const scope=createHash("sha256").update(["payroll-intake-status-v1",batch].join("\n")).digest("hex");
 return [...signedAction("profitpilot-sensitive-api-v1",[tenant,order,"payroll_intake_status",scope],identity,env,now),batch];
}
export function payrollIntakeStepProof(tenant,batch,order,input,scope,step,identity,env=process.env,now=Math.floor(Date.now()/1000)){
 intakeIds(tenant,batch,order);const [pool,...f]=intakeFields(input);
 const signed=securityWorkProof(tenant,order,"privileged_operation",scope,step,identity,env,now);
 return [tenant,batch,pool,order,...f,JSON.stringify(input.rows),scope,step,...signed.slice(5)];
}

export function payrollAllocationBuildProof(tenant,pool,run,lines,identity,env=process.env,now=Math.floor(Date.now()/1000)){
 if(![tenant,pool,run].every(x=>typeof x==="string"&&uuid.test(x)))denied();
 const canonical=canonicalAllocationMapping(pool,lines);if(canonical===null)denied();
 const scope=createHash("sha256").update(canonical).digest("hex");
 return [...signedAction("profitpilot-sensitive-api-v1",[tenant,run,"payroll_allocation_build",scope],identity,env,now),pool,JSON.stringify(lines)];
}
export function payrollAllocationStatusProof(tenant,pool,run,identity,env=process.env,now=Math.floor(Date.now()/1000)){
 if(![tenant,pool,run].every(x=>typeof x==="string"&&uuid.test(x)))denied();
 const scope=createHash("sha256").update(["payroll-allocation-status-v1",pool].join("\n")).digest("hex");
 return [...signedAction("profitpilot-sensitive-api-v1",[tenant,run,"payroll_allocation_status",scope],identity,env,now),pool];
}

export function workspaceCreateProof(tenant,id,input,identity,env=process.env,now=Math.floor(Date.now()/1000)){
 const f=workspaceRecordFields(input);if(!uuid.test(tenant)||!uuid.test(id)||!f)denied();
 const scope=createHash("sha256").update(["workspace-create-v1",...f.map(x=>x??"")].join("\n")).digest("hex");
 return [...signedAction("profitpilot-sensitive-api-v1",[tenant,id,"workspace_create",scope],identity,env,now),...f];
}
export function workspaceReadProof(tenant,kind,cursor,identity,env=process.env,now=Math.floor(Date.now()/1000)){
 if(!uuid.test(tenant)||!WORKSPACE_KINDS.includes(kind)||(cursor!==null&&!uuid.test(cursor)))denied();
 const scope=createHash("sha256").update(["workspace-read-v1",kind,cursor??""].join("\n")).digest("hex");
 return [...signedAction("profitpilot-sensitive-api-v1",[tenant,tenant,"workspace_read",scope],identity,env,now),kind,cursor];
}
export function workspaceVersionProof(tenant,contract,order,input,step,identity,env=process.env,now=Math.floor(Date.now()/1000)){
 const f=workspaceVersionFields(input);if(![tenant,contract,order].every(x=>typeof x==="string"&&uuid.test(x))||!f)denied();
 const scope=createHash("sha256").update(["workspace-version-v1",contract,...f].join("\n")).digest("hex");
 return [tenant,contract,order,...f,scope,step,...securityWorkProof(tenant,order,"privileged_operation",scope,step,identity,env,now).slice(5)];
}
export function workspaceVersionStatusProof(tenant,contract,order,identity,env=process.env,now=Math.floor(Date.now()/1000)){
 if(![tenant,contract,order].every(x=>typeof x==="string"&&uuid.test(x)))denied();
 const scope=createHash("sha256").update(["workspace-version-status-v1",contract].join("\n")).digest("hex");
 return [...signedAction("profitpilot-sensitive-api-v1",[tenant,order,"workspace_version_status",scope],identity,env,now),contract];
}

export function workspaceJobWriteProof(tenant,job,body,identity,env=process.env,now=Math.floor(Date.now()/1000)){
 const f=workspaceJobFields(body);if(!uuid.test(tenant)||!uuid.test(job)||!f)denied();
 const scope=createHash("sha256").update(["workspace-job-v1",body.action,...f.map(x=>x??"")].join("\n")).digest("hex");
 return [...signedAction("profitpilot-sensitive-api-v1",[tenant,job,"workspace_job_write",scope],identity,env,now),body.action,f];
}
export function workspaceJobReadProof(tenant,target,mode,cursor,identity,env=process.env,now=Math.floor(Date.now()/1000)){
 if(!uuid.test(tenant)||!uuid.test(target)||!["list","status"].includes(mode)||(mode==="list"&&target!==tenant)||(mode==="status"&&cursor!==null)||(cursor!==null&&!uuid.test(cursor)))denied();
 const scope=createHash("sha256").update(["workspace-job-read-v1",mode,cursor??""].join("\n")).digest("hex");
 return [...signedAction("profitpilot-sensitive-api-v1",[tenant,target,"workspace_job_read",scope],identity,env,now),mode,cursor];
}

export function invoiceIntakePreviewProof(tenant,batch,order,input,identity,env=process.env,now=Math.floor(Date.now()/1000)){
 const f=invoiceIntakeFields(input);if(![tenant,batch,order].every(x=>typeof x==="string"&&uuid.test(x))||!f)denied();
 const scope=createHash("sha256").update(["invoice-intake-preview-v1",batch,...f].join("\n")).digest("hex");
 return [...signedAction("profitpilot-sensitive-api-v1",[tenant,order,"invoice_intake_preview",scope],identity,env,now),batch,...f];
}
export function invoiceIntakeStatusProof(tenant,batch,order,identity,env=process.env,now=Math.floor(Date.now()/1000)){
 if(![tenant,batch,order].every(x=>typeof x==="string"&&uuid.test(x)))denied();
 const scope=createHash("sha256").update(["invoice-intake-status-v1",batch].join("\n")).digest("hex");
 return [...signedAction("profitpilot-sensitive-api-v1",[tenant,order,"invoice_intake_status",scope],identity,env,now),batch];
}
export function invoiceIntakeStepProof(tenant,batch,order,input,scope,step,identity,env=process.env,now=Math.floor(Date.now()/1000)){
 const f=invoiceIntakeFields(input);if(![tenant,batch,order].every(x=>typeof x==="string"&&uuid.test(x))||!f)denied();
 return [tenant,batch,order,...f,scope,step,...securityWorkProof(tenant,order,"privileged_operation",scope,step,identity,env,now).slice(5)];
}

export function supplierCostStepProof(t,b,o,input,step,identity,env=process.env,now=Math.floor(Date.now()/1000)){
 const fields=supplierCostFields(input);if(![t,b,o].every(x=>typeof x==="string"&&uuid.test(x))||!fields)denied();
 const scope=createHash("sha256").update(["supplier-cost-v1",b,...fields].join("\n")).digest("hex");return [t,b,o,...fields,scope,step,...securityWorkProof(t,o,"privileged_operation",scope,step,identity,env,now).slice(5)];
}
export function supplierCostStatusProof(t,b,o,identity,env=process.env,now=Math.floor(Date.now()/1000)){
 if(![t,b,o].every(x=>typeof x==="string"&&uuid.test(x)))denied();const scope=createHash("sha256").update(["supplier-cost-status-v1",b].join("\n")).digest("hex");return [...signedAction("profitpilot-sensitive-api-v1",[t,o,"supplier_cost_status",scope],identity,env,now),b];
}

export function sharedCostStepProof(t,k,s,o,input,step,identity,env=process.env,now=Math.floor(Date.now()/1000)){
 const f=sharedCostFields(k,s,input);if(![t,s,o].every(x=>typeof x==="string"&&uuid.test(x))||!f)denied();
 const scope=createHash("sha256").update(f.canonical).digest("hex");
 return [t,k,s,o,JSON.stringify(f.shares),f.evidence,scope,step,...securityWorkProof(t,o,"privileged_operation",scope,step,identity,env,now).slice(5)];
}
export function sharedCostStatusProof(t,k,s,o,identity,env=process.env,now=Math.floor(Date.now()/1000)){
 if(![t,s,o].every(x=>typeof x==="string"&&uuid.test(x))||!["payroll","overhead","business_overhead"].includes(k))denied();
 const scope=createHash("sha256").update(["shared-cost-status-v1",k,s].join("\n")).digest("hex");
 return [...signedAction("profitpilot-sensitive-api-v1",[t,o,"shared_cost_status",scope],identity,env,now),k,s];
}

export function sharedCostCorrectionProof(t,k,s,o,input,step,identity,env=process.env,now=Math.floor(Date.now()/1000)){
 const f=sharedCostCorrectionFields(k,s,input);if(![t,s,o].every(x=>typeof x==="string"&&uuid.test(x))||!f||o===f.replaces)denied();
 const scope=createHash("sha256").update(f.canonical).digest("hex");
 return [t,k,s,o,f.replaces,JSON.stringify(f.shares),f.evidence,scope,step,...securityWorkProof(t,o,"privileged_operation",scope,step,identity,env,now).slice(5)];
}

export function financialCoverageProof(t,c,s,starts,ends,identity,env=process.env,now=Math.floor(Date.now()/1000)){
 if(![t,c,s].every(x=>typeof x==="string"&&uuid.test(x))||![starts,ends].every(x=>typeof x==="string"&&/^\d{4}-\d{2}-\d{2}$/.test(x)))denied();
 const scope=createHash("sha256").update(["financial-coverage-v1",s,starts,ends].join("\n")).digest("hex");
 return [...signedAction("profitpilot-sensitive-api-v1",[t,c,"financial_coverage",scope],identity,env,now),s,starts,ends];
}

export function invoiceCreditStepProof(t,l,o,input,step,identity,env=process.env,now=Math.floor(Date.now()/1000)){
 const fields=invoiceCreditFields(input);if(![t,l,o].every(x=>typeof x==="string"&&uuid.test(x))||!fields)denied();
 const scope=createHash("sha256").update(["invoice-credit-v1",l,...fields].join("\n")).digest("hex");
 return [t,l,o,...fields,scope,step,...securityWorkProof(t,o,"privileged_operation",scope,step,identity,env,now).slice(5)];
}
export function invoiceCreditStatusProof(t,l,o,identity,env=process.env,now=Math.floor(Date.now()/1000)){
 if(![t,l,o].every(x=>typeof x==="string"&&uuid.test(x)))denied();
 const scope=createHash("sha256").update(["invoice-credit-status-v1",l].join("\n")).digest("hex");
 return [...signedAction("profitpilot-sensitive-api-v1",[t,o,"invoice_credit_status",scope],identity,env,now),l];
}

export function invoiceCreditReversalProof(t,l,o,input,step,identity,env=process.env,now=Math.floor(Date.now()/1000)){
 const f=invoiceCreditReversalFields(input);if(![t,l,o].every(x=>typeof x==="string"&&uuid.test(x))||!f||o===f[0])denied();
 const scope=createHash("sha256").update(["invoice-credit-reversal-v1",l,...f].join("\n")).digest("hex");
 return [t,l,o,...f,scope,step,...securityWorkProof(t,o,"privileged_operation",scope,step,identity,env,now).slice(5)];
}

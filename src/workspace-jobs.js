import {isIsoDate} from "./engine.js";
import {COMMERCIAL_CLEANING_READINESS_TEMPLATE,evaluateJobReadiness} from "./job-readiness.js";
const uuid=x=>typeof x==="string"&&/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(x);
const digest=x=>typeof x==="string"&&/^[a-f0-9]{64}$/.test(x)&&!/^0+$/.test(x);
const exact=(x,k)=>x!==null&&typeof x==="object"&&!Array.isArray(x)&&Object.keys(x).length===k.length&&k.every(y=>Object.hasOwn(x,y));
export function workspaceJobFields(b){
 if(!b||b.confirm!==true||!digest(b.evidenceDigest))return null;
 if(b.action==="create"){
  if(!exact(b,["confirm","action","contractId","siteId","serviceDate","evidenceDigest"])||!uuid(b.contractId)||!uuid(b.siteId)||!isIsoDate(b.serviceDate))return null;
  return [b.contractId,b.siteId,b.serviceDate,null,null,null,b.evidenceDigest];
 }
 if(!uuid(b.eventId))return null;
 if(b.action==="check"){
  const r=COMMERCIAL_CLEANING_READINESS_TEMPLATE.requirements.find(r=>r.id===b.checkId);
  if(!exact(b,["confirm","action","eventId","checkId","checkStatus","evidenceDigest"])||!r||!["satisfied","missing","conflicting","unverified","not_applicable"].includes(b.checkStatus)||(b.checkStatus==="not_applicable"&&!r.allowNotApplicable))return null;
  return [null,null,null,b.eventId,b.checkId,b.checkStatus,b.evidenceDigest];
 }
 if(!["start","complete","cancel"].includes(b.action)||!exact(b,["confirm","action","eventId","evidenceDigest"]))return null;
 return [null,null,null,b.eventId,null,null,b.evidenceDigest];
}
// Independently evaluate the persisted evidence states against the shared
// readiness template. Non-applicable reasons are represented by reviewed
// evidence references, not untrusted free-form content.
export function evaluatePersistedJob(job){
 const checks={};
 for(const r of COMMERCIAL_CLEANING_READINESS_TEMPLATE.requirements){
  const c=job.checks?.[r.id];if(!c)continue;
  const values={customer:job.contractId,site:job.siteId,scope:c.evidenceDigest,service_date:job.serviceDate,price:job.baselinePrice,currency:job.currency,access:c.evidenceDigest,materials:true,skills:true,permissions:true,completion_evidence:c.evidenceDigest};
  checks[r.id]={status:c.status,value:values[r.id],evidenceRef:c.evidenceDigest,reason:c.evidenceDigest};
 }
 return evaluateJobReadiness(COMMERCIAL_CLEANING_READINESS_TEMPLATE,{checks});
}
export function verifiedJobSummary(job){
 const readiness=evaluatePersistedJob(job);
 if(readiness.readinessStatus!==job.readinessStatus||readiness.resolvedRequiredChecks!==job.resolvedRequiredChecks||readiness.totalRequiredChecks!==job.totalRequiredChecks)throw Error("Persisted readiness does not reconcile");
 return {...job,readiness};
}

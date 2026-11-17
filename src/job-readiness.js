import {isIsoDate,money} from "./engine.js";

const CHECK_STATUSES=new Set(["satisfied","missing","conflicting","unverified","not_applicable"]);
const VALUE_TYPES=new Set(["text","boolean_true","money","currency","iso_date"]);

export const COMMERCIAL_CLEANING_READINESS_TEMPLATE=Object.freeze({
  id:"commercial-cleaning-job-readiness",
  version:"1.0.0",
  industry:"commercial_cleaning",
  requirements:Object.freeze([
    Object.freeze({id:"customer",label:"Customer identified",valueType:"text",required:true,evidenceRequired:true,allowNotApplicable:false}),
    Object.freeze({id:"site",label:"Service site confirmed",valueType:"text",required:true,evidenceRequired:true,allowNotApplicable:false}),
    Object.freeze({id:"scope",label:"Scope and exclusions recorded",valueType:"text",required:true,evidenceRequired:true,allowNotApplicable:false}),
    Object.freeze({id:"service_date",label:"Service date confirmed",valueType:"iso_date",required:true,evidenceRequired:true,allowNotApplicable:false}),
    Object.freeze({id:"price",label:"Commercial price recorded",valueType:"money",required:true,evidenceRequired:true,allowNotApplicable:false}),
    Object.freeze({id:"currency",label:"Currency confirmed",valueType:"currency",required:true,evidenceRequired:true,allowNotApplicable:false}),
    Object.freeze({id:"access",label:"Access requirements resolved",valueType:"text",required:true,evidenceRequired:true,allowNotApplicable:true}),
    Object.freeze({id:"materials",label:"Materials and equipment ready",valueType:"boolean_true",required:true,evidenceRequired:false,allowNotApplicable:true}),
    Object.freeze({id:"skills",label:"Required skills confirmed",valueType:"boolean_true",required:true,evidenceRequired:false,allowNotApplicable:true}),
    Object.freeze({id:"permissions",label:"Permissions and induction confirmed",valueType:"boolean_true",required:true,evidenceRequired:true,allowNotApplicable:true}),
    Object.freeze({id:"completion_evidence",label:"Completion evidence defined",valueType:"text",required:true,evidenceRequired:true,allowNotApplicable:true})
  ])
});

function validateTemplate(template){
  if(!template||typeof template!=="object"||typeof template.id!=="string"||!template.id.trim()||typeof template.version!=="string"||!template.version.trim()||!Array.isArray(template.requirements)||template.requirements.length===0)
    throw new TypeError("A versioned readiness template with requirements is required");
  if(!template.requirements.some(requirement=>requirement&&requirement.required===true))throw new TypeError("At least one required readiness check is required");
  const seen=new Set();
  for(const requirement of template.requirements){
    if(!requirement||typeof requirement.id!=="string"||!/^[a-z][a-z0-9_]{0,63}$/.test(requirement.id)||seen.has(requirement.id)||typeof requirement.label!=="string"||!requirement.label.trim()||!VALUE_TYPES.has(requirement.valueType)||typeof requirement.required!=="boolean"||typeof requirement.evidenceRequired!=="boolean"||typeof requirement.allowNotApplicable!=="boolean")
      throw new TypeError("Readiness template contains an invalid or duplicate requirement");
    seen.add(requirement.id);
  }
}

function validValue(type,value){
  if(type==="text")return typeof value==="string"&&value.trim().length>0;
  if(type==="boolean_true")return value===true;
  if(type==="money"){const canonical=money(value);return canonical!==null&&!canonical.startsWith("-");}
  if(type==="currency")return typeof value==="string"&&/^[A-Z]{3}$/.test(value);
  if(type==="iso_date")return isIsoDate(value);
  return false;
}

/**
 * Evaluate explicit evidence states against one immutable template version.
 * This is a completeness check only; it does not certify safety, legality,
 * profitability, customer consent or successful delivery.
 */
export function evaluateJobReadiness(template,proposal){
  validateTemplate(template);
  if(!proposal||typeof proposal!=="object"||Array.isArray(proposal))throw new TypeError("A job proposal object is required");
  const supplied=proposal.checks&&typeof proposal.checks==="object"&&!Array.isArray(proposal.checks)?proposal.checks:{};
  const requirements=template.requirements;
  const checkResults=requirements.map(requirement=>{
    const input=supplied[requirement.id]&&typeof supplied[requirement.id]==="object"&&!Array.isArray(supplied[requirement.id])?supplied[requirement.id]:{};
    const hasStatus=Object.prototype.hasOwnProperty.call(input,"status")&&input.status!==undefined;
    let status=hasStatus?(CHECK_STATUSES.has(input.status)?input.status:"unverified"):"missing";
    let issue=hasStatus&&!CHECK_STATUSES.has(input.status)?"status_invalid":null;
    const reason=typeof input.reason==="string"?input.reason.trim():"";
    const evidenceRef=typeof input.evidenceRef==="string"?input.evidenceRef.trim():"";
    if(status==="not_applicable"){
      if(!requirement.allowNotApplicable){status="unverified";issue="not_applicable_not_allowed";}
      else if(!reason){status="unverified";issue="not_applicable_reason_required";}
    }else if(status==="satisfied"){
      if(!validValue(requirement.valueType,input.value)){status="unverified";issue="value_invalid";}
      else if(requirement.evidenceRequired&&!evidenceRef){status="unverified";issue="evidence_reference_required";}
    }else if(status==="conflicting"&&!reason){
      issue="conflict_reason_required";
    }
    const blocking=requirement.required&&!["satisfied","not_applicable"].includes(status);
    return {id:requirement.id,label:requirement.label,required:requirement.required,status,blocking,evidenceRef:evidenceRef||null,reason:reason||null,issue};
  });
  const required=checkResults.filter(x=>x.required);
  const resolved=required.filter(x=>["satisfied","not_applicable"].includes(x.status)).length;
  const blockers=required.filter(x=>x.blocking);
  const known=new Set(requirements.map(x=>x.id));
  const unexpectedCheckIds=Object.keys(supplied).filter(id=>!known.has(id)).sort();
  return {
    templateId:template.id,
    templateVersion:template.version,
    industry:typeof template.industry==="string"?template.industry:null,
    readinessStatus:blockers.length===0?"ready":"not_ready",
    completenessPercent:Math.round((resolved/required.length)*100),
    resolvedRequiredChecks:resolved,
    totalRequiredChecks:required.length,
    blockingCount:blockers.length,
    blockers:blockers.map(x=>x.id),
    checkResults,
    unexpectedCheckIds,
    interpretation:"Completeness indicator only. Not a guarantee of safety, profitability, legal compliance, customer consent or successful delivery."
  };
}

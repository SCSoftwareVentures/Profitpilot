const STATES=new Set(["satisfied","missing","conflicting","unverified","not_applicable"]);
const SAFE_ID=/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

function safeText(value,max=500){
  return typeof value==="string"?value.trim().slice(0,max):"";
}

/**
 * Evaluate a versioned job-readiness template without inventing missing facts.
 * "ready_for_human_decision" is deliberately not an approval or safety guarantee.
 */
export function evaluateJobReadiness({template,answers}={}){
  if(!template||typeof template!=="object"||Array.isArray(template)||
     typeof template.id!=="string"||!SAFE_ID.test(template.id)||typeof template.version!=="string"||!SAFE_ID.test(template.version)||
     !Array.isArray(template.checks)||template.checks.length===0||template.checks.length>200){
    throw new TypeError("A versioned readiness template with 1–200 checks is required.");
  }
  if(!answers||typeof answers!=="object"||Array.isArray(answers)){
    throw new TypeError("Readiness answers must be an object keyed by check ID.");
  }
  const seen=new Set();
  const checks=template.checks.map((definition,index)=>{
    if(!definition||typeof definition!=="object"||Array.isArray(definition)||
       typeof definition.id!=="string"||!SAFE_ID.test(definition.id)||seen.has(definition.id)){
      throw new TypeError("Template check IDs must be unique valid identifiers.");
    }
    seen.add(definition.id);
    const required=definition.required!==false;
    const evidenceRequired=definition.evidenceRequired!==false;
    const answer=answers[definition.id];
    let state=answer&&typeof answer==="object"&&!Array.isArray(answer)&&STATES.has(answer.state)
      ?answer.state:"unverified";
    const evidenceRefs=answer&&Array.isArray(answer.evidenceRefs)
      ?answer.evidenceRefs.filter(x=>typeof x==="string"&&SAFE_ID.test(x.trim())).map(x=>x.trim()).slice(0,50):[];
    const reason=safeText(answer?.reason,500);
    const owner=safeText(answer?.owner,120);
    const nextAction=safeText(answer?.nextAction,500);
    if(state==="not_applicable"&&definition.allowNotApplicable!==true)state="conflicting";
    if(state==="satisfied"&&evidenceRequired&&evidenceRefs.length===0)state="unverified";
    const blocking=required&&state!=="satisfied"&&!(state==="not_applicable"&&definition.allowNotApplicable===true);
    return {
      id:definition.id,
      label:safeText(definition.label,160)||("Readiness check "+(index+1)),
      required,
      state,
      evidenceRefs,
      reason,
      owner,
      nextAction,
      blocking
    };
  });
  const requiredCount=checks.filter(x=>x.required).length;
  const satisfiedCount=checks.filter(x=>x.required&&x.state==="satisfied").length;\n  const notApplicableCount=checks.filter(x=>x.required&&x.state==="not_applicable").length;
  const blockers=checks.filter(x=>x.blocking).map(x=>({
    checkId:x.id,
    state:x.state,
    owner:x.owner||null,
    nextAction:x.nextAction||x.reason||"Review the missing or conflicting information."
  }));
  const status=blockers.length?"blocked":"ready_for_human_decision";
  return {
    templateId:template.id,
    templateVersion:template.version,
    status,
    approvalGranted:false,
    readinessCounts:{required:requiredCount,satisfied:satisfiedCount,notApplicable:notApplicableCount,complete:satisfiedCount+notApplicableCount,blocked:blockers.length},
    checks,
    blockers,
    limitations:[
      "Readiness is a completeness assessment, not a guarantee of safety, profitability, legal compliance or successful delivery.",
      "A responsible human must make and record the proceed/decline decision.",
      "Missing or unverified information is never treated as satisfied."
    ]
  };
}

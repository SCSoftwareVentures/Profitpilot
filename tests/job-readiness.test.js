import test from "node:test";
import assert from "node:assert/strict";
import {COMMERCIAL_CLEANING_READINESS_TEMPLATE,evaluateJobReadiness} from "../src/job-readiness.js";

const satisfied={
  customer:{status:"satisfied",value:"Example Customer Pty Ltd",evidenceRef:"synthetic:customer-1"},
  site:{status:"satisfied",value:"Site A, Melbourne",evidenceRef:"synthetic:site-1"},
  scope:{status:"satisfied",value:"Nightly office cleaning; windows excluded",evidenceRef:"synthetic:scope-1"},
  service_date:{status:"satisfied",value:"2026-12-01",evidenceRef:"synthetic:schedule-1"},
  price:{status:"satisfied",value:"1250.00",evidenceRef:"synthetic:quote-1"},
  currency:{status:"satisfied",value:"AUD",evidenceRef:"synthetic:quote-1"},
  access:{status:"satisfied",value:"Security desk issues access card",evidenceRef:"synthetic:access-1"},
  materials:{status:"satisfied",value:true},
  skills:{status:"satisfied",value:true},
  permissions:{status:"satisfied",value:true,evidenceRef:"synthetic:induction-1"},
  completion_evidence:{status:"satisfied",value:"Supervisor checklist and timestamped completion record",evidenceRef:"synthetic:evidence-1"}
};

test("complete evidenced proposal is ready and retains template version",()=>{
  const result=evaluateJobReadiness(COMMERCIAL_CLEANING_READINESS_TEMPLATE,{checks:satisfied});
  assert.equal(result.readinessStatus,"ready");
  assert.equal(result.templateVersion,"1.0.0");
  assert.equal(result.completenessPercent,100);
  assert.equal(result.blockingCount,0);
});

test("missing, conflicting and unverified required checks block readiness",()=>{
  const checks={...satisfied,scope:{status:"conflicting",reason:"Customer scope email differs"},service_date:{status:"unverified"},access:{status:"missing"}};
  const result=evaluateJobReadiness(COMMERCIAL_CLEANING_READINESS_TEMPLATE,{checks});
  assert.equal(result.readinessStatus,"not_ready");
  assert.deepEqual(result.blockers,["scope","service_date","access"]);
  assert.equal(result.completenessPercent,73);
});

test("not-applicable checks require template permission and a recorded reason",()=>{
  const checks={...satisfied,access:{status:"not_applicable",reason:"Site access is provided by the customer"},materials:{status:"not_applicable",reason:"Customer supplies all consumables"}};
  const result=evaluateJobReadiness(COMMERCIAL_CLEANING_READINESS_TEMPLATE,{checks});
  assert.equal(result.readinessStatus,"ready");
  assert.equal(result.checkResults.find(x=>x.id==="access").status,"not_applicable");
  const invalid=evaluateJobReadiness(COMMERCIAL_CLEANING_READINESS_TEMPLATE,{checks:{...checks,access:{status:"not_applicable"}}});
  assert.equal(invalid.readinessStatus,"not_ready");
  assert.equal(invalid.checkResults.find(x=>x.id==="access").issue,"not_applicable_reason_required");
});

test("satisfied states require valid typed values and required evidence references",()=>{
  const checks={...satisfied,price:{status:"satisfied",value:1250,evidenceRef:"synthetic:quote-1"},currency:{status:"satisfied",value:"aud",evidenceRef:"synthetic:quote-1"},scope:{status:"satisfied",value:"   ",evidenceRef:"synthetic:scope-1"},permissions:{status:"satisfied",value:true}};
  const result=evaluateJobReadiness(COMMERCIAL_CLEANING_READINESS_TEMPLATE,{checks});
  assert.equal(result.readinessStatus,"not_ready");
  assert.equal(result.checkResults.find(x=>x.id==="price").issue,"value_invalid");
  assert.equal(result.checkResults.find(x=>x.id==="currency").issue,"value_invalid");
  assert.equal(result.checkResults.find(x=>x.id==="scope").issue,"value_invalid");
  assert.equal(result.checkResults.find(x=>x.id==="permissions").issue,"evidence_reference_required");
});

test("invalid statuses are held as unverified and unknown checks are reported",()=>{
  const result=evaluateJobReadiness(COMMERCIAL_CLEANING_READINESS_TEMPLATE,{checks:{...satisfied,scope:{status:"approved",value:"Scope",evidenceRef:"synthetic:scope-1"},extra:{status:"satisfied"}}});
  assert.equal(result.readinessStatus,"not_ready");
  assert.equal(result.checkResults.find(x=>x.id==="scope").status,"unverified");
  assert.equal(result.checkResults.find(x=>x.id==="scope").issue,"status_invalid");
  assert.deepEqual(result.unexpectedCheckIds,["extra"]);
});

test("template rejects missing versions, empty requirements and duplicate IDs",()=>{
  assert.throws(()=>evaluateJobReadiness({id:"t",version:"",requirements:[{id:"a",label:"A",valueType:"text",required:true,evidenceRequired:false,allowNotApplicable:false}]},{checks:{}}),/versioned readiness template/);
  assert.throws(()=>evaluateJobReadiness({id:"t",version:"1",requirements:[]},{checks:{}}),/versioned readiness template/);
  const duplicate={id:"t",version:"1",requirements:[
    {id:"a",label:"A",valueType:"text",required:true,evidenceRequired:false,allowNotApplicable:false},
    {id:"a",label:"B",valueType:"text",required:true,evidenceRequired:false,allowNotApplicable:false}
  ]};
  assert.throws(()=>evaluateJobReadiness(duplicate,{checks:{}}),/invalid or duplicate/);
});

test("readiness result expressly disclaims safety, profitability and compliance certification",()=>{
  const result=evaluateJobReadiness(COMMERCIAL_CLEANING_READINESS_TEMPLATE,{checks:satisfied});
  assert.match(result.interpretation,/not a guarantee of safety, profitability, legal compliance/);
});

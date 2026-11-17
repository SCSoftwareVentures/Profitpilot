import test from "node:test";
import assert from "node:assert/strict";
import {evaluateJobReadiness} from "../src/job-readiness.js";

const template={
  id:"cleaning-job-v1",
  version:"1.0.0",
  checks:[
    {id:"scope",label:"Approved scope",required:true,evidenceRequired:true},
    {id:"access",label:"Site access",required:true,evidenceRequired:true},
    {id:"materials",label:"Materials",required:true,evidenceRequired:false,allowNotApplicable:true},
    {id:"notes",label:"Optional notes",required:false,evidenceRequired:false}
  ]
};

test("job readiness remains blocked when required answers are missing or unverified",()=>{
  const result=evaluateJobReadiness({template,answers:{
    scope:{state:"satisfied",evidenceRefs:["contract-v3"]},
    access:{state:"missing",nextAction:"Obtain current access instructions"},
    materials:{state:"not_applicable"},
    notes:{state:"unverified"}
  }});
  assert.equal(result.status,"blocked");
  assert.equal(result.approvalGranted,false);
  assert.equal(result.readinessCounts.required,3);
  assert.equal(result.readinessCounts.satisfied,1);assert.equal(result.readinessCounts.notApplicable,1);assert.equal(result.readinessCounts.complete,2);
  assert.equal(result.blockers.length,1);
  assert.equal(result.blockers[0].checkId,"access");
});

test("satisfied checks without required evidence are downgraded to unverified",()=>{
  const result=evaluateJobReadiness({template,answers:{
    scope:{state:"satisfied"},
    access:{state:"satisfied",evidenceRefs:["site-access-approval"]},
    materials:{state:"not_applicable"}
  }});
  assert.equal(result.status,"blocked");
  assert.equal(result.checks[0].state,"unverified");
});

test("all required checks complete yields human decision status, never automatic approval",()=>{
  const result=evaluateJobReadiness({template,answers:{
    scope:{state:"satisfied",evidenceRefs:["contract-v3"]},
    access:{state:"satisfied",evidenceRefs:["access-v2"]},
    materials:{state:"not_applicable"}
  }});
  assert.equal(result.status,"ready_for_human_decision");
  assert.equal(result.approvalGranted,false);
  assert.equal(result.blockers.length,0);
});

test("not-applicable is a conflict unless the template explicitly permits it",()=>{
  const restricted={id:"restricted-v1",version:"1",checks:[{id:"insurance",label:"Insurance",required:true}]};
  const result=evaluateJobReadiness({template:restricted,answers:{insurance:{state:"not_applicable"}}});
  assert.equal(result.status,"blocked");
  assert.equal(result.checks[0].state,"conflicting");
});

test("unknown check states and missing answers remain unverified",()=>{
  const result=evaluateJobReadiness({template,answers:{scope:{state:"maybe"},access:{state:"satisfied",evidenceRefs:["a"]},materials:{state:"not_applicable"}}});
  assert.equal(result.checks[0].state,"unverified");
  assert.equal(result.status,"blocked");
});

test("template and answer structures are validated",()=>{
  assert.throws(()=>evaluateJobReadiness({template:{id:"bad id",version:"1",checks:[{id:"x"}]},answers:{}}),/versioned readiness template/);
  assert.throws(()=>evaluateJobReadiness({template:{id:"t",version:"1",checks:[{id:"x"},{id:"x"}]},answers:{}}),/unique valid identifiers/);
  assert.throws(()=>evaluateJobReadiness({template,answers:[]}),/answers must be an object/);
});

test("evidence references are bounded safe identifiers and user text is bounded",()=>{
  const result=evaluateJobReadiness({template,answers:{
    scope:{state:"satisfied",evidenceRefs:["contract-1","<script>"],reason:"x".repeat(600)},
    access:{state:"satisfied",evidenceRefs:["access-1"]},
    materials:{state:"not_applicable"}
  }});
  assert.deepEqual(result.checks[0].evidenceRefs,["contract-1"]);
  assert.equal(result.checks[0].reason.length,500);
  assert.equal(result.status,"ready_for_human_decision");
});

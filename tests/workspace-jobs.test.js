import test from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import {workspaceJobFields,verifiedJobSummary} from "../src/workspace-jobs.js";
import {COMMERCIAL_CLEANING_READINESS_TEMPLATE as template} from "../src/job-readiness.js";
const hash="a".repeat(64),create={action:"create",confirm:true,contractId:randomUUID(),siteId:randomUUID(),serviceDate:"2026-11-15",evidenceDigest:hash};
test("job input admits only exact shapes and known requirements",()=>{
 assert.ok(workspaceJobFields(create));assert.equal(workspaceJobFields({...create,customerName:"not admitted"}),null);
 const check={action:"check",confirm:true,eventId:randomUUID(),checkId:"price",checkStatus:"satisfied",evidenceDigest:hash};
 assert.ok(workspaceJobFields(check));assert.equal(workspaceJobFields({...check,checkStatus:"not_applicable"}),null);
 assert.ok(workspaceJobFields({...check,checkId:"access",checkStatus:"not_applicable"}));assert.equal(workspaceJobFields({...check,checkId:"unknown"}),null);
});
test("persisted evidence must reconcile with real shared readiness engine",()=>{
 const job={contractId:create.contractId,siteId:create.siteId,serviceDate:create.serviceDate,baselinePrice:"100.00",currency:"AUD",
 checks:Object.fromEntries(template.requirements.map(r=>[r.id,{status:"satisfied",evidenceDigest:hash}])),readinessStatus:"ready",resolvedRequiredChecks:11,totalRequiredChecks:11};
 assert.equal(verifiedJobSummary(job).readiness.completenessPercent,100);
 assert.throws(()=>verifiedJobSummary({...job,resolvedRequiredChecks:10}));assert.throws(()=>verifiedJobSummary({...job,checks:{}}));
});

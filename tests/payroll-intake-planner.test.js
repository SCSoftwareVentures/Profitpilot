import test from "node:test";
import assert from "node:assert/strict";
import {createHash,randomUUID} from "node:crypto";
import {canonicalPayrollRows,planMinimizedPayrollAllocation} from "../src/payroll-source-intake.js";
const H=x=>createHash("sha256").update(x).digest("hex");
const rows=[{source_row_key:"ppr_"+H("a"),amount:"0.10",currency:"AUD"},{source_row_key:"ppr_"+H("b"),amount:"0.20",currency:"AUD"}];
function fixture(){
 const bytes=canonicalPayrollRows(rows),manifest={format:"minimized-payroll-v1",sourceNamespace:randomUUID(),periodStart:"2026-11-01",periodEnd:"2026-11-14",currency:"AUD",controlTotal:"0.30",rowCount:2,fileSha256:H(bytes),authorityDigest:H("a"),policyDigest:H("b"),controlDigest:H("c")};
 return {bytes,manifest};
}
test("canonical API rows reconstruct reviewed export bytes",()=>{
 assert.equal(canonicalPayrollRows(rows).toString(),"source_row_key,amount,currency\n"+rows.map(r=>r.source_row_key+","+r.amount+",AUD\n").join(""));
 assert.equal(canonicalPayrollRows([{...rows[0],employee:"unapproved"}]),null);assert.equal(canonicalPayrollRows([{...rows[0],amount:0.1}]),null);
 assert.equal(canonicalPayrollRows([]),null);
});
test("minimized sources link to exact allocation proposals with explicit residual",()=>{
 const {bytes,manifest}=fixture(),pool=randomUUID(),site=randomUUID();
 const plan=planMinimizedPayrollAllocation(bytes,manifest,pool,[{sourceRowKey:rows[0].source_row_key,bucket:"direct",siteRef:site,amount:"0.10",evidenceRef:"synthetic-evidence"}]);
 assert.equal(plan.status,"needs_allocation");assert.equal(plan.proposal.totals.direct,"0.10");assert.equal(plan.proposal.totals.unallocated,"0.20");assert.equal(plan.requiresHumanConfirmation,true);
 const full=planMinimizedPayrollAllocation(bytes,manifest,pool,[{sourceRowKey:rows[0].source_row_key,bucket:"direct",siteRef:site,amount:"0.10",evidenceRef:"synthetic-evidence"},{sourceRowKey:rows[1].source_row_key,bucket:"non_site",siteRef:null,amount:"0.20",evidenceRef:"synthetic-evidence-2"}]);
 assert.equal(full.status,"pending_review");assert.equal(full.proposal.totals.unallocated,"0.00");
});
test("changed source and excess allocation remain held",()=>{
 const {bytes,manifest}=fixture(),pool=randomUUID();
 assert.equal(planMinimizedPayrollAllocation(bytes,{...manifest,controlTotal:"0.31"},pool,[]).status,"held");
 assert.equal(planMinimizedPayrollAllocation(bytes,manifest,pool,[{sourceRowKey:rows[0].source_row_key,bucket:"non_site",siteRef:null,amount:"0.11",evidenceRef:"synthetic-evidence"}]).status,"held");
});

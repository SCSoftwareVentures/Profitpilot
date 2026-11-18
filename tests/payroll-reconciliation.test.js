import test from "node:test";
import assert from "node:assert/strict";
import {normalizePayrollRows} from "../src/engine.js";
import {planPayrollReconciliation as plan} from "../src/payroll-reconciliation.js";
const pool={poolRef:"pool-1",periodStart:"2026-11-01",periodEnd:"2026-11-14",currency:"AUD",total:"0.30"};
const source=(key,amount,currency="AUD")=>{
  const row=normalizePayrollRows([{source_row_key:key,amount,currency}])[0];
  return {...row.record,rowSha256:row.rowSha256};
};
const sources=[source("a","0.10"),source("b","0.20")];
const line=(sourceRowKey,amount,overrides={})=>({sourceRowKey,bucket:"direct",siteRef:"site-1",amount,evidenceRef:"evidence-1",...overrides});
const base={pool,sourceRows:sources,allocations:[line("a","0.10"),line("b","0.20")]};
const reject=(input,code)=>{const r=plan(input);assert.equal(r.status,"held");assert.equal(r.proposal,null);assert.equal(r.errors[0].code,code);assert.equal(r.requiresHumanConfirmation,true);};
test("reconciles exact integer cents; never authorises",()=>{
  const r=plan(base);
  assert.equal(r.status,"pending_review");assert.equal(r.requiresHumanConfirmation,true);
  assert.equal(r.proposal.totals.direct,"0.30");
  assert.deepEqual(r.proposal.siteTotals,[{siteRef:"site-1",amount:"0.30"}]);
  assert.equal(r.proposal.attributionCoverageBasisPoints,10000);
  assert.equal(r.proposalSha256.length,64);
});
test("residual is explicit and blocks readiness",()=>{
  const r=plan({...base,allocations:[line("a","0.05")]});
  assert.equal(r.status,"needs_allocation");assert.equal(r.proposal.totals.unallocated,"0.25");
  assert.equal(r.proposal.attributionCoverageBasisPoints,1666);
  assert.equal(r.proposal.lines.filter(x=>x.bucket==="unallocated").length,2);
});
test("all buckets reconcile and exclude non-site amounts from site totals",()=>{
  const p={...pool,total:"1.00"};
  const r=plan({pool:p,sourceRows:[source("a","1.00")],allocations:[
    line("a","0.20"),line("a","0.30",{bucket:"approved_allocated"}),
    line("a","0.10",{bucket:"non_site",siteRef:null}),
    line("a","0.40",{bucket:"excluded",siteRef:null})
  ]});
  assert.equal(r.status,"pending_review");assert.equal(r.proposal.attributionCoverageBasisPoints,5000);
  assert.deepEqual(r.proposal.totals,{direct:"0.20",approved_allocated:"0.30",non_site:"0.10",excluded:"0.40",unallocated:"0.00"});
});
test("same logical proposal produces stable digest independent of input order",()=>{
  const r=plan(base),s=plan({...base,sourceRows:[...sources].reverse(),allocations:[...base.allocations].reverse()});
  assert.equal(r.proposalSha256,s.proposalSha256);assert.deepEqual(r.proposal,s.proposal);
  assert.notEqual(r.proposalSha256,plan({...base,allocations:[line("a","0.10",{evidenceRef:"other"}),line("b","0.20")]}).proposalSha256);
});
test("rejects source tampering, duplicate, mixed currency and pool mismatch",()=>{
  reject({...base,sourceRows:[{...sources[0],amount:"0.11"},sources[1]]},"SOURCE_DIGEST_MISMATCH");
  reject({...base,sourceRows:[sources[0],sources[0]]},"DUPLICATE_SOURCE_ROW");
  reject({...base,sourceRows:[source("a","0.10","NZD"),sources[1]]},"MIXED_CURRENCY");
  reject({...base,pool:{...pool,total:"0.31"}},"POOL_TOTAL_MISMATCH");
});
test("rejects source over-allocation even when aggregate total could reconcile",()=>{
  reject({...base,allocations:[line("a","0.20")]},"SOURCE_OVERALLOCATED");
  reject({...base,allocations:[line("missing","0.10")]},"UNKNOWN_SOURCE_ROW");
  reject({...base,allocations:[line("a","0.05"),line("a","0.05")]},"DUPLICATE_ALLOCATION_BUCKET");
});
test("rejects missing evidence, improper site association and personal columns",()=>{
  reject({...base,allocations:[line("a","0.10",{evidenceRef:""})]},"INVALID_ALLOCATION");
  reject({...base,allocations:[line("a","0.10",{bucket:"non_site"})]},"INVALID_ALLOCATION");
  reject({...base,allocations:[line("a","0.10",{siteRef:null})]},"INVALID_ALLOCATION");
  reject({...base,sourceRows:[{...sources[0],employee_name:"synthetic"},sources[1]]},"INVALID_SOURCE_ROW");
  reject({...base,employee_name:"synthetic"},"INVALID_INPUT_SHAPE");
});
test("rejects noncanonical amounts, invalid dates and excessive counts",()=>{
  for(const amount of ["-0.00","01","1e-2","0.001",0.1,"0.00"])
    reject({...base,allocations:[line("a",amount)]},"INVALID_ALLOCATION_AMOUNT");
  reject({...base,pool:{...pool,periodStart:"2026-02-30"}},"INVALID_POOL");
  reject({...base,sourceRows:[]},"INVALID_BATCH_SIZE");
  reject({...base,allocations:Array(50001).fill(null)},"INVALID_BATCH_SIZE");
});
test("zero pool has no artificial coverage; max supported amount stays exact",()=>{
  const zero=plan({pool:{...pool,total:"0"},sourceRows:[source("z","0")],allocations:[]});
  assert.equal(zero.status,"pending_review");assert.equal(zero.proposal.attributionCoverageBasisPoints,null);
  const max="999999999999.99";
  const r=plan({pool:{...pool,total:max},sourceRows:[source("max",max)],allocations:[line("max",max)]});
  assert.equal(r.proposal.totals.direct,max);assert.equal(r.proposal.attributionCoverageBasisPoints,10000);
});

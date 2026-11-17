import test from "node:test";
import assert from "node:assert/strict";
import {validatePayrollRows} from "../src/engine.js";

const period={periodStart:"2026-02-01",periodEnd:"2026-02-28"};
const good={source_ref:"SYNTHETIC-1",cost_component:"gross_wages",amount:"1250.50",currency:"AUD",period_start:"2026-02-01",period_end:"2026-02-14"};
const check=row=>validatePayrollRows([row],period)[0];

test("structurally valid payroll is held for human review, not automatically approved",()=>{
 assert.equal(check(good).status,"pending_review");
 assert.deepEqual(check(good).errors,[]);
});
test("missing or oversized source reference and cost component are held",()=>{
 for(const change of [{source_ref:""},{cost_component:""},{source_ref:"x".repeat(121)},{cost_component:"x".repeat(121)}])
  assert.equal(check({...good,...change}).status,"held");
});
test("zero, negative, malformed and imprecise amounts are held",()=>{
 for(const amount of ["0","0.00","-3","1,200","1e3","1.001","$10",0,1.2,null]){
  assert.equal(check({...good,amount}).status,"held",String(amount));
 }
});
test("precise decimal string amounts pass structural checks without coercion",()=>{
 for(const amount of ["0.01","1","1.2","999999999999.99"])assert.equal(check({...good,amount}).status,"pending_review",amount);
});
test("unsupported and omitted currencies are held rather than converted",()=>{
 for(const currency of ["USD","aud","AUD ",null,undefined])assert.equal(check({...good,currency}).status,"held");
});
test("invalid, reversed and out-of-batch periods are held",()=>{
 for(const item of [{period_start:"2026-02-30"},{period_end:"2026-02-29"},{period_start:"2026-02-16",period_end:"2026-02-14"},{period_start:"2026-01-31"},{period_end:"2026-03-01"}])
  assert.equal(check({...good,...item}).status,"held",JSON.stringify(item));
});
test("valid leap day and raw row numbers are handled",()=>{
 const row={...good,period_start:"2024-02-28",period_end:"2024-02-29",__rowNumber:"73"};
 const x=validatePayrollRows([row],{periodStart:"2024-02-01",periodEnd:"2024-02-29"})[0];
 assert.equal(x.status,"pending_review");
 assert.equal(x.rowNumber,"73");
 assert.equal(check(null).status,"held");
});

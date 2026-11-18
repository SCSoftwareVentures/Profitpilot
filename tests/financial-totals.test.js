import test from "node:test";
import assert from "node:assert/strict";
import {exactAggregateCents,financialTotals} from "../src/financial-totals.js";
test("PostgreSQL decimal aggregates convert to exact cents",()=>{
 assert.equal(exactAggregateCents("0.30"),30);
 assert.equal(exactAggregateCents("-0.01"),-1);
 assert.equal(exactAggregateCents("90071992547409.91"),9007199254740991);
});
test("financial contribution avoids binary float drift",()=>{
 assert.deepEqual(financialTotals("0.30","0.20"),{revenue:0.3,deliveryCost:0.2,contribution:0.1,marginPercent:33.33});
 assert.deepEqual(financialTotals("125.50","25.25"),{revenue:125.5,deliveryCost:25.25,contribution:100.25,marginPercent:79.88});
});
test("reject malformed, imprecise or unsafe financial aggregates",()=>{
 for(const value of ["NaN","Infinity","1.001","1e3","1",null,123.45,"90071992547409.92"])assert.throws(()=>exactAggregateCents(value));
});

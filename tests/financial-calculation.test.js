import test from "node:test";
import assert from "node:assert/strict";
import {decimalCents,formatCents,contributionTotals,canonicalSnapshot,snapshotDigest,MAX_EVIDENCE_LINES} from "../src/financial-calculation.js";
test("decimal parsing preserves cents and rejects ambiguous representations",()=>{
 assert.equal(decimalCents("999999999999.99"),99999999999999n);
 assert.equal(decimalCents("-0.01"),-1n);assert.equal(formatCents(-1n),"-0.01");
 for(const v of [1,"","1e2","1.001"," 1","NaN","+1","1000000000000","Infinity",null])assert.throws(()=>decimalCents(v));
});
test("exact contribution and rounded margin avoid binary floating-point arithmetic",()=>{
 assert.deepEqual(contributionTotals(["0.10","0.20"],["0.10"]).exact,{revenue:"0.30",deliveryCost:"0.10",contribution:"0.20",marginPercent:"66.67"});
 assert.equal(contributionTotals(["32"],["31.99"]).exact.marginPercent,"0.03");
 assert.equal(contributionTotals(["32"],["32.01"]).exact.marginPercent,"-0.03");
 assert.equal(contributionTotals(["32"],["31"]).exact.marginPercent,"3.13");
 assert.equal(contributionTotals(["32"],["33"]).exact.marginPercent,"-3.13");
 assert.equal(contributionTotals(["0"],["1"]).exact.marginPercent,null);
 assert.equal(contributionTotals(["-1"],["1"]).marginPercent,null);
});
test("financial precision and nonnegative payroll fail closed",()=>{
 assert.throws(()=>contributionTotals(["999999999999.99","0.01"],["0"]));
 assert.throws(()=>contributionTotals(["-999999999999.99"],["0.01"]));
 assert.throws(()=>contributionTotals(["1"],["-0.01"]));
 assert.throws(()=>contributionTotals([],["1"]));
 assert.throws(()=>contributionTotals(Array(MAX_EVIDENCE_LINES+1).fill("1"),["1"]));
 const huge=contributionTotals(["0.01"],["999999999999.99"]);
 assert.equal(huge.marginPercent,null);assert.equal(huge.exact.marginPercent,"-9999999999999800.00");
});
test("snapshot digest is deterministic over JSON object key order and detects input changes",()=>{
 const a={rows:[{id:"a",amount:"1.00"}],version:2};
 const b={version:2,rows:[{amount:"1.00",id:"a"}]};
 assert.equal(canonicalSnapshot(a),canonicalSnapshot(b));
 assert.equal(snapshotDigest(a),snapshotDigest(b));
 assert.notEqual(snapshotDigest(a),snapshotDigest({...a,rows:[{id:"a",amount:"1.01"}]}));
 assert.throws(()=>canonicalSnapshot({amount:0.1}));
});

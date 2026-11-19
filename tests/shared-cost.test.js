import test from "node:test";import assert from "node:assert/strict";import {randomUUID} from "node:crypto";import {sharedCostFields} from "../src/shared-cost.js";
test("exact ordered source split canonicalization denies duplicate, unordered and noncanonical inputs",()=>{
 const source=randomUUID(),a=randomUUID(),b=randomUUID(),base=randomUUID(),ids=[a,b].sort(),evidenceDigest="a".repeat(64);
 const shares=[[ids[0],base,"0.01"],[ids[1],base,"0.02"],[null,null,"0.01"]];
 const input={shares,evidenceDigest};const f=sharedCostFields("payroll",source,input);
 assert.equal(f.canonical.split("\n").at(-1),"~,~,0.01");
 for(const bad of [[shares[0],shares[0]],[shares[1],shares[0]],[[null,base,"0.01"]],[[a,base,0.01]],[[a,base,"0.00"]],[[a,base,"0.001"]]])assert.equal(sharedCostFields("payroll",source,{shares:bad,evidenceDigest}),null);
 assert.equal(sharedCostFields("other",source,input),null);
});

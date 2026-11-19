import test from "node:test";import assert from "node:assert/strict";import {randomUUID} from "node:crypto";import {sharedCostFields} from "../src/shared-cost.js";
test("exact ordered source split canonicalization denies duplicate, unordered and noncanonical inputs",()=>{
 const source=randomUUID(),a=randomUUID(),b=randomUUID(),base=randomUUID(),ids=[a,b].sort(),evidenceDigest="a".repeat(64);
 const shares=[[ids[0],base,"0.01"],[ids[1],base,"0.02"],[null,null,"0.01"]];
 const input={shares,evidenceDigest};const f=sharedCostFields("payroll",source,input);
 assert.equal(f.canonical.split("\n").at(-1),"~,~,0.01");
 for(const bad of [[shares[0],shares[0]],[shares[1],shares[0]],[[null,base,"0.01"]],[[a,base,0.01]],[[a,base,"0.00"]],[[a,base,"0.001"]]])assert.equal(sharedCostFields("payroll",source,{shares:bad,evidenceDigest}),null);
 assert.equal(sharedCostFields("other",source,input),null);
});

test("business overhead canonicalization binds site and contract and admits one remainder",()=>{
 const source=randomUUID(),site1=randomUUID(),site2=randomUUID(),contract=randomUUID(),base=randomUUID(),evidenceDigest="b".repeat(64);
 const shares=[[site1,contract,base,"0.02"],[site2,contract,base,"0.03"]].sort((a,b)=>a[0]<b[0]?-1:1);shares.push([null,null,null,"0.01"]);
 const x=sharedCostFields("business_overhead",source,{shares,evidenceDigest});
 assert.equal(x.canonical.split("\n").at(-1),"~,~,~,0.01");
 assert.equal(sharedCostFields("overhead",source,{shares,evidenceDigest}),null);
 assert.equal(sharedCostFields("business_overhead",source,{shares:[shares[0],shares[0]],evidenceDigest}),null);
 assert.equal(sharedCostFields("business_overhead",source,{shares:[[null,contract,base,"0.01"]],evidenceDigest}),null);
});

test("non-site payroll uses ordered site contract baseline targets without assumed business origin",()=>{const source=randomUUID(),site=randomUUID(),contract=randomUUID(),base=randomUUID();const f=sharedCostFields("non_site_payroll",source,{shares:[[site,contract,base,"0.10"],[null,null,null,"0.10"]],evidenceDigest:"c".repeat(64)});assert.equal(f.canonical.split("\n").at(-1),"~,~,~,0.10");assert.equal(sharedCostFields("non_site_payroll",source,{shares:[[contract,base,"0.20"]],evidenceDigest:"c".repeat(64)}),null);});

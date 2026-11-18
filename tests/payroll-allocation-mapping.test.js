import test from "node:test";
import assert from "node:assert/strict";
import {randomUUID,createHash} from "node:crypto";
import {canonicalAllocationMapping} from "../src/payroll-allocation-mapping.js";
const H=x=>createHash("sha256").update(x).digest("hex"),pool=randomUUID(),site=randomUUID();
const row={sourceRowKey:"ppr_"+H("synthetic row"),bucket:"approved_allocated",siteId:site,amount:"0.10",evidenceRef:"ev_"+H("synthetic evidence").slice(0,60)};
test("canonical exact mapping",()=>{
 assert.equal(canonicalAllocationMapping(pool,[row]),["payroll-allocation-build-v1",pool,[row.sourceRowKey,row.bucket,site,row.amount,row.evidenceRef].join(",")].join("\n"));
 assert.equal(canonicalAllocationMapping(pool,[]),"payroll-allocation-build-v1\n"+pool);
});
for(const [name,change] of [
 ["direct", {bucket:"direct"}],["injected residual",{bucket:"unallocated"}],["extra field",{employee:"synthetic"}],["negative",{amount:"-0.01"}],["number",{amount:0.1}],["zero",{amount:"0.00"}],["wrong site",{siteId:"invalid"}],["null site",{siteId:null}],["non-site with site",{bucket:"non_site"}],["free-form evidence",{evidenceRef:"synthetic note"}],["raw identity",{sourceRowKey:"employee-123"}]
])test("mapping rejects "+name,()=>assert.equal(canonicalAllocationMapping(pool,[{...row,...change}]),null));
test("duplicate tuple and invalid size rejected",()=>{assert.equal(canonicalAllocationMapping(pool,[row,row]),null);assert.equal(canonicalAllocationMapping(pool,Array(401).fill(row)),null);});
test("site-less non-site mapping admitted",()=>assert.ok(canonicalAllocationMapping(pool,[{...row,siteId:null,bucket:"non_site"}])));

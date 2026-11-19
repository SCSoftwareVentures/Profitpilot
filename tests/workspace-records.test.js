import test from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import {workspaceRecordFields,workspaceVersionFields} from "../src/workspace-records.js";
const b=randomUUID(),c=randomUUID(),v=randomUUID();
test("managed record structures",()=>{
 for(const r of [{kind:"business",parentId:null,relatedId:null,label:"Synthetic Business"},{kind:"customer",parentId:b,relatedId:null,label:"Synthetic Customer"},{kind:"contract",parentId:b,relatedId:c,label:"Synthetic Agreement"},{kind:"contract_site",parentId:b,relatedId:c,label:null}])assert.ok(workspaceRecordFields(r));
 for(const r of [{kind:"site",parentId:null,relatedId:null,label:"Site"},{kind:"business",parentId:null,relatedId:null,label:"Bank account 123456789"},{kind:"contract_site",parentId:b,relatedId:c,label:"Unexpected"},{kind:"business",parentId:null,relatedId:null,label:"<script>"}])assert.equal(workspaceRecordFields(r),null);
});
const spec={versionId:v,periodStart:"2026-11-01",periodEnd:"2026-11-30",price:"100.00",taxBasis:"gst_exclusive",billingBasis:"monthly",evidenceDigest:"a".repeat(64)};
test("canonical baseline validates exact date and price",()=>{assert.ok(workspaceVersionFields(spec));for(const change of [{price:100},{price:"-1.00"},{price:"1e2"},{periodEnd:"2026-02-30"},{periodEnd:"2028-01-01"},{taxBasis:"unknown"},{extra:true},{evidenceDigest:"0".repeat(64)}])assert.equal(workspaceVersionFields({...spec,...change}),null);});

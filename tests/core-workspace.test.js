import test from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import {workspaceInput,coreWorkspaceGate} from "../server/core-workspace.js";
const input={setupId:randomUUID(),businessName:"Synthetic Business",siteName:"Synthetic Site",customerName:"Synthetic Customer",effectiveFrom:"2026-11-01",price:"1000.01",currency:"AUD",taxBasis:"gst_exclusive",billingBasis:"monthly"};
test("workspace preserves exact price and permits only reviewed draft fields",()=>{
 const {setupId,...data}=input;
 assert.deepEqual(workspaceInput(input),{setupId,data});
 for(const patch of [{price:1000.01},{price:"1.001"},{price:"01.00"},{price:"-1.00"},{price:"1000000000000.00"},{effectiveFrom:"2026-02-30"},{effectiveFrom:"0000-01-01"},{currency:"USD"},{taxBasis:"approved"},{billingBasis:"hourly"},{businessName:" person@example.invalid"},{siteName:"Synthetic Site\n"},{customerName:"X".repeat(121)},{approved:true},{setupId:"not-an-id"},{price:null}])assert.equal(workspaceInput({...input,...patch}),null);
 assert.equal(workspaceInput({...input,price:"999999999999.99"}).data.price,"999999999999.99");
 assert.equal(workspaceInput({...input,price:"0.00",taxBasis:"unknown"}).data.price,"0.00");
});
test("production workspace gate captures closed state at bootstrap",()=>{
 const env={NODE_ENV:"production",CORE_WORKSPACES_ENABLED:"true"};const gate=coreWorkspaceGate(env);
 env.NODE_ENV="test";
 let status,next=false;
 gate({}, {status(n){status=n;return this;},json(){}},()=>{next=true;});
 assert.equal(status,503);assert.equal(next,false);
 coreWorkspaceGate({NODE_ENV:"test"})({},null,()=>{next=true;});assert.equal(next,true);
});

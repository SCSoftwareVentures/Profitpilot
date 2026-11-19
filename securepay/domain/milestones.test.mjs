import test from "node:test";
import assert from "node:assert/strict";
import {createPlan,advance} from "./milestones.ts";
const items=[{id:"stage1",amountCents:30000,description:"Stage 1",final:false},
{id:"final",amountCents:70000,description:"Final completion",final:true}];
const plan=()=>createPlan(100000,items);
const accepted=()=>advance(advance(plan(),{type:"ACCEPT_PLAN",actor:"owner"}),{type:"ACCEPT_PLAN",actor:"customer"});
const move=(p,type,id="stage1",extra={})=>advance(p,{type,id,actor:type==="SUBMIT"?"owner":type==="APPROVE"||type==="DISPUTE"?"customer":"payment_service",...extra});
test("amounts must match total and final milestone is mandatory",()=>{
 assert.throws(()=>createPlan(100001,items));
 assert.throws(()=>createPlan(100000,items.map(x=>({...x,final:false}))));
 assert.throws(()=>createPlan(100000,[items[0],items[0]]));
});
test("both parties must accept before milestone submission",()=>{
 assert.throws(()=>move(plan(),"SUBMIT","stage1",{photos:["a"]}));
 assert.throws(()=>move(advance(plan(),{type:"ACCEPT_PLAN",actor:"owner"}),"SUBMIT","stage1",{photos:["a"]}));
});
test("photos required, comments optional, cost details not requested",()=>{
 assert.throws(()=>move(accepted(),"SUBMIT","stage1",{photos:[]}));
 const p=move(accepted(),"SUBMIT","stage1",{photos:["completion"]});
 assert.equal(p.milestones[0].comment,undefined);
 assert.equal(p.milestones[0].status,"submitted");
});
test("disputed milestone cannot release normally",()=>{
 const p=move(move(accepted(),"SUBMIT","stage1",{photos:["completion"]}),"DISPUTE");
 assert.throws(()=>move(p,"APPROVE"));
 assert.throws(()=>move(p,"REQUEST_RELEASE","stage1",{verifiedAuthorizationRef:"token"}));
});
test("release requires approval and verified authorization reference and provider confirmation",()=>{
 let p=move(accepted(),"SUBMIT","stage1",{photos:["completion"]});
 assert.throws(()=>move(p,"REQUEST_RELEASE","stage1",{verifiedAuthorizationRef:"token"}));
 p=move(p,"APPROVE");
 assert.throws(()=>move(p,"REQUEST_RELEASE","stage1",{verifiedAuthorizationRef:""}));
 p=move(p,"REQUEST_RELEASE","stage1",{verifiedAuthorizationRef:"token"});
 assert.equal(p.milestones[0].status,"release_pending");
 p=move(p,"CONFIRM_RELEASE","stage1",{providerTransactionRef:"txn-1"});
 assert.equal(p.milestones[0].status,"released");
 assert.throws(()=>move(p,"CONFIRM_RELEASE","stage1",{providerTransactionRef:"txn-1"}));
});
test("final completion cannot be submitted until earlier milestones are released",()=>{
 assert.throws(()=>move(accepted(),"SUBMIT","final",{photos:["final"]}));
 let p=move(accepted(),"SUBMIT","stage1",{photos:["first"]});
 p=move(p,"APPROVE");
 p=move(p,"REQUEST_RELEASE","stage1",{verifiedAuthorizationRef:"verified"});
 p=move(p,"CONFIRM_RELEASE","stage1",{providerTransactionRef:"txn-1"});
 p=move(p,"SUBMIT","final",{photos:["finished"]});
 assert.equal(p.milestones[1].status,"submitted");
});

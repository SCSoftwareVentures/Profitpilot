import test from "node:test";
import assert from "node:assert/strict";
import {EventEmitter} from "node:events";
import {jsonWithinBudget,createRequestAdmission,createWorkBudget} from "../server/request-budget.js";

test("bounded JSON admits normal chunks and rejects unsupported depth, breadth and characters",()=>{
 assert.equal(jsonWithinBudget({rows:Array.from({length:200},()=>Object.fromEntries(Array.from({length:10},(_,i)=>["field"+i,"value"]))) }),true);
 assert.equal(jsonWithinBudget({name:"valid \u{1F600}"}),true);
 assert.equal(jsonWithinBudget(JSON.parse('{"__proto__":{"polluted":true}}')),false);
 assert.equal(jsonWithinBudget({constructor:"unsafe"}),false);
 assert.equal(jsonWithinBudget({value:"\u0000"}),false);
 assert.equal(jsonWithinBudget({value:"\ud800"}),false);
 assert.equal(jsonWithinBudget(Array(4096).fill(0)),false);
 let nested={};for(let i=0;i<10;i++)nested={nested};
 assert.equal(jsonWithinBudget(nested),false);
});
test("request admission refuses excess connections and releases precisely once",()=>{
 const gate=createRequestAdmission(2);
 function request(){
  const res=new EventEmitter();res.set=()=>res;res.status=n=>{res.code=n;return res;};res.json=()=>res;
  let admitted=false;gate({},res,()=>{admitted=true;});return {res,admitted};
 }
 const a=request(),b=request();assert.equal(a.admitted,true);assert.equal(b.admitted,true);
 assert.equal(request().res.code,503);
 a.res.emit("finish");a.res.emit("close");
 const c=request();assert.equal(c.admitted,true);assert.equal(request().res.code,503);
 b.res.emit("close");c.res.emit("finish");
 assert.equal(request().admitted,true);
});
test("work capacity is released only after completion or rejection",async()=>{
 const gate=createWorkBudget(1);let release;
 const pending=gate(()=>new Promise(resolve=>{release=resolve;}));
 await assert.rejects(()=>gate(()=>true),e=>e.status===503);
 release("done");assert.equal(await pending,"done");
 await assert.rejects(()=>gate(()=>{throw Error("failure");}),/failure/);
 assert.equal(await gate(()=>true),true);
});

import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {requireRole} from "../server/auth.js";

const allowed=["owner","admin","analyst","reviewer"];
test("financial report role gate denies missing membership and unauthorised roles",()=>{
 const gate=requireRole(...allowed);
 for(const role of [undefined,"viewer","billing","guest"]){
  let status,called=false;
  const req={membership:role?{role}:undefined};
  const res={status(code){status=code;return this;},json(body){assert.equal(body.error,"Insufficient tenant role");}};
  gate(req,res,()=>{called=true;});
  assert.equal(status,403);
  assert.equal(called,false);
 }
});
test("financial report role gate permits only approved roles",()=>{
 const gate=requireRole(...allowed);
 for(const role of allowed){
  let called=false;
  gate({membership:{role}},{status(){throw new Error("Unexpected denial");}},()=>{called=true;});
  assert.equal(called,true);
 }
});
test("calculation read endpoint retains membership and explicit role gate",()=>{
 const source=readFileSync(new URL("../server/index.js",import.meta.url),"utf8");
 assert.match(source,/app\.get\("\/v1\/tenants\/:tenantId\/calculations\/:runId",membership,requireRole\("owner","admin","analyst","reviewer"\),async/);
});
test("server error logger does not serialize raw exception messages",()=>{
 const source=readFileSync(new URL("../server/index.js",import.meta.url),"utf8");
 assert.doesNotMatch(source,/process\.stderr\.write\([^\n]*message:err\.message/);
 assert.match(source,/event:"request_error",id,code:/);
});

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

test("unauthenticated HTTP financial report request is rejected before database access",async()=>{
 process.env.NODE_ENV="test";
 const {default:app}=await import("../server/index.js");
 const server=await new Promise(resolve=>{const s=app.listen(0,"127.0.0.1",()=>resolve(s));});
 try{
  const address=server.address();
  const response=await fetch("http://127.0.0.1:"+address.port+"/v1/tenants/00000000-0000-4000-8000-000000000000/calculations/00000000-0000-4000-8000-000000000001");
  assert.equal(response.status,401);
  const body=await response.json();
  assert.ok(body.error);
  assert.equal(body.outputs,undefined);
 }finally{await new Promise((resolve,reject)=>server.close(e=>e?reject(e):resolve()));}
});

test("reconciliation runs inside calculation creation, never match review",async()=>{
 const {readFile}=await import("node:fs/promises");
 const source=await readFile(new URL("../server/index.js",import.meta.url),"utf8");
 const matchStart=source.indexOf('app.post("/v1/tenants/:tenantId/matches/:matchId/decision"');
 const calculationStart=source.indexOf('app.post("/v1/tenants/:tenantId/calculations"');
 const calculationRead=source.indexOf('app.get("/v1/tenants/:tenantId/calculations/:runId"');
 assert.ok(matchStart>=0&&calculationStart>matchStart&&calculationRead>calculationStart);
 assert.ok(!source.slice(matchStart,calculationStart).includes("reconcileFinancialReport("));
 assert.ok(source.slice(calculationStart,calculationRead).includes("const reconciliation=reconcileFinancialReport(outputs,"));
 assert.ok(source.slice(calculationStart,calculationRead).includes("reconciliation,sourceEvidence})"));
});

test("financial calculation persists bounded source-row fingerprints, not source identifiers",async()=>{
 const {readFile}=await import("node:fs/promises");
 const source=await readFile(new URL("../server/index.js",import.meta.url),"utf8");
 const start=source.indexOf('app.post("/v1/tenants/:tenantId/calculations"');
 const end=source.indexOf('app.get("/v1/tenants/:tenantId/calculations/:runId"');
 assert.ok(start>=0&&end>start);
 const route=source.slice(start,end);
 assert.match(route,/const invoiceEvidence=await client\.query/);
 assert.match(route,/const costEvidence=await client\.query/);
 assert.match(route,/mr\.decision='confirmed'/);
 assert.match(route,/ar\.status='confirmed'/);
 assert.match(route,/sourceEvidence\}\)/);
 assert.match(route,/Source evidence counts changed during calculation/);
});

test("source-status endpoint requires tenant membership and compares stored fingerprints",async()=>{
 const {readFile}=await import("node:fs/promises");
 const source=await readFile(new URL("../server/index.js",import.meta.url),"utf8");
 const start=source.indexOf('app.get("/v1/tenants/:tenantId/calculations/:runId/source-status"');
 assert.ok(start>=0);
 const route=source.slice(start,source.indexOf('app.use((err,req,res,next)=>',start));
 assert.match(route,/requireRole\("owner","admin","analyst","reviewer"\)/);
 assert.match(route,/row\.inputs\?\.sourceEvidence/);
 assert.match(route,/previous\.version!==1/);
 assert.match(route,/mr\.decision='confirmed'/);
 assert.match(route,/ar\.status='confirmed'/);
 assert.match(route,/matches\?"unchanged":"changed"/);
});

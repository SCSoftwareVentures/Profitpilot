import test from "node:test";
import assert from "node:assert/strict";
import express from "express";
import {readFileSync} from "node:fs";
import {createBoundedServer} from "../server/network-boundary.js";
import {mountSecurePayCandidate} from "../server/securepay-candidate.js";
import {productionReleaseGate} from "../server/release-gate.js";

async function withApp(env,fn){
 const app=express();app.use(productionReleaseGate(env));
 await mountSecurePayCandidate(app,env);
 app.use("/v1",(_req,res)=>res.status(401).json({error:"Staff authentication required"}));
 const server=createBoundedServer(app);
 await new Promise(resolve=>server.listen(0,"127.0.0.1",resolve));
 try{await fn("http://127.0.0.1:"+server.address().port);}
 finally{await new Promise(resolve=>server.close(resolve));}
}
test("candidate defaults closed, and production release gate cannot be overridden",async()=>{
 for(const env of [{NODE_ENV:"test"},{NODE_ENV:"production",SECUREPAY_SANDBOX_ENABLED:"true"}]){
  await withApp(env,async base=>{
   const response=await fetch(base+"/v1/securepay/portal");
   assert.equal(response.status,env.NODE_ENV==="production"?503:404);
  });
 }
});
test("sandbox mount is isolated from staff authentication and refuses uploads/compression",async()=>{
 await withApp({NODE_ENV:"test",SECUREPAY_SANDBOX_ENABLED:"true",SECUREPAY_AUTHORITY_SOCKET:"/tmp/profitpilot-candidate-test-absent.sock"},async base=>{
  const page=await fetch(base+"/v1/securepay/portal");
  assert.equal(page.status,200);assert.match(page.headers.get("cache-control"),/no-store/);
  assert.equal((await fetch(base+"/v1/me")).status,401);
  const path="/v1/securepay/tenants/11111111-1111-4111-8111-111111111111/milestones/22222222-2222-4222-8222-222222222222/";
  assert.equal((await fetch(base+path+"reserve",{method:"POST",headers:{"content-type":"application/json"},body:"{}"})).status,401);
  assert.equal((await fetch(base+path+"case-upload",{method:"POST",headers:{"content-type":"application/json"},body:"{}"})).status,413);
  assert.equal((await fetch(base+path+"reserve",{method:"POST",headers:{"content-encoding":"gzip","content-type":"application/json"},body:"{}"})).status,415);
  assert.equal((await fetch(base+"/v1/securepay/unknown")).status,404);
 });
});
test("gateway refuses credentials in staff process",async()=>{
 await assert.rejects(mountSecurePayCandidate(express(),{NODE_ENV:"test",SECUREPAY_SANDBOX_ENABLED:"true",SECUREPAY_AUTHORITY_SOCKET:"/tmp/test.sock",SECUREPAY_PIN_PEPPER:"fixture"}),/authority secrets forbidden/);
});
test("real app preserves the global production gate and separate authentication order",()=>{
 const source=readFileSync(new URL("../server/index.js",import.meta.url),"utf8");
 const positions=["app.use(createRequestAdmission(32))","app.use(productionReleaseGate())","await mountSecurePayCandidate(app)","app.use(\"/v1\",authRequired())","app.use(\"/v1\",sessionRequired(checkIdentitySession))"].map(x=>source.indexOf(x));
 assert.ok(positions.every((v,i)=>v>=0&&(i===0||v>positions[i-1])));
});

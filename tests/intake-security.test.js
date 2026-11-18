import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {createHmac,createHash} from "node:crypto";
import express from "express";
import {importIntakeGate,promotionProof} from "../server/intake-security.js";
const tenant="33333333-3333-4333-8333-333333333333",batch="44444444-4444-4444-8444-444444444444";

test("all production import paths reject before parsing, without disabling other endpoints",async()=>{
 const app=express();
 let routed=0,parsed=0;
 app.use("/v1/tenants/:tenantId/imports",importIntakeGate({NODE_ENV:"production",QUARANTINE_UPLOADS_ENABLED:"true",ALLOW_LIVE_IMPORTS:"true"}));
 app.use((req,res,next)=>{parsed++;next();});
 app.use(express.json());
 app.post("/v1/tenants/:tenantId/imports/*rest",(req,res)=>{routed++;res.sendStatus(200);});
 app.get("/health",(req,res)=>res.sendStatus(200));
 const server=app.listen(0,"127.0.0.1");await new Promise(resolve=>server.once("listening",resolve));
 try{
  const base="http://127.0.0.1:"+server.address().port;
  for(const path of ["/imports","/imports/"+batch+"/rows","/IMPORTS/"+batch+"/validate","/imports/"+batch+"/file","/imports/"+batch+"/file/approve"]){
   const res=await fetch(base+"/v1/tenants/"+tenant+path,{method:"POST",headers:{"content-type":"application/json"},body:"{malformed"});
   assert.equal(res.status,503,path);
  }
  assert.equal(parsed,0);assert.equal(routed,0);
  assert.equal((await fetch(base+"/health")).status,200);
  assert.equal(parsed,1);
 }finally{await new Promise(resolve=>server.close(resolve));}
 const source=readFileSync(new URL("../server/index.js",import.meta.url),"utf8");
 const gate='app.use("/v1/tenants/:tenantId/imports",importIntakeGate())';
 assert.ok(source.includes(gate));
 assert.ok(source.indexOf(gate)<source.indexOf('app.use("/v1",express.json'));
 assert.ok(source.indexOf(gate)>source.indexOf('app.use("/v1",sessionRequired(checkIdentitySession))'));
 let called=0;importIntakeGate({NODE_ENV:"test"})({},null,()=>called++);assert.equal(called,1);
});
test("approval proof binds exact batch, tenant, verified session and recent MFA",()=>{
 const now=1780000000,secret=createHash("sha256").update("synthetic promotion fixture").digest("hex"),env={TENANT_CONTEXT_HMAC_SECRET:secret,TENANT_CONTEXT_HMAC_KEY_ID:"ci"};
 const identity={subject:"synthetic-subject",mfa:true,authTime:now-10,issuedAt:now,sessionId:"synthetic-session"};
 const proof=promotionProof(tenant,batch,identity,env,now);
 assert.deepEqual(proof.slice(0,5),[tenant,batch,String(now-10),String(now),createHash("sha256").update(identity.sessionId).digest("hex")]);
 assert.equal(proof[5],String(now+20));assert.match(proof[6],/^[a-f0-9]{32}$/);assert.equal(proof[7],"ci");
 const expected=createHmac("sha256",Buffer.from(secret,"hex")).update(["profitpilot-promotion-v1",tenant,batch,identity.subject,...proof.slice(2,-1)].join("\n")).digest("hex");
 assert.equal(proof[8],expected);assert.ok(!proof.includes(identity.sessionId));
 for(const bad of [{mfa:false},{authTime:now-301},{issuedAt:now+6},{subject:"bad\nsubject"},{sessionId:undefined}])assert.throws(()=>promotionProof(tenant,batch,{...identity,...bad},env,now));
 assert.throws(()=>promotionProof("bad",batch,identity,env,now));
});

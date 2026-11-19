import test from "node:test";
import assert from "node:assert/strict";
import {createServer,request} from "node:http";
import {once} from "node:events";
import {dashboardHandler} from "../scripts/security-dashboard.js";
const token="0123456789abcdef".repeat(4);
const drift={schemaVersion:1,observedAt:"2026-11-18T00:00:00Z",catalogVerified:false,status:"catalog_drift",counts:null,activeIncidents:null,nextCursor:null};
test("dashboard denies unauthorized, cross-origin, malformed and mutation requests; drift fails closed",async()=>{
 let calls=0,page;
 const authority="localhost:8443",server=createServer(dashboardHandler({token,authority,snapshot:async p=>{calls++;page=p;return drift;}}));
 server.listen(0,"127.0.0.1");await once(server,"listening");
 const req=(path,headers={},method="GET")=>new Promise((resolve,reject)=>{
  const q=request({hostname:"127.0.0.1",port:server.address().port,path,method,headers:{Host:authority,...headers}},res=>{
   let body="";res.on("data",chunk=>body+=chunk);res.on("end",()=>resolve({status:res.statusCode,headers:{get:key=>res.headers[key.toLowerCase()]??null},text:async()=>body,json:async()=>JSON.parse(body)}));
   res.on("error",reject);
  });q.on("error",reject);q.end();
 });
 try{
  const ui=await req("/");assert.equal(ui.status,200);assert.match(ui.headers.get("content-security-policy"),/frame-ancestors 'none'/);assert.equal(ui.headers.get("cache-control"),"no-store");
  assert.match(await ui.text(),/Security command centre/);
  assert.equal((await req("/dashboard.js")).status,200);
  assert.equal((await req("/snapshot")).status,401);
  assert.equal((await req("/snapshot",{Authorization:"Bearer "+"a".repeat(64)})).status,401);
  const auth={Authorization:"Bearer "+token};
  assert.equal((await req("/snapshot",{...auth,Origin:"https://evil.invalid"})).status,403);
  assert.equal((await req("/snapshot",{...auth,Host:"evil.invalid"})).status,403);
  assert.equal((await req("/snapshot",auth,"POST")).status,403);
  for(const q of ["?limit=101","?limit=1&limit=2","?token="+token,"?cursor=bad"])assert.equal((await req("/snapshot"+q,auth)).status,400);
  assert.equal(calls,0);
  const result=await req("/snapshot?limit=1",auth);assert.equal(result.status,503);assert.deepEqual(await result.json(),drift);assert.deepEqual(page,{limit:1,cursor:null});assert.equal(calls,1);
 }finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
});

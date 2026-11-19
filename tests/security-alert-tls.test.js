import test from "node:test";
import assert from "node:assert/strict";
import {mkdtempSync,readFileSync,rmSync} from "node:fs";
import {join} from "node:path";
import {tmpdir} from "node:os";
import {execFileSync} from "node:child_process";
import {createServer} from "node:https";
import {once} from "node:events";
import {initialAlertState,observeAlerts,deliverAlert,verifyAlert} from "../scripts/security-alert-delivery.js";
const key="0123456789abcdef".repeat(4);
test("real TLS webhook validates signatures and rejects untrusted certificates and redirect responses",async()=>{
 const dir=mkdtempSync(join(tmpdir(),"pp-alert-tls-"));
 let server;
 try{
  execFileSync("openssl",["req","-x509","-newkey","rsa:2048","-nodes","-days","1","-subj","/CN=localhost","-addext","subjectAltName=DNS:localhost,IP:127.0.0.1","-addext","basicConstraints=critical,CA:TRUE","-keyout",join(dir,"key.pem"),"-out",join(dir,"cert.pem")],{stdio:"ignore"});
  const ca=readFileSync(join(dir,"cert.pem"));
  let received=0,redirected=0;
  server=createServer({key:readFileSync(join(dir,"key.pem")),cert:ca,minVersion:"TLSv1.2"},(req,res)=>{
   if(req.url==="/redirect"){res.writeHead(302,{Location:"/hook"});res.end();return;}
   if(req.url!=="/hook"){redirected++;res.writeHead(404);res.end();return;}
   let body="";req.on("data",c=>{body+=c;});req.on("end",()=>{
    try{verifyAlert(body,req.headers,key);received++;res.writeHead(204);}
    catch{res.writeHead(401);}res.end();
   });
  });
  server.listen(0,"127.0.0.1");await once(server,"listening");
  const base="https://127.0.0.1:"+server.address().port;
  const event=observeAlerts(initialAlertState(),null).pending[0];
  await deliverAlert(event,{url:new URL(base+"/hook"),key,ca});
  assert.equal(received,1);
  await assert.rejects(()=>deliverAlert(event,{url:new URL(base+"/hook"),key}));
  await assert.rejects(()=>deliverAlert(event,{url:new URL(base+"/redirect"),key,ca}),/not acknowledged/);
  assert.equal(received,1);assert.equal(redirected,0);
 }finally{
  if(server){server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
  rmSync(dir,{recursive:true,force:true});
 }
});

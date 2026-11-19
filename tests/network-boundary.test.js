import test from "node:test";
import assert from "node:assert/strict";
import express from "express";
import {proxyTrust,corsOrigins,createBoundedServer} from "../server/network-boundary.js";

test("proxy trust is exact, bounded, canonical and limited to the immediate peer",()=>{
 assert.equal(proxyTrust({})("127.0.0.1",0),false);
 const trust=proxyTrust({TRUSTED_PROXY_IPS:"10.0.0.3,2001:db8::1"});
 assert.equal(trust("10.0.0.3",0),true);
 assert.equal(trust("::ffff:a00:3",0),true);
 assert.equal(trust("::ffff:10.0.0.3",0),true);
 assert.equal(trust("2001:0db8:0:0:0:0:0:1",0),true);
 assert.equal(trust("10.0.0.4",0),false);
 assert.equal(trust("10.0.0.3",1),false);
 for(const bad of ["*","true","loopback","10.0.0.0/8","0.0.0.0","::","proxy.example.invalid","127.0.0.1,"]){
  assert.throws(()=>proxyTrust({TRUSTED_PROXY_IPS:bad}));
 }
});
test("CORS accepts exact origins, not patterns or production cleartext",()=>{
 assert.deepEqual(corsOrigins({NODE_ENV:"production",CORS_ORIGIN:"https://one.example.invalid, https://two.example.invalid"}),["https://one.example.invalid","https://two.example.invalid"]);
 assert.deepEqual(corsOrigins({}),[]);
 assert.deepEqual(corsOrigins({NODE_ENV:"development",CORS_ORIGIN:"http://localhost:8080"}),["http://localhost:8080"]);
 for(const value of ["*","null","https://one.example.invalid/path","https://one.example.invalid/","https://u:p@one.example.invalid","http://one.example.invalid","https://one.example.invalid?x=1"]){
  assert.throws(()=>corsOrigins({NODE_ENV:"production",CORS_ORIGIN:value}));
 }
});
test("real Express requests cannot spoof the client IP across the trusted boundary",async()=>{
 const app=express();
 app.set("trust proxy",proxyTrust({}));
 app.get("/ip",(req,res)=>res.json({ip:req.ip}));
 const server=createBoundedServer(app);
 assert.equal(server.requestTimeout,15000);assert.equal(server.headersTimeout,10000);
 assert.equal(server.keepAliveTimeout,5000);assert.equal(server.maxConnections,256);
 assert.equal(server.maxRequestsPerSocket,100);
 await new Promise(resolve=>server.listen(0,"127.0.0.1",resolve));
 const url="http://127.0.0.1:"+server.address().port+"/ip";
 try{
  let response=await fetch(url,{headers:{"X-Forwarded-For":"203.0.113.1, 198.51.100.2"}});
  assert.equal((await response.json()).ip,"127.0.0.1");
  app.set("trust proxy",proxyTrust({TRUSTED_PROXY_IPS:"127.0.0.1"}));
  response=await fetch(url,{headers:{"X-Forwarded-For":"203.0.113.1, 198.51.100.2"}});
  assert.equal((await response.json()).ip,"198.51.100.2");
 }finally{await new Promise(resolve=>server.close(resolve));}
});

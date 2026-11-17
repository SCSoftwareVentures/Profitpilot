import test from "node:test";
import assert from "node:assert/strict";
import express from "express";
import {createServer} from "node:http";
import {accountRateLimit} from "../server/request-guard.js";
test("authenticated quota applies independently per stable identity, not token ID",async()=>{
 const app=express();
 // Synthetic identity middleware only; the real API verifies signed access tokens.
 app.use((req,res,next)=>{if(req.headers["x-synthetic-subject"])req.identity={subject:req.headers["x-synthetic-subject"]};next();});
 app.use(accountRateLimit({limit:2,windowMs:60_000}));
 app.get("/",(req,res)=>res.json({ok:true}));
 const server=createServer(app);
 await new Promise(resolve=>server.listen(0,"127.0.0.1",resolve));
 try{
  const url="http://127.0.0.1:"+server.address().port;
  const get=(subject,token)=>fetch(url,{headers:subject?{"x-synthetic-subject":subject,"x-synthetic-token":token||"first"}:{}});
  assert.equal((await get()).status,401);
  assert.equal((await get("synthetic-a","token-1")).status,200);
  assert.equal((await get("synthetic-a","token-2")).status,200);
  const denied=await get("synthetic-a","token-3");assert.equal(denied.status,429);
  assert.equal((await denied.json()).error,"Account request limit exceeded");
  assert.equal((await get("synthetic-b")).status,200);
 }finally{await new Promise(resolve=>server.close(resolve));}
});

import test from "node:test";
import assert from "node:assert/strict";
import {verifyAndEraseSupabaseIdentity as erase} from "../scripts/supabase-provider-erasure.js";
const issuer="https://abcdefghijklmnopqrst.supabase.co/auth/v1";
const subject="aaaaaaaa-1111-4111-8111-111111111111",grantId="bbbbbbbb-1111-4111-8111-111111111111";
const defaults={target:{issuer,subject,grantId},issuer,serviceRoleKey:"x".repeat(40),enabled:true};
const absent=()=>new Response(JSON.stringify({code:"user_not_found"}),{status:404});
const present=()=>new Response(JSON.stringify({id:subject}),{status:200});
test("provider adapter requires exact approved project, identity and explicit enablement",async()=>{
 for(const override of [{enabled:false},{issuer:"https://evil.example/auth/v1"},{target:{...defaults.target,issuer:"https://other.example/auth/v1"}},{target:{...defaults.target,subject:"../someone"}},{serviceRoleKey:"short"}]){
  await assert.rejects(()=>erase({...defaults,...override,fetchImpl:()=>{throw Error("unexpected outbound request");}}),/authorization required/);
 }
});
test("provider adapter verifies identity before hard delete and verified absence afterward",async()=>{
 const calls=[];
 const responses=[present(),new Response("{}",{status:200}),absent()];
 const result=await erase({...defaults,fetchImpl:async(url,opts)=>{calls.push({url,method:opts.method,redirect:opts.redirect,body:opts.body});return responses.shift();}});
 assert.deepEqual(result,{verifiedAbsent:true,alreadyAbsent:false});
 assert.deepEqual(calls.map(x=>x.method),["GET","DELETE","GET"]);
 assert.ok(calls.every(x=>x.url===issuer+"/admin/users/"+subject&&x.redirect==="error"));
 assert.deepEqual(JSON.parse(calls[1].body),{should_soft_delete:false});
});
test("provider adapter never deletes a mismatched or unverifiable identity",async()=>{
 for(const response of [new Response('{"id":"wrong"}',{status:200}),new Response("not found",{status:404}),new Response('{"code":"permission_denied"}',{status:403})]){
  let n=0;
  await assert.rejects(()=>erase({...defaults,fetchImpl:async()=>{n++;return response;}}),/verifiable/);
  assert.equal(n,1);
 }
});
test("provider adapter does not claim erasure on a successful DELETE without absence verification",async()=>{
 const responses=[present(),new Response("{}",{status:200}),present()];
 await assert.rejects(()=>erase({...defaults,fetchImpl:async()=>responses.shift()}),/absence not confirmed/);
 let n=0;
 assert.deepEqual(await erase({...defaults,fetchImpl:async()=>{n++;return absent();}}),{verifiedAbsent:true,alreadyAbsent:true});
 assert.equal(n,1);
});

import test from "node:test";
import assert from "node:assert/strict";
import {generateKeyPairSync,randomUUID} from "node:crypto";
import express from "express";
import {jobReferenceSigner,jobReferenceVerifier,issueJobReference,verifyJobReference,projectJobReference} from "../server/core-job-reference.js";
import {createCompletionRouter} from "../server/securepay-completion.js";
const keys=generateKeyPairSync("ed25519"),tenantId=randomUUID(),jobId=randomUUID();
const job={jobId,contractId:randomUUID(),siteId:randomUUID(),baselineId:randomUUID(),serviceDate:"2026-11-19",baselinePrice:"125.00",taxBasis:"gst_exclusive",currency:"AUD",status:"planned",readinessStatus:"ready",email:"not included"};
const issued=()=>issueJobReference({tenantId,jobId,job,signingKey:keys.privateKey});
const check=(reference,extra={})=>verifyJobReference({reference,tenantId,jobId,publicKey:keys.publicKey,...extra});
test("dedicated Ed25519 keys and synthetic opt-in only",()=>{
 const env={NODE_ENV:"test",CORE_JOB_REFERENCE_ENABLED:"true"};
 assert.equal(jobReferenceSigner({NODE_ENV:"production",CORE_JOB_REFERENCE_ENABLED:"true"}),null);
 assert.equal(jobReferenceVerifier({NODE_ENV:"test"}),null);
 assert.throws(()=>jobReferenceVerifier({...env,CORE_JOB_REFERENCE_SIGNING_KEY:"fixture"}));
 const signer=jobReferenceSigner({...env,CORE_JOB_REFERENCE_SIGNING_KEY:keys.privateKey.export({type:"pkcs8",format:"der"}).toString("base64url")});
 const verifier=jobReferenceVerifier({...env,CORE_JOB_REFERENCE_PUBLIC_KEY:keys.publicKey.export({type:"spki",format:"der"}).toString("base64url")});
 assert.equal(check(issueJobReference({tenantId,jobId,job,signingKey:signer}).reference,{publicKey:verifier}).jobId,jobId);
});
test("exact scope, signature, expiry, bounded content and minimal fields",()=>{
 const x=issued(),p=check(x.reference);
 assert.equal(p.baselinePrice,"125.00");assert.equal(p.email,undefined);
 assert.throws(()=>check(x.reference,{tenantId:randomUUID()}));
 assert.throws(()=>check(x.reference,{jobId:randomUUID()}));
 assert.throws(()=>check(x.reference,{publicKey:generateKeyPairSync("ed25519").publicKey}));
 assert.throws(()=>check(x.reference,{now:p.expiresAt}));
 assert.throws(()=>check(x.reference,{now:p.issuedAt-6}));
 assert.throws(()=>check(x.reference+"="));
 const [body,sig]=x.reference.split("."),edited=JSON.parse(Buffer.from(body,"base64url"));edited[8]="1.00";
 assert.throws(()=>check(Buffer.from(JSON.stringify(edited)).toString("base64url")+"."+sig));
 assert.throws(()=>issueJobReference({tenantId,jobId,job:{...job,baselinePrice:125},signingKey:keys.privateKey}));
});
test("read-only projection validates the actual quote and never equates baseline with a payment amount",()=>{
 const p=check(issued().reference),quote={quoteId:randomUUID(),quoteDigest:"a".repeat(64),revision:1,totalCents:"5000",description:"not forwarded"};
 const v=projectJobReference(p,{jobId,quote,plan:null});
 assert.equal(v.coreBaseline.notAJobQuote,true);assert.equal(v.quote.totalCents,"5000");assert.equal(v.quote.description,undefined);assert.equal(v.paymentAuthorized,false);assert.equal(v.moneyMoved,false);
 assert.throws(()=>projectJobReference(p,{jobId:randomUUID(),quote,plan:null}));
 assert.throws(()=>projectJobReference(p,{jobId,quote:{...quote,totalCents:"9007199254740992"},plan:null}));
});
test("separate completion endpoint requires its own authentication and signed core context; no mutations",async()=>{
 let reads=0;const owner={quoteStatus:async scope=>{reads++;assert.deepEqual(scope,{tenantId,jobId});return {ok:true,view:{jobId,quote:null,plan:null}};}};
 const app=express();app.use("/completion",createCompletionRouter({enabled:true,tenantId,subject:"fixture-owner",verifyToken:async t=>({subject:t}),owner,coreReferenceKey:keys.publicKey}));
 const server=app.listen(0,"127.0.0.1");await new Promise(r=>server.once("listening",r));
 const base="http://127.0.0.1:"+server.address().port+"/completion/"+jobId+"/core-link-preview";
 const post=(body,token="fixture-owner")=>fetch(base,{method:"POST",headers:{"content-type":"application/json",...(token?{authorization:"Bearer "+token}:{})},body:JSON.stringify(body)});
 try{
  const {reference}=issued();assert.equal((await post({reference},null)).status,401);
  assert.equal((await post({reference},"staff-token")).status,403);
  assert.equal((await post({reference:"bad"})).status,403);
  assert.equal((await post({reference,amount:1})).status,400);assert.equal(reads,0);
  const r=await post({reference});assert.equal(r.status,200);assert.match(r.headers.get("cache-control"),/no-store/);
  const x=await r.json();assert.equal(x.jobReferenceVerified,true);assert.equal(x.paymentAuthorized,false);assert.equal(reads,1);
 }finally{await new Promise(r=>server.close(r));}
});

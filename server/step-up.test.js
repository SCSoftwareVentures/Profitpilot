import test from "node:test";
import assert from "node:assert/strict";
import {requireStepUp} from "./auth.js";

function evaluate(identity, config={}){
 const previousAcr=process.env.AUTH_STEP_UP_ACR;
 const previousAge=process.env.AUTH_STEP_UP_MAX_AGE_SECONDS;
 try{
  process.env.AUTH_STEP_UP_ACR=config.requiredAcr??"urn:profitpilot:mfa";
  process.env.AUTH_STEP_UP_MAX_AGE_SECONDS=config.maxAge??"300";
  const result={status:null,body:null,allowed:false};
  const req={identity};
  const res={status(code){result.status=code;return this;},json(body){result.body=body;return this;}};
  requireStepUp()(req,res,()=>{result.allowed=true;});
  return result;
 }finally{
  if(previousAcr===undefined)delete process.env.AUTH_STEP_UP_ACR;else process.env.AUTH_STEP_UP_ACR=previousAcr;
  if(previousAge===undefined)delete process.env.AUTH_STEP_UP_MAX_AGE_SECONDS;else process.env.AUTH_STEP_UP_MAX_AGE_SECONDS=previousAge;
 }
}
const now=()=>Math.floor(Date.now()/1000);
test("step-up permits recent matching assurance",()=>{
 assert.equal(evaluate({authTime:now()-30,acr:"urn:profitpilot:mfa"}).allowed,true);
});
test("step-up denies absent or incorrect assurance",()=>{
 for(const acr of [null,undefined,"urn:other"]){
  assert.equal(evaluate({authTime:now(),acr}).status,403);
 }
});
test("step-up denies missing, stale and future authentication times",()=>{
 for(const authTime of [null,undefined,"recent",now()-301,now()+1,now()+6]){
  assert.equal(evaluate({authTime,acr:"urn:profitpilot:mfa"}).status,403);
 }
});
test("step-up denies unsafe freshness configuration",()=>{
 for(const maxAge of ["","29","901","NaN","1.5"]){
  assert.equal(evaluate({authTime:now(),acr:"urn:profitpilot:mfa"},{maxAge}).status,403);
 }
});

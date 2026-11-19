// Run on Node >=22.18: node --test --experimental-strip-types securepay/domain/state-machine.test.mjs
import test from "node:test";
import assert from "node:assert/strict";
import { INITIAL_CASE, transition } from "./state-machine.ts";
const step=(c,e)=>transition(c,e);
const work={type:"SUBMIT_WORK",actor:"owner",photos:["photo-1"]};
const submitted=()=>step(INITIAL_CASE,work);
const dispute=(severity="minor")=>step(submitted(),{type:"OPEN_DISPUTE",actor:"customer",reason:"Defect",severity});
const throws=(c,e)=>assert.throws(()=>step(c,e),/transition denied/);
test("completion requires photos; comments optional",()=>{
  throws(INITIAL_CASE,{...work,photos:[]});
  assert.equal(submitted().status,"submitted");
  assert.equal(submitted().comments,undefined);
});
test("minor moderate and serious disputes are recorded",()=>{
  for(const severity of ["minor","moderate","serious"])
    assert.equal(dispute(severity).severity,severity);
});
test("cannot approve while dispute active",()=>{
  throws(dispute(),{type:"APPROVE",actor:"customer"});
  throws(dispute(),{type:"PIN_VERIFIED",actor:"customer",verificationToken:"x"});
});
test("agreed rectification permits resubmission then PIN-gated release",()=>{
  let c=dispute();
  c=step(c,{type:"PROPOSE_REPAIR",actor:"owner",deadline:"2026-12-01"});
  c=step(c,{type:"ACCEPT_REPAIR",actor:"customer"});
  throws(c,{type:"APPROVE",actor:"customer"});
  c=step(c,{type:"SUBMIT_REPAIR",actor:"owner",photos:["fixed"]});
  c=step(c,{type:"APPROVE",actor:"customer"});
  throws(c,{type:"PROVIDER_RELEASE_CONFIRMED",actor:"payment_service",transactionId:"p1"});
  c=step(c,{type:"PIN_VERIFIED",actor:"customer",verificationToken:"verified"});
  c=step(c,{type:"PROVIDER_RELEASE_CONFIRMED",actor:"payment_service",transactionId:"p1"});
  assert.equal(c.status,"released");
  throws(c,{type:"PROVIDER_RELEASE_CONFIRMED",actor:"payment_service",transactionId:"p1"});
});
test("independent reviewer can set rectification deadline with reasons",()=>{
  let c=step(dispute("serious"),{type:"REFER_REVIEW",actor:"owner"});
  throws(c,{type:"SET_REPAIR_DEADLINE",actor:"reviewer",deadline:"2026-12-01",reasons:""});
  c=step(c,{type:"SET_REPAIR_DEADLINE",actor:"reviewer",deadline:"2026-12-01",reasons:"Independent assessment"});
  assert.equal(c.status,"rectification");
});
test("reasoned investigation outcome does not automatically pay",()=>{
  let c=step(dispute("serious"),{type:"REFER_REVIEW",actor:"customer"});
  throws(c,{type:"CLOSE_DISPUTE",actor:"reviewer",reasons:"",authorizedOutcomeRef:"x"});
  c=step(c,{type:"CLOSE_DISPUTE",actor:"reviewer",reasons:"Evidence reviewed",authorizedOutcomeRef:"outcome-1"});
  assert.equal(c.status,"closed");
  throws(c,{type:"PROVIDER_RELEASE_CONFIRMED",actor:"payment_service",transactionId:"p1"});
});
test("ordinary release needs PIN and provider confirmation",()=>{
  let c=step(submitted(),{type:"APPROVE",actor:"customer"});
  throws(c,{type:"PIN_VERIFIED",actor:"customer",verificationToken:""});
  c=step(c,{type:"PIN_VERIFIED",actor:"customer",verificationToken:"verified"});
  assert.equal(c.status,"release_pending");
  throws(c,{type:"PROVIDER_RELEASE_CONFIRMED",actor:"payment_service",transactionId:""});
});

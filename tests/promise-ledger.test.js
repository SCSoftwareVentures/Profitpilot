import test from "node:test";
import assert from "node:assert/strict";
import {createPromiseRecord,transitionPromise} from "../src/promise-ledger.js";

const base={
  id:"promise-1",tenantId:"tenant-1",promiseType:"customer_promise",counterparty:"Example Customer",
  title:"Complete nightly office cleaning",description:"Complete agreed cleaning at the listed site.",
  scope:["Vacuum offices","Clean common areas"],exclusions:["External windows"],
  dueAt:"2026-12-01T21:00:00+11:00",dueTimezone:"Australia/Melbourne",ownerId:"user-1",
  responsibleParty:"business",originRef:"contract:C-101",createdBy:"user-1",
  createdAt:"2026-11-17T10:00:00+11:00",eventId:"event-proposed-1"
};
const event=(id,type,extra={})=>({id,type,actorId:"user-1",actorType:"business_user",occurredAt:"2026-11-17T10:05:00+11:00",...extra});

test("customer promise starts proposed with immutable version and event history",()=>{
  const record=createPromiseRecord(base);
  assert.equal(record.status,"proposed");
  assert.equal(record.currentVersion,1);
  assert.equal(record.events.length,1);
  assert.equal(record.events[0].type,"proposed");
  assert.equal(record.versions[0].scope[0],"Vacuum offices");
});

test("communication records a sent message but does not infer receipt or acceptance",()=>{
  const record=createPromiseRecord(base);
  const sent=transitionPromise(record,event("event-sent","communicated",{messageRef:"message:outbound-1"}));
  assert.equal(sent.status,"communicated");
  assert.equal(sent.events.at(-1).messageRef,"message:outbound-1");
  assert.match(sent.communicationMeaning,/receipt and acceptance are separate/);
  assert.equal(record.status,"proposed");
});

test("customer promise acceptance requires customer actor type and acknowledgement evidence",()=>{
  const sent=transitionPromise(createPromiseRecord(base),event("event-sent","communicated",{messageRef:"message:1"}));
  assert.throws(()=>transitionPromise(sent,event("event-accept-bad","accepted",{evidenceRef:"ack:1"})),/appropriate accepting party/);
  const accepted=transitionPromise(sent,event("event-accept","accepted",{actorType:"customer_contact",evidenceRef:"ack:customer-1"}));
  assert.equal(accepted.status,"accepted");
  assert.equal(accepted.events.at(-1).evidenceRef,"ack:customer-1");
});

test("internal tasks can be accepted by a business user but cannot be customer-communicated",()=>{
  const task=createPromiseRecord({...base,promiseType:"internal_task",counterparty:undefined,eventId:"task-proposed"});
  assert.throws(()=>transitionPromise(task,event("task-sent","communicated",{messageRef:"message:task"})),/Communication requires/);
  const accepted=transitionPromise(task,event("task-accepted","accepted",{evidenceRef:"assignment:accepted"}));
  assert.equal(accepted.status,"accepted");
});

test("changes append a new version and require re-communication and re-acceptance",()=>{
  const sent=transitionPromise(createPromiseRecord(base),event("event-sent","communicated",{messageRef:"message:1"}));
  const accepted=transitionPromise(sent,event("event-accept","accepted",{actorType:"customer_contact",evidenceRef:"ack:1"}));
  const changed=transitionPromise(accepted,event("event-change","changed",{reason:"Customer approved a revised service window",evidenceRef:"change:approval-1",revision:{dueAt:"2026-12-02T21:00:00+11:00",scope:["Vacuum offices","Clean common areas","Sanitise reception"]}}));
  assert.equal(changed.status,"changed");
  assert.equal(changed.currentVersion,2);
  assert.equal(changed.versions.length,2);
  assert.deepEqual(changed.versions[0].scope,["Vacuum offices","Clean common areas"]);
  assert.deepEqual(changed.versions[1].scope,["Vacuum offices","Clean common areas","Sanitise reception"]);
  const resent=transitionPromise(changed,event("event-resent","communicated",{messageRef:"message:2",occurredAt:"2026-11-17T10:10:00+11:00"}));
  const reaccepted=transitionPromise(resent,event("event-reaccept","accepted",{actorType:"customer_contact",evidenceRef:"ack:2",occurredAt:"2026-11-17T10:11:00+11:00"}));
  assert.equal(reaccepted.status,"accepted");
  assert.equal(reaccepted.currentVersion,2);
});

test("fulfilment requires evidence and terminal records cannot be rewritten",()=>{
  const sent=transitionPromise(createPromiseRecord(base),event("event-sent","communicated",{messageRef:"message:1"}));
  const accepted=transitionPromise(sent,event("event-accept","accepted",{actorType:"customer_contact",evidenceRef:"ack:1"}));
  assert.throws(()=>transitionPromise(accepted,event("event-done-bad","fulfilled")),/completion evidence/);
  const fulfilled=transitionPromise(accepted,event("event-done","fulfilled",{evidenceRef:"completion:photo-set-1"}));
  assert.equal(fulfilled.status,"fulfilled");
  assert.throws(()=>transitionPromise(fulfilled,event("event-change-after","changed",{reason:"Late edit",evidenceRef:"change:1",revision:{title:"Changed"}})),/status transition is not allowed/);
});

test("missed state cannot be recorded before due time and may later be fulfilled",()=>{
  const sent=transitionPromise(createPromiseRecord(base),event("event-sent","communicated",{messageRef:"message:1"}));
  const accepted=transitionPromise(sent,event("event-accept","accepted",{actorType:"customer_contact",evidenceRef:"ack:1"}));
  assert.throws(()=>transitionPromise(accepted,event("event-missed-early","missed",{reason:"Not done",occurredAt:"2026-11-30T20:00:00+11:00"})),/no earlier than its due time/);
  const missed=transitionPromise(accepted,event("event-missed","missed",{reason:"Crew could not access site",occurredAt:"2026-12-01T22:00:00+11:00"}));
  assert.equal(missed.status,"missed");
  const done=transitionPromise(missed,event("event-late-done","fulfilled",{evidenceRef:"completion:late-1",occurredAt:"2026-12-02T08:00:00+11:00"}));
  assert.equal(done.status,"fulfilled");
});

test("dispute and cancellation require reasons and cancellation is terminal",()=>{
  const sent=transitionPromise(createPromiseRecord(base),event("event-sent","communicated",{messageRef:"message:1"}));
  assert.throws(()=>transitionPromise(sent,event("event-dispute-bad","disputed")),/dispute requires/);
  const disputed=transitionPromise(sent,event("event-dispute","disputed",{actorType:"customer_contact",reason:"Customer disputes the revised scope"}));
  const cancelled=transitionPromise(disputed,event("event-cancel","cancelled",{reason:"Both parties agreed to cancel",occurredAt:"2026-11-17T10:06:00+11:00"}));
  assert.equal(cancelled.status,"cancelled");
  assert.throws(()=>transitionPromise(cancelled,event("event-after","accepted",{actorType:"customer_contact",evidenceRef:"ack:2",occurredAt:"2026-11-17T10:07:00+11:00"})),/status transition is not allowed/);
});

test("creation rejects missing provenance, scope, explicit timezone and invalid party",()=>{
  assert.throws(()=>createPromiseRecord({...base,originRef:""}),/originRef is required/);
  assert.throws(()=>createPromiseRecord({...base,scope:[]}),/scope must be an array/);
  assert.throws(()=>createPromiseRecord({...base,dueTimezone:"Mars/Olympus"}),/valid IANA timezone/);
  assert.throws(()=>createPromiseRecord({...base,dueAt:"2026-12-01T21:00:00"}),/explicit UTC offset/);
  assert.throws(()=>createPromiseRecord({...base,responsibleParty:"unknown"}),/responsibleParty is invalid/);
});

test("events require unique IDs and chronological timestamps",()=>{
  const record=createPromiseRecord(base);
  assert.throws(()=>transitionPromise(record,event("event-proposed-1","cancelled",{reason:"duplicate",occurredAt:"2026-11-17T10:01:00+11:00"})),/event ID must be unique/);
  const sent=transitionPromise(record,event("event-sent","communicated",{messageRef:"message:1"}));
  assert.throws(()=>transitionPromise(sent,event("event-out-of-order","accepted",{actorType:"customer_contact",evidenceRef:"ack:1",occurredAt:"2026-11-17T10:01:00+11:00"})),/chronological order/);
});

test("event revisions cannot rewrite tenant, status or record identity",()=>{
  const sent=transitionPromise(createPromiseRecord(base),event("event-sent","communicated",{messageRef:"message:1"}));
  const accepted=transitionPromise(sent,event("event-accept","accepted",{actorType:"customer_contact",evidenceRef:"ack:1"}));
  assert.throws(()=>transitionPromise(accepted,event("event-change","changed",{reason:"Scope update",evidenceRef:"change:1",revision:{tenantId:"other-tenant"}})),/unsupported fields/);
});

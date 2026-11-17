import test from "node:test";
import assert from "node:assert/strict";
import {appendPromiseEvent} from "../src/promise-ledger.js";

const proposed={promiseId:"promise-1",eventId:"event-1",type:"proposed",actorId:"user-1",occurredAt:"2026-11-17T09:00:00+11:00",sourceRef:"quote-101",reason:"Initial customer commitment drafted",evidenceRefs:["quote-101"]};
const event=(overrides={})=>({...proposed,...overrides});

test("promise ledger requires a proposed first event and explicit source traceability",()=>{
  assert.throws(()=>appendPromiseEvent({event:event({type:"accepted"})}),/begin with a proposed/);
  assert.throws(()=>appendPromiseEvent({event:event({sourceRef:""})}),/safe non-empty IDs/);
  const result=appendPromiseEvent({event:proposed});
  assert.equal(result.state,"proposed");
  assert.equal(result.terminal,false);
});

test("promise transitions require communication before acceptance and evidence for material states",()=>{
  const first=appendPromiseEvent({event:proposed});
  assert.throws(()=>appendPromiseEvent({events:first.events,event:event({eventId:"event-2",type:"accepted",occurredAt:"2026-11-17T09:05:00+11:00"})}),/Invalid promise state transition/);
  const communicated=appendPromiseEvent({events:first.events,event:event({eventId:"event-2",type:"communicated",occurredAt:"2026-11-17T09:05:00+11:00",evidenceRefs:["message-receipt-1"]})});
  assert.throws(()=>appendPromiseEvent({events:communicated.events,event:event({eventId:"event-3",type:"accepted",occurredAt:"2026-11-17T09:10:00+11:00",evidenceRefs:[]})}),/requires at least one evidence/);
});

test("accepted promises can be changed and then fulfilled with evidence",()=>{
  const first=appendPromiseEvent({event:proposed});
  const sent=appendPromiseEvent({events:first.events,event:event({eventId:"event-2",type:"communicated",occurredAt:"2026-11-17T09:05:00+11:00",evidenceRefs:["sent-message-1"]})});
  const accepted=appendPromiseEvent({events:sent.events,event:event({eventId:"event-3",type:"accepted",occurredAt:"2026-11-17T09:10:00+11:00",evidenceRefs:["customer-acceptance-1"]})});
  const changed=appendPromiseEvent({events:accepted.events,event:event({eventId:"event-4",type:"changed",occurredAt:"2026-11-17T09:15:00+11:00",evidenceRefs:["change-request-1"],reason:"Customer changed service date"})});
  const fulfilled=appendPromiseEvent({events:changed.events,event:event({eventId:"event-5",type:"fulfilled",occurredAt:"2026-11-18T09:00:00+11:00",evidenceRefs:["completion-record-1"]})});
  assert.equal(fulfilled.state,"fulfilled");
  assert.equal(fulfilled.terminal,true);
  assert.equal(fulfilled.events.length,5);
});

test("fulfilled and cancelled promises are terminal",()=>{
  const first=appendPromiseEvent({event:proposed});
  const sent=appendPromiseEvent({events:first.events,event:event({eventId:"event-2",type:"communicated",occurredAt:"2026-11-17T09:05:00+11:00",evidenceRefs:["sent-1"]})});
  const accepted=appendPromiseEvent({events:sent.events,event:event({eventId:"event-3",type:"accepted",occurredAt:"2026-11-17T09:10:00+11:00",evidenceRefs:["accept-1"]})});
  const done=appendPromiseEvent({events:accepted.events,event:event({eventId:"event-4",type:"fulfilled",occurredAt:"2026-11-17T10:00:00+11:00",evidenceRefs:["proof-1"]})});
  assert.throws(()=>appendPromiseEvent({events:done.events,event:event({eventId:"event-5",type:"disputed",occurredAt:"2026-11-17T11:00:00+11:00",evidenceRefs:["dispute-1"]})}),/Invalid promise state transition/);
});

test("event IDs are unique and event chronology cannot move backwards",()=>{
  const first=appendPromiseEvent({event:proposed});
  assert.throws(()=>appendPromiseEvent({events:first.events,event:proposed}),/Duplicate promise event ID/);
  assert.throws(()=>appendPromiseEvent({events:first.events,event:event({eventId:"event-2",type:"communicated",occurredAt:"2026-11-17T08:59:00+11:00",evidenceRefs:["sent-1"]})}),/chronological order/);
});

test("timestamps must include an explicit timezone",()=>{
  assert.throws(()=>appendPromiseEvent({event:event({occurredAt:"2026-11-17T09:00:00"})}),/explicit timezone/);
  assert.throws(()=>appendPromiseEvent({event:event({occurredAt:"not-a-date"})}),/explicit timezone/);
});

test("appending an event does not mutate the previous event array",()=>{
  const original=[{...proposed}];
  const result=appendPromiseEvent({events:original,event:event({eventId:"event-2",type:"communicated",occurredAt:"2026-11-17T09:05:00+11:00",evidenceRefs:["sent-1"]})});
  assert.equal(original.length,1);
  assert.equal(result.events.length,2);
  assert.notEqual(result.events,original);
});

import test from "node:test";
import assert from "node:assert/strict";
import {appendValueEvent,summariseValueEvents} from "../src/verified-value-ledger.js";

const base={valueId:"value-001",eventId:"event-001",actorId:"user-001",scopeRef:"contract-site-C101",type:"quoted",amount:"1000.00",currency:"AUD",taxBasis:"gst_exclusive",periodStart:"2026-11-01",periodEnd:"2026-11-30",sourceRef:"quote-001",occurredAt:"2026-11-17T09:00:00+11:00",reason:"Initial quoted service value",evidenceRefs:["quote-001"]};
const event=(overrides={})=>({...base,...overrides});

test("value events require explicit amount, dimensions, actor, reason and evidence",()=>{
  assert.equal(appendValueEvent({event:base}).events.length,1);
  for(const overrides of [{amount:100.5},{amount:"-1.00"},{currency:""},{taxBasis:""},{evidenceRefs:[]},{occurredAt:"2026-11-17T09:00:00"},{occurredAt:"2026-02-31T09:00:00+11:00"}])
    assert.throws(()=>appendValueEvent({event:event(overrides)}));
});

test("event IDs are unique and append chronology is enforced",()=>{
  const first=appendValueEvent({event:base});
  assert.throws(()=>appendValueEvent({events:first.events,event:base}),/Duplicate value event ID/);
  assert.throws(()=>appendValueEvent({events:first.events,event:event({eventId:"event-002",type:"invoiced",occurredAt:"2026-11-17T08:59:00+11:00"})}),/chronological order/);
});

test("value summaries preserve each commercial state and do not net credits or refunds",()=>{
  let ledger=appendValueEvent({event:base});
  for(const [i,type,amount] of [[2,"contracted","1000.00"],[3,"delivered","900.00"],[4,"customer_accepted","850.00"],[5,"invoiced","1000.00"],[6,"credited","100.00"],[7,"settled","900.00"]]){
    ledger=appendValueEvent({events:ledger.events,event:event({eventId:"event-00"+i,type,amount,occurredAt:"2026-11-17T09:0"+i+":00+11:00",sourceRef:"source-"+i,reason:"Recorded "+type,evidenceRefs:["evidence-"+i]})});
  }
  const summary=summariseValueEvents(ledger.events)[0];
  assert.equal(summary.recordedAmounts.quoted,"1000.00");
  assert.equal(summary.recordedAmounts.delivered,"900.00");
  assert.equal(summary.recordedAmounts.customer_accepted,"850.00");
  assert.equal(summary.recordedAmounts.invoiced,"1000.00");
  assert.equal(summary.recordedAmounts.credited,"100.00");
  assert.equal(summary.recordedAmounts.settled,"900.00");
  assert.equal(summary.recordedAmounts.refunded,null);
  assert.equal(summary.eventTypeCounts.refunded,0);
  assert.equal(summary.creditedAndRefunded,"100.00");
  assert.equal(summary.nettedTotal,null);
  assert.equal(summary.verificationStatus,"not_independently_verified");
});

test("unlike currencies, tax bases and periods are kept in separate summary groups",()=>{
  const a=appendValueEvent({event:base});
  const b=appendValueEvent({event:event({eventId:"event-002",scopeRef:"contract-site-C102",currency:"NZD",sourceRef:"quote-002",occurredAt:"2026-11-17T09:01:00+11:00",evidenceRefs:["quote-002"]})});
  const summaries=summariseValueEvents([...a.events,...b.events]);
  assert.equal(summaries.length,2);
  assert.deepEqual(summaries.map(x=>x.currency).sort(),["AUD","NZD"]);
});

test("summary rejects malformed history instead of producing totals",()=>{
  assert.throws(()=>summariseValueEvents([{valueId:"value-1",type:"quoted",amount:"1.00",currency:"AUD",taxBasis:"gst_exclusive",periodStart:"2026-11-01",periodEnd:"2026-11-30"}]));
});

test("a value record cannot change its scope, currency, tax basis or period",()=>{
  const first=appendValueEvent({event:base});
  assert.throws(()=>appendValueEvent({events:first.events,event:event({eventId:"event-002",currency:"NZD",occurredAt:"2026-11-17T09:01:00+11:00",sourceRef:"source-2",evidenceRefs:["evidence-2"]})}),/cannot change scope, currency, tax basis or reporting period/);
  assert.throws(()=>summariseValueEvents([...first.events,event({eventId:"event-002",currency:"NZD",occurredAt:"2026-11-17T09:01:00+11:00",sourceRef:"source-2",evidenceRefs:["evidence-2"]})]),/mixed reporting dimensions/);
});

import test from "node:test";
import assert from "node:assert/strict";
import {appendValueEvent,createValueLedger,summarizeValueLedger} from "../src/verified-value-ledger.js";

const base={currency:"AUD",taxBasis:"gst_exclusive",periodStart:"2026-11-01",periodEnd:"2026-11-30"};
const initial=()=>createValueLedger({id:"ledger-1",tenantId:"tenant-1",originRef:"contract:C-101",createdAt:"2026-11-17T09:00:00+11:00"});
const event=(id,type,extra={})=>({id,type,valueId:"value-1",amount:"100.00",...base,actorId:"user-1",occurredAt:"2026-11-17T09:05:00+11:00",evidenceRef:"synthetic:evidence-1",sourceRef:"synthetic:source-1",...extra});

test("value stages append without overwriting or collapsing earlier states",()=>{
  let ledger=initial();
  for(const [id,type] of [["e1","proposed"],["e2","quoted"],["e3","contractually_accepted"],["e4","delivered"],["e5","customer_accepted"],["e6","invoiced"]]){
    ledger=appendValueEvent(ledger,event(id,type,{invoiceRef:type==="invoiced"?"INV-1":undefined}));
  }
  const summary=summarizeValueLedger(ledger);
  assert.equal(summary.eventCount,6);
  for(const type of ["proposed","quoted","contractually_accepted","delivered","customer_accepted","invoiced"])assert.equal(summary.totalsByState[type],"100.00");
  assert.equal(summary.settlementStatus,"not_in_scope");
});

test("partial credits and refunds remain separate and cannot exceed invoiced amount",()=>{
  let ledger=appendValueEvent(initial(),event("invoice","invoiced",{invoiceRef:"INV-1",amount:"100.00"}));
  ledger=appendValueEvent(ledger,event("credit","credited",{invoiceRef:"INV-1",amount:"20.00",reason:"Partial scope credit"}));
  ledger=appendValueEvent(ledger,event("refund","refunded",{invoiceRef:"INV-1",amount:"10.00",reason:"Refund issued"}));
  const summary=summarizeValueLedger(ledger);
  assert.equal(summary.totalsByState.invoiced,"100.00");
  assert.equal(summary.totalsByState.credited,"20.00");
  assert.equal(summary.totalsByState.refunded,"10.00");
  assert.throws(()=>appendValueEvent(ledger,event("excess","refunded",{invoiceRef:"INV-1",amount:"71.00",reason:"Excess"})),/cannot exceed evidenced invoiced value/);
});

test("currency and tax-basis mismatches are rejected for one value lineage",()=>{
  let ledger=appendValueEvent(initial(),event("quote","quoted"));
  assert.throws(()=>appendValueEvent(ledger,event("invoice","invoiced",{currency:"USD",invoiceRef:"INV-1"})),/cannot silently mix currencies or tax bases/);
  assert.throws(()=>appendValueEvent(ledger,event("invoice","invoiced",{taxBasis:"gst_inclusive",invoiceRef:"INV-1"})),/cannot silently mix currencies or tax bases/);
});

test("invalid money, numeric JSON values and missing evidence are rejected",()=>{
  assert.throws(()=>appendValueEvent(initial(),event("bad","quoted",{amount:100})),/positive canonical decimal string/);
  assert.throws(()=>appendValueEvent(initial(),event("bad","quoted",{amount:"1.005"})),/positive canonical decimal string/);
  assert.throws(()=>appendValueEvent(initial(),event("bad","delivered",{evidenceRef:""})),/supporting evidence/);
});

test("invoice, credit and refund events require traceable invoice references and reasons",()=>{
  assert.throws(()=>appendValueEvent(initial(),event("invoice","invoiced")),/invoice reference/);
  let ledger=appendValueEvent(initial(),event("invoice","invoiced",{invoiceRef:"INV-1"}));
  assert.throws(()=>appendValueEvent(ledger,event("credit","credited",{invoiceRef:"INV-1",reason:""})),/reason and invoice reference/);
});

test("events are chronological, unique and append-only",()=>{
  let ledger=appendValueEvent(initial(),event("quote","quoted"));
  assert.throws(()=>appendValueEvent(ledger,event("quote","quoted")),/unique/);
  assert.throws(()=>appendValueEvent(ledger,event("earlier","delivered",{occurredAt:"2026-11-17T09:01:00+11:00"})),/chronological/);
  const later=appendValueEvent(ledger,event("accepted","contractually_accepted"));
  assert.equal(later.events[0].id,"quote");
  assert.equal(later.events[1].parentEventId,"quote");
  assert.equal(ledger.events.length,1);
});

test("settlement events are not accepted by the prototype",()=>{
  assert.throws(()=>appendValueEvent(initial(),event("settled","settled")),/supported value event type/);
});

test("summary warns that lifecycle stage totals are not additive realised value",()=>{
  const ledger=appendValueEvent(initial(),event("proposal","proposed"));
  assert.match(summarizeValueLedger(ledger).interpretation,/must not be added together as realised value/);
});

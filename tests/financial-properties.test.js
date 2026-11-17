import test from "node:test";
import assert from "node:assert/strict";
import {allocatePayroll,aggregateMetrics,money,validateInvoiceRows} from "../src/engine.js";

// Deterministic LCG: seed and generated case count are retained as test evidence.
const SEED=0x5eed1234;
const CASES=500;
function generator(seed){
  let state=seed>>>0;
  return ()=>{state=(Math.imul(state,1664525)+1013904223)>>>0;return state;};
}
function decimal(cents){
  const n=BigInt(cents);
  return String(n/100n)+"."+String(n%100n).padStart(2,"0");
}
function cents(value){
  const [whole,fraction]=value.split(".");
  return BigInt(whole)*100n+BigInt(fraction);
}

test("PROP-001/002/012 — seeded payroll bucket reconciliation and exact cents (seed 0x5eed1234, 500 cases)",()=>{
  const next=generator(SEED);
  for(let i=0;i<CASES;i++){
    const pool=BigInt(next()%100000000)+1n;
    let remaining=pool;
    const direct=BigInt(next().toString())%(remaining+1n);remaining-=direct;
    const approved=BigInt(next().toString())%(remaining+1n);remaining-=approved;
    const nonSite=BigInt(next().toString())%(remaining+1n);remaining-=nonSite;
    const excluded=BigInt(next().toString())%(remaining+1n);remaining-=excluded;
    const result=allocatePayroll({
      pool:decimal(pool),
      direct:direct?[{site:"site-A",amount:decimal(direct)}]:[],
      approved:approved?[{site:"site-B",amount:decimal(approved)}]:[],
      nonSite:decimal(nonSite),
      excluded:decimal(excluded)
    });
    assert.equal(result.reconciles,true,"generated allocation must reconcile at case "+i);
    const total=cents(result.direct)+cents(result.approvedAllocated)+cents(result.nonSite)+cents(result.excluded)+cents(result.unallocated);
    assert.equal(total,pool,"exact cents must equal source pool at case "+i);
  }
});

test("PROP-003/012 — aggregate totals are invariant to input row permutation",()=>{
  const next=generator(SEED);
  const rows=Array.from({length:100},(_,i)=>{
    const revenue=BigInt(next()%100000000)+1n;
    const cost=BigInt(next()%(Number(revenue)+1));
    return {currency:"AUD",taxBasis:"gst_exclusive",periodStart:"2026-11-01",periodEnd:"2026-11-30",revenue:decimal(revenue),cost:decimal(cost)};
  });
  const forward=aggregateMetrics(rows);
  const reverse=aggregateMetrics([...rows].reverse());
  assert.deepEqual(
    [forward.revenue,forward.cost,forward.contribution,forward.margin],
    [reverse.revenue,reverse.cost,reverse.contribution,reverse.margin]
  );
});

test("PROP-005/013 — unknown amounts remain invalid and negative credits retain their sign",()=>{
  assert.equal(money(null),null);
  assert.equal(money(0.1),null);
  assert.equal(money("-110.00"),"-110.00");
  const credit=aggregateMetrics([{currency:"AUD",taxBasis:"gst_exclusive",periodStart:"2026-11-01",periodEnd:"2026-11-30",revenue:"100.00",cost:"110.00"}]);
  assert.equal(credit.contribution,"-10.00");
});

test("PROP-008/009 — unlike currency and tax basis never aggregate",()=>{
  const base={periodStart:"2026-11-01",periodEnd:"2026-11-30",revenue:"100.00",cost:"50.00"};
  assert.equal(aggregateMetrics([{...base,currency:"AUD",taxBasis:"gst_exclusive"},{...base,currency:"NZD",taxBasis:"gst_exclusive"}]).aggregationValid,false);
  assert.equal(aggregateMetrics([{...base,currency:"AUD",taxBasis:"gst_exclusive"},{...base,currency:"AUD",taxBasis:"gst_inclusive"}]).aggregationValid,false);
});

test("PROP-005/006 — missing and unconfirmed invoice values cannot enter valid candidate totals",()=>{
  const base={invoice_id:"INV-SYNTHETIC",site:"Site A",date:"2026-11-01"};
  assert.equal(validateInvoiceRows([{...base}])[0].status,"held");
  assert.equal(validateInvoiceRows([{...base,amount:0.1}])[0].status,"held");
  assert.equal(validateInvoiceRows([{...base,amount:"100.00"}])[0].status,"pending_review");
});

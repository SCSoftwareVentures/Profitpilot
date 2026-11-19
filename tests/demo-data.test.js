import test from "node:test";
import assert from "node:assert/strict";
import {DEMO_CONTRACTS} from "../src/demo-data.js";
import {aggregateMetrics} from "../src/engine.js";

test("browser demo fixture supplies explicit financial basis and exact decimal strings",()=>{
  assert.equal(DEMO_CONTRACTS.length,3);
  for(const contract of DEMO_CONTRACTS){
    assert.equal(typeof contract.revenue,"string");
    assert.equal(typeof contract.cost,"string");
    assert.equal(contract.currency,"AUD");
    assert.equal(contract.taxBasis,"gst_exclusive");
    assert.equal(contract.periodStart,"2026-11-01");
    assert.equal(contract.periodEnd,"2026-11-30");
  }
  const result=aggregateMetrics(DEMO_CONTRACTS);
  assert.equal(result.aggregationValid,true);
  assert.equal(result.completeness,"unverified");
  assert.deepEqual([result.revenue,result.cost,result.contribution,result.margin],["48250.00","31840.00","16410.00","34.01"]);
});

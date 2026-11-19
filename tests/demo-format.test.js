import test from "node:test";
import assert from "node:assert/strict";
import {formatDemoMoney} from "../src/demo-format.js";

test("demo money formatter preserves exact decimal text and groups thousands",()=>{
  assert.equal(formatDemoMoney("48250.00"),"$48,250.00");
  assert.equal(formatDemoMoney("-1234.5"),"−$1,234.50");
  assert.equal(formatDemoMoney("0"),"$0.00");
});
test("demo money formatter refuses invalid and non-string amounts",()=>{
  for(const value of [null,48250,"1e3","01.00","1.234","not-money"])assert.equal(formatDemoMoney(value),"Unavailable");
});

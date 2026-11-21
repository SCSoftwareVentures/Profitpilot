import test from "node:test";
import assert from "node:assert/strict";
import {matrix,classifyTestFiles,integrationOrder} from "../scripts/run-test-matrix.mjs";

test("B20 discovers every unit test and all three database integration suites",()=>{
 const result=matrix();
 assert.deepEqual(result.integration,[...integrationOrder]);
 assert.equal(result.integration.length,3);
 assert.ok(result.unit.length>=35,"Unexpectedly few discovered unit suites");
 assert.ok(result.unit.includes("tests/test-matrix.test.js"));
 assert.ok(result.unit.includes("tests/openssl-package-floor.test.js"));
 assert.ok(result.unit.every(p=>p.endsWith(".test.js")&&!p.includes(".integration.test.js")));
 assert.equal(new Set([...result.unit,...result.integration]).size,
  result.unit.length+result.integration.length);
});
test("B20 fails when a new integration suite would otherwise be silently omitted",()=>{
 const original=[...matrix().unit,...integrationOrder];
 assert.throws(()=>classifyTestFiles([...original,"tests/new-payments.integration.test.js"]),
  /Integration test inventory changed/);
 assert.throws(()=>classifyTestFiles(original.filter(p=>p!=="tests/api.integration.test.js")),
  /Integration test inventory changed/);
});
test("B20 rejects duplicate or malformed test-discovery paths",()=>{
 const original=[...matrix().unit,...integrationOrder];
 assert.throws(()=>classifyTestFiles([...original,"tests/api.integration.test.js"]),
  /Invalid or duplicated/);
 assert.throws(()=>classifyTestFiles([...original,"server/non-test.js"]),
  /Invalid or duplicated/);
 assert.throws(()=>classifyTestFiles([...original,null]),/Invalid or duplicated/);
});

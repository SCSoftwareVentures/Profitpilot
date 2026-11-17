import test from "node:test";
import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
const html=await readFile(new URL("../demo/switchproof.html",import.meta.url),"utf8");
test("SwitchProof demo is responsive, local-only and clearly synthetic",()=>{
  assert.match(html,/name="viewport"/);
  assert.match(html,/SWITCHPROOF.*SYNTHETIC DEMO/);
  assert.match(html,/processes text locally in your browser/);
  assert.match(html,/Do not paste real customer/);
  assert.ok(html.includes('from "../src/switchproof.js"'));
  assert.doesNotMatch(html,/\bfetch\s*\(|XMLHttpRequest|localStorage|sessionStorage/);
});
test("SwitchProof demo invalidates stale previews after source edits",()=>{
  assert.match(html,/Source changed\. Re-profile before generating a preview/);
  assert.match(html,/row\.errors\.join/);
  assert.match(html,/textContent/);
});

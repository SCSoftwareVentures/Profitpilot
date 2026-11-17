import test from "node:test";
import assert from "node:assert/strict";
import {readFile,access} from "node:fs/promises";
import {spawnSync} from "node:child_process";
import {fileURLToPath} from "node:url";
import {dirname,resolve} from "node:path";

const root=resolve(dirname(fileURLToPath(import.meta.url)),"..");
const htmlPath=resolve(root,"app/index.html");

test("dashboard module script parses as JavaScript and its local imports exist",async()=>{
  const html=await readFile(htmlPath,"utf8");
  const match=html.match(/<script type="module">([\s\S]*?)<\/script>/);
  assert.ok(match,"dashboard module script must exist");
  const checked=spawnSync(process.execPath,["--check","--input-type=module"],{input:match[1],encoding:"utf8"});
  assert.equal(checked.status,0,checked.stderr||checked.stdout||"dashboard script syntax check failed");
  const imports=[...match[1].matchAll(/from\s+["'](\.\.\/[^"']+)["']/g)].map(x=>x[1]);
  assert.ok(imports.length>=2,"dashboard must use local source modules");
  for(const specifier of imports)await access(resolve(dirname(htmlPath),specifier));
});

test("dashboard shell exposes keyboard focus, labelled import and explicit report limitations",async()=>{
  const html=await readFile(htmlPath,"utf8");
  assert.match(html,/:focus-visible/);
  assert.match(html,/for="csvFile"/);
  assert.match(html,/aria-describedby="importHelp"/);
  assert.match(html,/aria-current="page"/);
  assert.match(html,/source_completeness,unverified/);
  assert.match(html,/indicative_contribution/);
});

test("dashboard rendering escapes dynamic text and never displays a null margin",async()=>{
  const html=await readFile(htmlPath,"utf8");
  assert.match(html,/const escapeHtml=value=>String\(value\?\?""\)\.replace/);
  assert.match(html,/displayMargin\(c\.margin\)/);
  assert.match(html,/Source completeness: unverified/);
  assert.doesNotMatch(html,/\+c\.margin\+'%'/);
});

test("dashboard exposes the synthetic job readiness workflow and its human-authority boundary",async()=>{
  const html=await readFile(htmlPath,"utf8");
  assert.match(html,/data-view="readiness"/);
  assert.match(html,/id="readiness"/);
  assert.match(html,/evaluateJobReadiness/);
  assert.match(html,/data-view="promises"/);
  assert.match(html,/id="promises"/);
  assert.match(html,/renderPromiseLedger/);
  assert.match(html,/data-view="value"/);
  assert.match(html,/id="value"/);
  assert.match(html,/renderValueLedger/);
  assert.match(html,/Lifecycle stage totals are not additive realised value/);
  assert.match(html,/No notifications or external messages are sent/);
  assert.match(html,/data-view="leaks"/);
  assert.match(html,/id="leaks"/);
  assert.match(html,/detectProfitLeaks/);
  assert.match(html,/No accounting entries, refunds, collections or automated decisions are made/);
  assert.match(html,/renderProfitLeaks/);
  assert.match(html,/No override or approval action is available in this demonstration/);
  assert.match(html,/escapeHtml\(x\.label\)/);
  assert.match(html,/escapeHtml\(x\.reason\|\|x\.issue\|\|x\.evidenceRef/);
});

test("main dashboard links to both staged differentiator demonstrations",async()=>{
  const html=await readFile(htmlPath,"utf8");
  assert.match(html,/<a href="\.\.\/demo\/switchproof\.html">SwitchProof<\/a>/);
  assert.match(html,/<a href="\.\.\/demo\/field-knowledge\.html">Field Knowledge<\/a>/);
  await access(resolve(dirname(htmlPath),"../demo/switchproof.html"));
  await access(resolve(dirname(htmlPath),"../demo/field-knowledge.html"));
  assert.match(html,/\.side a:focus-visible/);
});

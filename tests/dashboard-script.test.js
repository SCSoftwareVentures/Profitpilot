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

test("dashboard exposes the synthetic Job Readiness Engine workflow",async()=>{
  const html=await readFile(htmlPath,"utf8");
  assert.match(html,/data-view="readiness"/);
  assert.match(html,/id="readiness"/);
  assert.match(html,/evaluateJobReadiness\(\{template:readinessTemplate,answers:readinessAnswers\}\)/);
  assert.match(html,/Ready for human decision/);
  assert.match(html,/never approves the job automatically/);
});

test("dashboard exposes a synthetic append-only Promise Ledger timeline",async()=>{
  const html=await readFile(htmlPath,"utf8");
  assert.match(html,/data-view="promises"/);
  assert.match(html,/id="promises"/);
  assert.match(html,/appendPromiseEvent\(\{events:promiseProposed\.events/);
  assert.match(html,/This synthetic timeline/);
  assert.match(html,/does not send messages/);
});

test("dashboard exposes evidence-gated Profit Leak Radar candidates",async()=>{
  const html=await readFile(htmlPath,"utf8");
  assert.match(html,/data-view="leaks"/);
  assert.match(html,/id="leaks"/);
  assert.match(html,/assessLeakCandidate/);
  assert.match(html,/Exposure withheld/);
  assert.match(html,/not verified losses or recovered savings/);
});

test("dashboard exposes separate value lifecycle states without netting credits",async()=>{
  const html=await readFile(htmlPath,"utf8");
  assert.match(html,/data-view="value"/);
  assert.match(html,/id="value"/);
  assert.match(html,/summariseValueEvents\(valueLedger\.events\)/);
  assert.match(html,/Credits are not silently netted/);
  assert.match(html,/Net total: withheld/);
});

test("dashboard exposes SwitchProof source profiling and migration safeguards",async()=>{
  const html=await readFile(htmlPath,"utf8");
  assert.match(html,/data-view="migration"/);
  assert.match(html,/id="migration"/);
  assert.match(html,/profileMigration\(\{manifest:migrationManifest/);
  assert.match(html,/does not copy, transform, upload or migrate data/);
  assert.match(html,/control total reconciles/i);
});

test("dashboard exposes permission-scoped Field Knowledge with review and expiry states",async()=>{
  const html=await readFile(htmlPath,"utf8");
  assert.match(html,/data-view="knowledge"/);
  assert.match(html,/id="knowledge"/);
  assert.match(html,/createKnowledgeEntry/);
  assert.match(html,/canReadKnowledgeEntry/);
  assert.match(html,/production access control, retention, consent, audit and secure storage must be enforced server-side/);
});

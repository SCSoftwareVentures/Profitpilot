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

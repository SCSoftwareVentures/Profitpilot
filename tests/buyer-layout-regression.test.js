import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {resolve} from "node:path";
import {fileURLToPath} from "node:url";
const root=resolve(fileURLToPath(new URL("..",import.meta.url)));
const html=()=>readFileSync(resolve(root,"demo/buyer-walkthrough.html"),"utf8");
const shell=()=>readFileSync(resolve(root,"demo/buyer-walkthrough.shell.html"),"utf8");
test("B5 mobile layout uses minmax zero tracks rather than content-sized grid minimums",()=>{
 for(const page of [html(),shell()]){
  assert.match(page,/\.layout\{display:grid;grid-template-columns:minmax\(0,1fr\)/);
  assert.match(page,/\.layout>\*\{min-width:0\}/);
  assert.match(page,/\.columns\{display:grid;grid-template-columns:minmax\(0,1\.07fr\) minmax\(0,\.93fr\)/);
  assert.match(page,/\.columns>\*\{min-width:0\}/);
  assert.match(page,/\.panel\{min-width:0;background:/);
  assert.match(page,/\.tablebox\{max-width:100%;min-width:0;overflow-x:auto\}/);
  assert.match(page,/\.columns\{grid-template-columns:minmax\(0,1fr\)\}\.kpis\{grid-template-columns:minmax\(0,1fr\)\}/);
  assert.match(page,/table\{width:100%;border-collapse:collapse;min-width:740px\}/);
 }
});
test("B5 keeps the source-only synthetic actions and network-denial boundary",()=>{
 const page=html();
 assert.match(page,/connect-src 'none'/);
 assert.match(page,/Simulate invoice-match confirmation/);
 assert.match(page,/Simulate payroll allocation/);
 assert.match(page,/No approval path in this demonstration/);
 assert.doesNotMatch(page,/<script[^>]*src=/i);
});

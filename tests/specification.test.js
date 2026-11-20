import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync,existsSync} from "node:fs";
import {resolve} from "node:path";
const catalog=JSON.parse(readFileSync(new URL("../docs/specification/requirements.json",import.meta.url),"utf8"));
const root=new URL("../",import.meta.url);
test("A1 specification catalogue covers every required design family",()=>{
 const expected={SD:4,FR:15,DI:5,SP:5,QO:4,AH:4};
 const ids=new Set();
 for(const r of catalog.requirements){
  assert.match(r.id,/^(SD|FR|DI|SP|QO|AH)-\d{2}$/);
  assert.ok(!ids.has(r.id),r.id);ids.add(r.id);
  for(const key of ["title","ownerRole","verification","currentEvidence","document"])assert.ok(typeof r[key]==="string"&&r[key].trim(),r.id+" "+key);
  assert.ok(["A","B","C","D"].includes(r.phase));
  assert.ok(["design-only","partial-prototype"].includes(r.currentEvidence));
  assert.ok(r.dependencies.length>0);
  if(r.phase==="D")assert.ok(r.dependencies.includes("legal/provider approval"));
  const doc=readFileSync(new URL(r.document,root),"utf8");
  assert.ok(doc.includes(r.id),r.id+" missing from "+r.document);
 }
 for(const [prefix,count] of Object.entries(expected))for(let i=1;i<=count;i++)assert.ok(ids.has(prefix+"-"+String(i).padStart(2,"0")));
 assert.equal(ids.size,Object.values(expected).reduce((a,b)=>a+b,0));
});
test("A1 index links only existing local specification files and preserves gates",()=>{
 const index=readFileSync(new URL("docs/specification/README.md",root),"utf8");
 for(const match of index.matchAll(/\]\(([^)]+)\)/g))assert.ok(existsSync(new URL(match[1],new URL("docs/specification/",root))),match[1]);
 assert.match(index,/not G5 approval/);
 const gates=readFileSync(new URL("docs/VALIDATION_GATES.md",root),"utf8");
 assert.match(gates,/Software build is prohibited until G0–G4/);
 const pay=readFileSync(new URL("docs/specification/SECUREPAY.md",root),"utf8");
 assert.match(pay,/never automatic transfer/);
});

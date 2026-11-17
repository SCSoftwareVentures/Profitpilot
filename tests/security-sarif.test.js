import test from "node:test";
import assert from "node:assert/strict";
import {assessSarif} from "../scripts/check-security-sarif.js";
const doc=(results=[],rules=[])=>({version:"2.1.0",runs:[{tool:{driver:{name:"CodeQL",rules}},results,invocations:[{executionSuccessful:true}]}]});
test("security gate detects high severity and does not echo finding payloads",()=>{
 assert.deepEqual(assessSarif(doc()),{total:0,blocking:[]});
 const rules=[{id:"js/example",properties:{"security-severity":"8.1"}},{id:"js/low",properties:{"security-severity":"3.2"}}];
 const r=assessSarif(doc([{ruleId:"js/example",message:{text:"sensitive marker"},locations:[{physicalLocation:{artifactLocation:{uri:"server/auth.js"},region:{startLine:12}}}]},{ruleId:"js/low"}],rules));
 assert.equal(r.total,2);assert.deepEqual(r.blocking,[{rule:"js/example",path:"server/auth.js",line:12}]);assert.equal(JSON.stringify(r).includes("sensitive marker"),false);
});
test("security gate rejects missing, fake, unclassified or unsuccessful reports",()=>{
 for(const d of [{},{version:"2.1.0",runs:[]},doc([{ruleId:"unknown"}]),{...doc(),runs:[{...doc().runs[0],invocations:[{executionSuccessful:false}]}]}, {version:"2.1.0",runs:[{tool:{driver:{name:"Other",rules:[]}},results:[]}]}])assert.throws(()=>assessSarif(d));
});

test("CodeQL rules contributed by extension packs retain their severity",()=>{
 const d=doc([{ruleId:"js/extension"}]);
 delete d.runs[0].tool.driver.rules;
 d.runs[0].tool.extensions=[{rules:[{id:"js/extension",properties:{"security-severity":"9.5"}}]}];
 assert.equal(assessSarif(d).blocking.length,1);
});

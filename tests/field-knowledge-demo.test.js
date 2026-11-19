import test from "node:test";
import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
const html=await readFile(new URL("../demo/field-knowledge.html",import.meta.url),"utf8");
test("Field Knowledge demo is mobile-first, synthetic and permission-aware",()=>{
 assert.match(html,/name="viewport"/);assert.match(html,/FIELD KNOWLEDGE.*SYNTHETIC DEMO/);
 assert.match(html,/not a credential vault/);assert.match(html,/createKnowledgeRecord,searchKnowledge/);
 assert.match(html,/owner_admin/);assert.match(html,/site_staff/);
 assert.doesNotMatch(html,/\bfetch\s*\(|XMLHttpRequest|localStorage|sessionStorage/);
});
test("Field Knowledge demo uses safe text rendering and role filtering",()=>{
 assert.match(html,/textContent/);assert.match(html,/addEventListener/);
 assert.match(html,/searchKnowledge\(records/);
});

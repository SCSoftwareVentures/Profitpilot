import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {webcrypto,createHash,randomUUID} from "node:crypto";
import {parseMinimizedRows,checksum,assignedSites,mappingLine,mappingKey,tenantPath,date,range} from "../server/product-ui/core.js";
const id=randomUUID(),site=randomUUID(),other=randomUUID(),key="ppr_"+"a".repeat(64),ref="ev_"+"c".repeat(60);
test("product source parser matches canonical server checksum and exact cents",async()=>{
 const parsed=parseMinimizedRows(key+",0.10,AUD\n"+"ppr_"+"b".repeat(64)+",0.20,AUD");
 assert.equal(parsed.controlTotal,"0.30");
 assert.equal(await checksum(parsed.canonical,webcrypto.subtle),createHash("sha256").update(parsed.canonical).digest("hex"));
 for(const input of ["employee,1.00,AUD",key+",1.0,AUD",key+",1.00,USD",key+",1.00,AUD\n"+key+",2.00,AUD",key+",-1.00,AUD",key+",1.00,AUD\r\n"])assert.throws(()=>parseMinimizedRows(input));
});
test("selectors and mappings use explicit site assignments",()=>{
 assert.deepEqual(assignedSites({contract_site:[{parentId:id,relatedId:site}],site:[{id:site,label:"A"},{id:other,label:"B"}]},id),[{id:site,label:"A"}]);
 const m=mappingLine({sourceRowKey:key,bucket:"approved_allocated",siteId:site,amount:"1.00",evidenceRef:ref});
 assert.equal(m.siteId,site);assert.ok(mappingKey(m));assert.throws(()=>mappingLine({...m,amount:"0.00"}));assert.throws(()=>mappingLine({...m,bucket:"direct"}));
});
test("relative tenant path, amounts and dates fail closed",()=>{assert.equal(tenantPath(id,"/workspace/jobs"),"/v1/tenants/"+id+"/workspace/jobs");for(const path of ["https://example.invalid","//example.invalid","/../other","/x#y"])assert.throws(()=>tenantPath(id,path));assert.throws(()=>date("2026-02-30"));assert.throws(()=>range("2026-01-02","2026-01-01"));});
test("candidate frontend action and element wiring; no persistent credential storage or external assets",()=>{
 const html=readFileSync(new URL("../server/product-ui/index.html",import.meta.url),"utf8"),app=readFileSync(new URL("../server/product-ui/app.js",import.meta.url),"utf8");
 const ids=[...html.matchAll(/\bid="([^"]+)"/g)].map(m=>m[1]);assert.equal(ids.length,new Set(ids).size);
 const actions=[...html.matchAll(/data-action="([^"]+)"/g)].map(m=>m[1]);for(const x of actions)assert.ok(x==="clear"||app.includes('case "'+x+'"'),x);
 for(const m of app.matchAll(/\b(?:el|value|uid|set|required|evidence|confirmed|show|options|newId)\("([a-z-]+)"/g))assert.ok(ids.includes(m[1]),m[1]);
 assert.match(app,/credentials:"omit",cache:"no-store",redirect:"error"/);
 assert.doesNotMatch(app,/\b(?:localStorage|sessionStorage|innerHTML|document\.cookie|eval)\b/);
 assert.doesNotMatch(html,/\b(?:src|href)="https?:/i);
 assert.match(html,/Synthetic candidate/);assert.match(html,/Customer invoices must be scanned/);
});

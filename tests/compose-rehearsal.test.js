import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {resolve} from "node:path";
import {fileURLToPath} from "node:url";
import {renderLegacyCompose} from "../scripts/make-b8-legacy-compose.mjs";
const root=resolve(fileURLToPath(new URL("..",import.meta.url)));
const read=p=>readFileSync(resolve(root,p),"utf8");
const source=read("docker-compose.yml");
const paths=text=>text.split("\n").filter(x=>x.includes("./database/migrations/"));
test("B8 fixture removes exactly nine historical SecurePay SQL mounts, preserving the earlier 23",()=>{
 const legacy=renderLegacyCompose(source);
 assert.equal(paths(source).length,32);
 assert.equal(paths(legacy).length,23);
 for(let n=25;n<=33;n++){
  const id=String(n).padStart(3,"0");
  assert.match(source,new RegExp("/"+id+"_securepay_"));
  assert.doesNotMatch(legacy,new RegExp("/"+id+"_securepay_"));
 }
 assert.match(legacy,/024_unified_report_snapshots\.sql/);
 assert.match(legacy,/database\/schema\.sql/);
 assert.match(legacy,/002-runtime-role\.sql/);
 assert.match(legacy,/004-tenant-context-key\.sql/);
 assert.equal(legacy.includes("POSTGRES_APP_PASSWORD"),true);
});
test("B8 fixture refuses accidental omission drift and malformed Compose input",()=>{
 assert.throws(()=>renderLegacyCompose(""),/Invalid/);
 assert.throws(()=>renderLegacyCompose(source.replace(/025_securepay_evidence_register\.sql/g,"024_broken.sql")),/exactly nine/);
});
test("B8 runtime rehearsal cannot run outside CI and cleans isolated volumes",()=>{
 const script=read("scripts/rehearse-compose-b8.sh");
 assert.match(script,/GITHUB_ACTIONS.*!= true/);
 assert.match(script,/RUNNER_TEMP/);
 assert.match(script,/PROJECT="profitpilotb8\$GITHUB_RUN_ID"/);
 assert.match(script,/trap cleanup EXIT/);
 assert.match(script,/down --volumes --remove-orphans/);
 assert.match(script,/pg_dump/);
 assert.match(script,/pg_restore/);
 assert.match(script,/wrong-key/);
 assert.match(script,/to_regclass\('public\.securepay_encrypted_custody_receipts'\) IS NULL/);
 assert.match(script,/for n in \{025\.\.033\}/);
 assert.match(script,/rolsuper OR rolbypassrls/);
 assert.match(script,/PGPASSWORD/);
 assert.match(script,/SELECT count\(\*\) FROM tenants/);
});
test("B8 source provenance and buyer packaging depend on the new independent recovery gate",()=>{
 const ci=read(".github/workflows/ci.yml");
 assert.match(ci,/  compose_rehearsal:\n    name: Synthetic Compose boot and legacy-volume upgrade\n    needs: \[verify\]/);
 assert.match(ci,/run: bash scripts\/rehearse-compose-b8\.sh/);
 const matches=ci.match(/needs: \[verify, database, static_analysis, container_security, compose_rehearsal\]/g)||[];
 assert.equal(matches.length,2);
});

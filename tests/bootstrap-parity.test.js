import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync,readdirSync} from "node:fs";
import {resolve} from "node:path";
import {fileURLToPath} from "node:url";
const root=resolve(fileURLToPath(new URL("..",import.meta.url)));
const read=p=>readFileSync(resolve(root,p),"utf8");
const source=()=>readdirSync(resolve(root,"database/migrations")).filter(f=>/^[0-9]{3}_[a-z0-9_]+\.sql$/.test(f)).sort();
function composeMounts(input){
 const candidates=input.split("\n").filter(x=>x.includes("./database/migrations/"));
 const rows=candidates.map(line=>{
  const match=/^\s*-\s+\.\/database\/migrations\/([0-9]{3}_[a-z0-9_]+\.sql):\/docker-entrypoint-initdb\.d\/([0-9]{3})-[a-z0-9-]+\.sql:ro\s*$/.exec(line);
  assert.ok(match,"Migration volume must be a single read-only SQL mount with numbered destination");
  return {source:match[1],dest:Number(match[2])};
 });
 return rows;
}
function ciMigrations(input){
 const lines=input.split("\n").filter(x=>x.trim().startsWith('psql "$DB_URL" ')&&x.includes("database/migrations/"));
 return lines.map(line=>{
  const match=/-f\s+database\/migrations\/([0-9]{3}_[a-z0-9_]+\.sql)(?:\s|$)/.exec(line);
  assert.ok(match,"CI migration command must point to the explicit migration file");
  return match[1];
 });
}
test("B7 clean Compose database bootstrap and CI enumerate every SQL migration in source order",()=>{
 const expected=source();
 const mounted=composeMounts(read("docker-compose.yml"));
 const applied=ciMigrations(read(".github/workflows/ci.yml"));
 assert.ok(expected.length>=32,"Unexpectedly short historical migration set");
 assert.deepEqual(mounted.map(x=>x.source),expected,"Compose initialization must apply every migration");
 assert.deepEqual(applied,expected,"CI must apply every migration");
 assert.equal(new Set(mounted.map(x=>x.dest)).size,mounted.length,"Init destination collision");
 for(let i=1;i<mounted.length;i++)
  assert.ok(mounted[i].dest>mounted[i-1].dest,"Lexicographic Compose execution order must match migrations");
});
test("B7 bootstrap preserves runtime-role and HMAC key initialization before later migrations",()=>{
 const compose=read("docker-compose.yml");
 const role=compose.indexOf("./database/init/002-runtime-role.sql");
 const mig2=compose.indexOf("./database/migrations/002_tenant_rls.sql");
 const hmac=compose.indexOf("./database/init/003-tenant-context-key.sql");
 const mig3=compose.indexOf("./database/migrations/003_allocation_lines.sql");
 assert.ok(role>=0&&role<mig2&&mig2<hmac&&hmac<mig3);
 assert.match(compose,/\.\/database\/schema\.sql:\/docker-entrypoint-initdb\.d\/001-schema\.sql:ro/);
});
test("B7 migration parser rejects omissions, duplicate destination numbers and writable mounts",()=>{
 const input=read("docker-compose.yml");
 const rows=composeMounts(input);
 assert.equal(rows.length,source().length);
 const omitted=input.replace(/^.*025_securepay_evidence_register\.sql.*\n/m,"");
 assert.equal(composeMounts(omitted).length,rows.length-1);
 const duplicate=input.replace(/\/027-securepay-evidence-register\.sql:ro/,"/026-securepay-evidence-register.sql:ro");
 const duplicated=composeMounts(duplicate);
 assert.equal(new Set(duplicated.map(x=>x.dest)).size,rows.length-1);
 const writable=input.replace("/027-securepay-evidence-register.sql:ro","/027-securepay-evidence-register.sql:rw");
 assert.throws(()=>composeMounts(writable),/read-only SQL mount/);
});
test("B7 Docker volume reuse is explicitly NOT labelled an automatically migrated database",()=>{
 const guide=read("docs/LOCAL_DEVELOPMENT.md");
 assert.match(guide,/existing volumes are not automatically migrated/i);
 assert.match(guide,/do not delete a volume containing data/i);
});

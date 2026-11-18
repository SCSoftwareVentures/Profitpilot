import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync,readdirSync} from "node:fs";
import {verifyMigrationInventory} from "../scripts/verify-migration-inventory.js";
const root=new URL("../",import.meta.url);
const read=p=>readFileSync(new URL(p,root),"utf8");
const actual={
 migrations:readdirSync(new URL("database/migrations/",root)),
 init:readdirSync(new URL("database/init/",root)),
 workflow:read(".github/workflows/ci.yml"),
 compose:read("docker-compose.yml")
};
test("complete and identically ordered CI and local migration inventory",()=>{
 assert.equal(verifyMigrationInventory(actual),actual.migrations.length+3);
});
test("acceptance inventory rejects omitted, duplicated, reordered and writable migrations",()=>{
 for(const change of [
  {migrations:actual.migrations.slice(1)},
  {migrations:[...actual.migrations,actual.migrations[0]]},
  {init:[...actual.init,"extra.sql"]},
  {workflow:actual.workflow.replace(/^\s*psql .* -f database\/migrations\/003_allocation_lines\.sql\s*$/m,"")},
  {workflow:actual.workflow.replace("database/migrations/003_allocation_lines.sql","database/migrations/002_tenant_rls.sql")},
  {compose:actual.compose.replace("005-allocation-lines.sql:ro","005-allocation-lines.sql:rw")},
  {compose:actual.compose.replace("005-allocation-lines.sql:ro","003-allocation-lines.sql:ro")},
  {compose:actual.compose+"\n        - ./unreviewed:/docker-entrypoint-initdb.d/unreviewed.sql:ro\n"}
 ])assert.throws(()=>verifyMigrationInventory({...actual,...change}));
});

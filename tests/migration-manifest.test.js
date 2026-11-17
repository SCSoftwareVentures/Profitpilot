import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync,readdirSync} from "node:fs";

const compose=readFileSync(new URL("../docker-compose.yml",import.meta.url),"utf8");
const workflow=readFileSync(new URL("../.github/workflows/ci.yml",import.meta.url),"utf8");
const files=readdirSync(new URL("../database/migrations/",import.meta.url))
 .filter(name=>/^\d{3}_[a-z0-9_]+\.sql$/.test(name))
 .sort();
const sourcePath=name=>"database/migrations/"+name;

// Strictly compare the real initialization commands, not comments or documentation.
const composeMounts=[...compose.matchAll(
 /^\s*-\s+\.\/(database\/(?:schema\.sql|init\/[a-z0-9_-]+\.sql|migrations\/\d{3}_[a-z0-9_]+\.sql)):(\/docker-entrypoint-initdb\.d\/\d+-[a-z0-9_-]+\.sql):ro\s*$/gm
)].map(m=>({file:m[1],target:m[2]}));

const ciCommands=[...workflow.matchAll(
 /^\s+(?:POSTGRES_APP_PASSWORD="\$POSTGRES_APP_PASSWORD"\s+)?psql "\$DB_URL" -v ON_ERROR_STOP=1 -f (database\/(?:schema\.sql|init\/[a-z0-9_-]+\.sql|migrations\/\d{3}_[a-z0-9_]+\.sql))\s*$/gm
)].map(m=>m[1]);

test("every migration is loaded once in matching Docker Compose and CI order",()=>{
 assert.ok(files.length>=24,"migration directory is unexpectedly small");
 assert.deepEqual(files.map(name=>name.slice(0,3)),
  Array.from({length:files.length},(_,i)=>String(i+2).padStart(3,"0")),
  "migration numbers must be contiguous from 002");
 const localSequence=composeMounts.map(m=>m.file);
 const ciSequence=ciCommands;
 assert.deepEqual(localSequence,ciSequence,
  "Compose and CI must bootstrap the schema, roles, signing keys and all migrations in identical order");
 assert.deepEqual(
  localSequence.filter(file=>file.startsWith("database/migrations/")),
  files.map(sourcePath),
  "every migration SQL file must be applied exactly once");
 assert.equal(new Set(composeMounts.map(m=>m.target)).size,composeMounts.length,
  "Compose initdb filenames must not collide");
 const initNumbers=composeMounts.map(m=>Number(m.target.match(/\/(\d+)-/)[1]));
 assert.deepEqual(initNumbers,
  Array.from({length:composeMounts.length},(_,i)=>i+1),
  "Compose initdb mounts must run in strictly increasing numerical order");
});

test("security checks use the restricted runtime database role and fail-closed audit",()=>{
 assert.match(workflow,/node --test tests\/tenant-isolation-catalog\.integration\.test\.js/);
 assert.match(workflow,/node --test tests\/route-tenant-isolation\.integration\.test\.js/);
 assert.match(workflow,/TEST_APP_DATABASE_URL=/);
 assert.ok(files.some(name=>name.startsWith("025_runtime_acl_and_catalog_guard")),
  "default runtime permission revocation must be present in migration inventory");
});

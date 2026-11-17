import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
const read=path=>readFileSync(new URL("../"+path,import.meta.url),"utf8");
test("all locked production dependencies have fixed npm registry resolution and SHA-512 integrity",()=>{
 const manifest=JSON.parse(read("package.json")),lock=JSON.parse(read("package-lock.json"));
 assert.equal(lock.lockfileVersion,3);
 assert.deepEqual(lock.packages[""].dependencies,manifest.dependencies);
 for(const [name,pkg] of Object.entries(lock.packages)){
  if(!name)continue;
  assert.match(pkg.resolved||"",/^https:\/\/registry\.npmjs\.org\//,name);
  assert.match(pkg.integrity||"",/^sha512-[A-Za-z0-9+/=]+$/,name);
  assert.equal(typeof pkg.version,"string",name);
 }
 assert.match(read("Dockerfile"),/npm ci --omit=dev --ignore-scripts/);
 const ci=read(".github/workflows/ci.yml");
 assert.match(ci,/npm ci --ignore-scripts/);
 assert.doesNotMatch(ci,/npm install --/);
 assert.match(ci,/npm sbom --omit=dev --sbom-format cyclonedx/);
 assert.doesNotMatch(ci,/PP_LOCK_CHUNK/);
});
test("Docker build context and local runtime privileges are constrained",()=>{
 const ignore=read(".dockerignore");
 assert.match(ignore,/^\*\*$/m);
 for(const file of ["!package-lock.json","!server/**","!src/**","**/.env","**/*.key","**/*.dump"])assert.ok(ignore.split("\n").includes(file),file);
 const ci=read(".github/workflows/ci.yml");
 assert.match(ci,/docker run -d --read-only --cap-drop ALL --security-opt no-new-privileges/);
 const compose=read("docker-compose.yml");
 assert.match(compose,/api:\s+build: \.\s+read_only: true\s+cap_drop:\s+- ALL\s+security_opt:\s+- no-new-privileges:true/);
});

#!/usr/bin/env node
// B20: explicit, fail-closed unit vs PostgreSQL integration test matrix.
// Never classify a newly added integration test as "skipped but covered".
import {readdirSync,appendFileSync} from "node:fs";
import {join,relative,resolve,sep} from "node:path";
import {fileURLToPath} from "node:url";
import {spawnSync} from "node:child_process";

const root=resolve(fileURLToPath(new URL("..",import.meta.url)));
const testRoot=join(root,"tests");
export const integrationOrder=Object.freeze([
 "tests/securepay-storage.integration.test.js",
 "tests/securepay-custody.integration.test.js",
 "tests/api.integration.test.js"
]);
function discover(dir){
 const results=[];
 for(const entry of readdirSync(dir,{withFileTypes:true})){
  const path=join(dir,entry.name);
  if(entry.isDirectory())results.push(...discover(path));
  else if(entry.isFile()&&/\.(?:test|spec)\.(?:js|mjs|cjs)$/.test(entry.name))
   results.push(relative(root,path).split(sep).join("/"));
 }
 return results;
}
export function classifyTestFiles(paths){
 if(!Array.isArray(paths)||paths.some(p=>typeof p!=="string"||!p.startsWith("tests/")||
  !/\.(?:test|spec)\.(?:js|mjs|cjs)$/.test(p))||new Set(paths).size!==paths.length)
  throw Error("Invalid or duplicated test discovery paths");
 const integration=paths.filter(p=>p.endsWith(".integration.test.js")).sort();
 const expected=[...integrationOrder].sort();
 if(integration.length!==expected.length||expected.some((p,i)=>p!==integration[i]))
  throw Error("Integration test inventory changed: update the CI execution matrix and preserve database coverage");
 const unit=paths.filter(p=>!integrationOrder.includes(p)).sort();
 if(unit.length===0)throw Error("No unit tests discovered");
 return Object.freeze({unit:Object.freeze(unit),integration:Object.freeze([...integrationOrder])});
}
export function matrix(){
 return classifyTestFiles(discover(testRoot));
}
function execute(files,label){
 const command=[ "--test","--test-reporter=tap",...files ];
 const result=spawnSync(process.execPath,command,{
  cwd:root,env:process.env,encoding:"utf8",maxBuffer:16*1024*1024
 });
 if(result.stdout)process.stdout.write(result.stdout);
 if(result.stderr)process.stderr.write(result.stderr);
 if(result.error)throw result.error;
 if(result.status!==0||result.signal)
  throw Error(label+" failed (status "+result.status+", signal "+result.signal+")");
 const summary={};
 for(const m of result.stdout.matchAll(/^# (tests|pass|fail|skipped) (\d+)\r?$/gm))
  summary[m[1]]=Number(m[2]);
 if(!["tests","pass","fail","skipped"].every(k=>Number.isSafeInteger(summary[k]))||
  summary.tests<=0||summary.fail!==0||summary.skipped!==0||
  summary.pass!==summary.tests)
  throw Error(label+" has incomplete, skipped or unverifiable tests: "+JSON.stringify(summary));
 return summary;
}
function reportLine(s){
 return s.tests+" executed; "+s.pass+" passed; "+s.fail+" failed; "+s.skipped+" skipped";
}
function ciSummary(markdown){
 if(process.env.GITHUB_STEP_SUMMARY)appendFileSync(process.env.GITHUB_STEP_SUMMARY,markdown,"utf8");
}
export function runMatrix(mode){
 const plan=matrix();
 if(mode==="unit"){
  const summary=execute(plan.unit,"Unit test suite");
  console.log("B20 UNIT SUITE:",reportLine(summary),
   "| database integration tests are explicitly executed in the separate PostgreSQL job.");
  ciSummary("### ProfitPilot unit tests — B20\n\n"+
   "- **"+reportLine(summary)+"**\n"+
   "- Three database-dependent suites are **not part of this unit-test run**; "+
   "they must pass separately in the PostgreSQL job.\n");
  return;
 }
 if(mode==="integration"){
  for(const key of ["TEST_ADMIN_DATABASE_URL","TEST_APP_DATABASE_URL","TENANT_CONTEXT_HMAC_SECRET"])
   if(typeof process.env[key]!=="string"||process.env[key].length<1)
    throw Error("Refusing integration run without PostgreSQL test prerequisites: "+key);
  // Each suite runs in a fresh process because API fixtures mutate process.env,
  // and signing-key rotation in the API test must happen after both SecurePay suites.
  let executed=0,passed=0;
  const lines=[];
  for(const file of plan.integration){
   const s=execute([file],file);
   executed+=s.tests;passed+=s.pass;
   lines.push("- "+file+": **"+reportLine(s)+"**");
  }
  if(executed<plan.integration.length)
   throw Error("Incomplete PostgreSQL integration coverage");
  console.log("B20 POSTGRES INTEGRATION SUITES: "+plan.integration.length+
   " suites, "+executed+" executed, "+passed+" passed, zero skipped.");
  ciSummary("### ProfitPilot PostgreSQL integration — B20\n\n"+
   lines.join("\n")+"\n\n"+
   "**All "+plan.integration.length+" database suites executed; none skipped.**\n");
  return;
 }
 throw Error("Usage: node scripts/run-test-matrix.mjs unit|integration");
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{runMatrix(process.argv[2]);}
 catch(error){console.error(error);process.exitCode=1;}
}

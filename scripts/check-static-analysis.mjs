import {readFileSync} from "node:fs";
const path=process.argv[2];
if(!path)throw Error("SARIF report required");
const r=JSON.parse(readFileSync(path,"utf8"));
if(r.version!=="2.1.0"||!Array.isArray(r.runs)||!r.runs.length)throw Error("Invalid SARIF");
let findings=0;
for(const run of r.runs){
 if(run.tool?.driver?.name!=="CodeQL"||!Array.isArray(run.results)||!run.invocations?.some(i=>i.executionSuccessful===true)||run.invocations.some(i=>i.executionSuccessful===false))throw Error("Incomplete CodeQL execution");
 for(const item of run.results){findings++;console.error("CodeQL finding:",item.ruleId??"unknown");}
}
console.log("CodeQL findings:",findings);
if(findings)process.exitCode=1;

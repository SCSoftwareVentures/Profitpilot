// Fail closed on absent or malformed static analysis evidence. Print rule/line only, never messages or source.
import {readFileSync,readdirSync,statSync} from "node:fs";
import {join} from "node:path";
import {pathToFileURL} from "node:url";
export function assessSarif(doc){
 if(doc?.version!=="2.1.0"||!Array.isArray(doc.runs)||!doc.runs.length)throw Error("Missing SARIF analysis");
 const blocking=[];let total=0;
 for(const run of doc.runs){
  const driver=run.tool?.driver;
  if(typeof driver?.name!=="string"||!driver.name.toLowerCase().includes("codeql")||!Array.isArray(run.results)||driver.rules!==undefined&&!Array.isArray(driver.rules)||run.tool.extensions!==undefined&&!Array.isArray(run.tool.extensions))throw Error("Unrecognised CodeQL evidence");
  if(run.invocations?.some(i=>i.executionSuccessful!==true))throw Error("Incomplete CodeQL invocation");
  const rules=new Map();
  for(const component of [driver,...(run.tool.extensions??[])]){
   if(component.rules!==undefined&&!Array.isArray(component.rules))throw Error("Invalid CodeQL rule metadata");
   for(const rule of component.rules??[]){
    if(typeof rule.id!=="string")throw Error("Invalid CodeQL rule metadata");
    const old=rules.get(rule.id);
    if(old&&JSON.stringify(old)!==JSON.stringify(rule))throw Error("Conflicting CodeQL rule metadata");
    rules.set(rule.id,rule);
   }
  }
  for(const result of run.results){
   total++;
   const rule=rules.get(result.ruleId);
   if(!rule)throw Error("Unclassified static analysis finding");
   const severity=Number(rule.properties?.["security-severity"]);
   const critical=result.level==="error"||rule.defaultConfiguration?.level==="error"||Number.isFinite(severity)&&severity>=7;
   if(critical){
    const location=result.locations?.[0]?.physicalLocation;
    const path=location?.artifactLocation?.uri;
    blocking.push({rule:result.ruleId,path:typeof path==="string"&&/^[A-Za-z0-9_./-]{1,300}$/.test(path)?path:undefined,line:location?.region?.startLine});
   }
  }
 }
 return {total,blocking};
}
function main(){
 const dir=process.argv[2];
 if(!dir)throw Error("CodeQL evidence directory required");
 const files=readdirSync(dir).filter(p=>p.endsWith(".sarif"));
 if(!files.length)throw Error("CodeQL produced no SARIF");
 let total=0,blocking=[];
 for(const file of files){const path=join(dir,file);if(statSync(path).size>64*1024*1024)throw Error("Oversized SARIF");const r=assessSarif(JSON.parse(readFileSync(path,"utf8")));total+=r.total;blocking.push(...r.blocking);}
 console.log(JSON.stringify({reports:files.length,findings:total,blocking}));
 if(blocking.length)process.exitCode=1;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)try{main();}catch(e){const known=new Set(["CodeQL evidence directory required","CodeQL produced no SARIF","Oversized SARIF","Missing SARIF analysis","Unrecognised CodeQL evidence","Incomplete CodeQL invocation","Invalid CodeQL rule metadata","Conflicting CodeQL rule metadata","Unclassified static analysis finding"]);console.error(known.has(e?.message)?e.message:"Static security evidence invalid or unavailable.");process.exitCode=1;}

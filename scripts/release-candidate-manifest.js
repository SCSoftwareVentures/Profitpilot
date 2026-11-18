import {createHash} from "node:crypto";
import {createReadStream,lstatSync,readdirSync,readFileSync,writeFileSync} from "node:fs";
import {join} from "node:path";
import {pathToFileURL} from "node:url";
const FORMAT="profitpilot-release-candidate-v1";
export const FILES=["api-image.tar.gz","api-scan.json","database-image.tar.gz","database-scan.json","sbom.json","source.tar.gz"];
const SHA=/^[0-9a-f]{64}$/,COMMIT=/^[0-9a-f]{40}$/,IMAGE=/^sha256:[0-9a-f]{64}$/;
const exact=(v,keys)=>v!==null&&typeof v==="object"&&!Array.isArray(v)&&Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));
const MAX_FILE=1024*1024*1024,MAX_JSON=32*1024*1024;
function metadata(value){
 if(!exact(value,["repository","commit","runId","runAttempt","platform","apiImage","databaseImage"])||
 value.repository!=="luxhustle01-ux/Profitpilot"||typeof value.commit!=="string"||!COMMIT.test(value.commit)||
 typeof value.runId!=="string"||!/^[1-9]\d{0,19}$/.test(value.runId)||
 typeof value.runAttempt!=="string"||!/^[1-9]\d{0,5}$/.test(value.runAttempt)||
 value.platform!=="linux/amd64"||typeof value.apiImage!=="string"||!IMAGE.test(value.apiImage)||
 typeof value.databaseImage!=="string"||!IMAGE.test(value.databaseImage)||value.apiImage===value.databaseImage)throw Error("Invalid candidate metadata");
 return {repository:value.repository,commit:value.commit,runId:value.runId,runAttempt:value.runAttempt,platform:value.platform,apiImage:value.apiImage,databaseImage:value.databaseImage};
}
async function digestFile(dir,name){
 const path=join(dir,name),s=lstatSync(path);
 if(!s.isFile()||s.size<1||s.size>MAX_FILE)throw Error("Invalid candidate file");
 const h=createHash("sha256");let n=0;
 for await(const chunk of createReadStream(path)){n+=chunk.length;if(n>MAX_FILE)throw Error("Candidate file exceeds bounds");h.update(chunk);}
 if(n!==s.size)throw Error("Candidate file changed during hashing");
 return {name,bytes:n,sha256:h.digest("hex")};
}
function readBoundedJson(dir,name){
 const p=join(dir,name),s=lstatSync(p);
 if(!s.isFile()||s.size<1||s.size>MAX_JSON)throw Error("Invalid candidate JSON file");
 return JSON.parse(readFileSync(p,"utf8"));
}
function checkScan(dir,name,expected){
 const report=readBoundedJson(dir,name);
 if(report?.SchemaVersion!==2||report?.ArtifactType!=="container_image"||report?.Metadata?.ImageID!==expected||
 !Array.isArray(report.Results)||!report.Results.length)throw Error("Scan evidence does not match candidate image");
 for(const result of report.Results){
  if(!result||typeof result!=="object"||typeof result.Target!=="string")throw Error("Invalid scanner result");
  if(result.Vulnerabilities!==undefined&&result.Vulnerabilities!==null&&!Array.isArray(result.Vulnerabilities))throw Error("Invalid vulnerability list");
  if((result.Vulnerabilities||[]).some(v=>!v||typeof v.Severity!=="string"||["HIGH","CRITICAL"].includes(v.Severity.toUpperCase())))throw Error("Unresolved severe vulnerability");
 }
}
function checkSbom(dir){
 const sbom=readBoundedJson(dir,"sbom.json");
 if(sbom?.bomFormat!=="CycloneDX"||!Array.isArray(sbom.components)||!sbom.components.length)throw Error("Missing dependency SBOM");
}
function checkNames(dir,withManifest){
 const expected=[...FILES,...(withManifest?["manifest.json"]:[])].sort();
 const actual=readdirSync(dir).sort();
 if(JSON.stringify(actual)!==JSON.stringify(expected))throw Error("Unexpected candidate artifact inventory");
}
export async function buildManifest(dir,info){
 checkNames(dir,false);
 const meta=metadata(info);
 checkScan(dir,"api-scan.json",meta.apiImage);
 checkScan(dir,"database-scan.json",meta.databaseImage);
 checkSbom(dir);
 const artifacts=[];for(const filename of FILES)artifacts.push(await digestFile(dir,filename));
 return {format:FORMAT,...meta,artifacts};
}
export async function verifyManifest(dir,{repository,commit,runId,runAttempt}){
 checkNames(dir,true);const m=readBoundedJson(dir,"manifest.json");
 if(!exact(m,["format","repository","commit","runId","runAttempt","platform","apiImage","databaseImage","artifacts"])||m.format!==FORMAT||
 m.repository!==repository||m.commit!==commit||m.runId!==runId||m.runAttempt!==runAttempt||!Array.isArray(m.artifacts)||m.artifacts.length!==FILES.length)throw Error("Candidate identity mismatch");
 const meta=metadata({repository:m.repository,commit:m.commit,runId:m.runId,runAttempt:m.runAttempt,platform:m.platform,apiImage:m.apiImage,databaseImage:m.databaseImage});
 for(let i=0;i<FILES.length;i++){
  const row=m.artifacts[i];
  if(!exact(row,["name","bytes","sha256"])||row.name!==FILES[i]||!Number.isSafeInteger(row.bytes)||row.bytes<1||row.bytes>MAX_FILE||typeof row.sha256!=="string"||!SHA.test(row.sha256))throw Error("Invalid artifact entry");
  const actual=await digestFile(dir,FILES[i]);
  if(actual.bytes!==row.bytes||actual.sha256!==row.sha256)throw Error("Release artifact digest mismatch");
 }
 checkScan(dir,"api-scan.json",meta.apiImage);checkScan(dir,"database-scan.json",meta.databaseImage);checkSbom(dir);
 return m;
}
async function main(){
 const [mode,dir,...args]=process.argv.slice(2);
 if(!dir||!["build","verify"].includes(mode))throw Error("Invalid release manifest command");
 const [repository,commit,runId,runAttempt,apiImage,databaseImage]=args;
 if(mode==="build"){
  if(args.length!==6)throw Error("Invalid release manifest metadata");
  const m=await buildManifest(dir,{repository,commit,runId,runAttempt,platform:"linux/amd64",apiImage,databaseImage});
  writeFileSync(join(dir,"manifest.json"),JSON.stringify(m)+"\n",{mode:0o600,flag:"wx"});
 }else{
  if(args.length!==4)throw Error("Independent expected candidate identity required");
  await verifyManifest(dir,{repository,commit,runId,runAttempt});
 }
 process.stdout.write("Release candidate manifest "+mode+" completed.\n");
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(()=>{process.stderr.write("Release candidate verification failed; details suppressed.\n");process.exitCode=1;});

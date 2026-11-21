#!/usr/bin/env node
// CI-gated asset-acquisition dossier, not a production release or ownership certificate.
import {createHash} from "node:crypto";
import {readFileSync,openSync,readSync,fstatSync,closeSync,writeFileSync,mkdirSync,readdirSync,constants} from "node:fs";
import {dirname,join,resolve} from "node:path";
import {fileURLToPath} from "node:url";

const ROOT=resolve(dirname(fileURLToPath(import.meta.url)),"..");
const INPUTS=["ProfitPilot_Source.tar.gz","dependencies.cdx.json","acquisition-inventory.json"];
const TARGETS=[...INPUTS,"README.txt","MANIFEST.json","SHA256SUMS"];
const MAX={"ProfitPilot_Source.tar.gz":32*1024*1024,
 "dependencies.cdx.json":10*1024*1024,"acquisition-inventory.json":8*1024*1024,
 "README.txt":32*1024};
const SHA=b=>createHash("sha256").update(b).digest("hex");
const reject=m=>{throw Error("Acquisition dossier refused: "+m);};
const sha40=x=>typeof x==="string"&&/^[a-f0-9]{40}$/.test(x);

function boundedRead(path,max){
 const fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{
  const stat=fstatSync(fd);
  if(!stat.isFile()||stat.size<1||stat.size>max)reject("nonregular, empty or oversized file");
  const out=Buffer.alloc(stat.size+1);
  let count=0;
  while(count<out.length){
   const n=readSync(fd,out,count,out.length-count,null);
   if(n===0)break;
   count+=n;
  }
  if(count!==stat.size||!fstatSync(fd).isFile())reject("source file changed while reading");
  return out.subarray(0,count);
 }finally{closeSync(fd);}
}
function parsedJson(bytes,label){
 try{return JSON.parse(bytes.toString("utf8"));}
 catch{reject("invalid JSON in "+label);}
}
function inputs(dir,sha){
 if(!sha40(sha))reject("40-character hexadecimal Git SHA required");
 const files=new Map();
 for(const name of INPUTS)files.set(name,boundedRead(join(dir,name),MAX[name]));
 if(readdirSync(dir).sort().join("\n")!==[...INPUTS].sort().join("\n"))
  reject("input staging directory contains unexpected files");
 const archive=files.get(INPUTS[0]);
 if(archive.length<128||archive[0]!==0x1f||archive[1]!==0x8b)
  reject("source archive must be a nonempty gzip archive");
 const sbom=parsedJson(files.get(INPUTS[1]),"SBOM");
 if(sbom.bomFormat!=="CycloneDX"||!Array.isArray(sbom.components)||sbom.components.length===0)
  reject("CycloneDX dependency evidence missing");
 const inventory=parsedJson(files.get(INPUTS[2]),"inventory");
 if(inventory.schema!=="profitpilot.acquisition-inventory.b6.v1"||
  inventory.sourceCommit!==sha||inventory.repository!=="SCSoftwareVentures/Profitpilot"||
  inventory.automatedMetadataChecksPassed!==true||
  inventory.ipChainOfTitleVerified!==false||inventory.permissionsTransferAssured!==false||
  inventory.productionReleaseApproved!==false||inventory.realCustomerDemandVerified!==false||
  inventory.saleReadiness!=="PENDING_INDEPENDENT_DUE_DILIGENCE")
   reject("stale or incorrectly qualified acquisition inventory");
 const notice=boundedRead(join(ROOT,"docs/ACQUISITION_NOTICE_B9.txt"),MAX["README.txt"]);
 const t=notice.toString("utf8");
 for(const phrase of ["FICTIONAL","NOT a production release","NOT an IP ownership certificate","NOT proof of customer demand"])
  if(!t.includes(phrase))reject("required buyer warning missing");
 files.set("README.txt",notice);
 return files;
}
function packet(stage,sha){
 const files=inputs(stage,sha);
 const manifest={
  schema:"profitpilot.rc1.b9.source-evidence.v1",
  repository:"SCSoftwareVentures/Profitpilot",
  sourceCommitSha:sha,
  purpose:"unreleased-source-acquisition-due-diligence-only",
  notAProductionRelease:true,
  sourceOwnershipCertified:false,
  thirdPartyLicensesLegallyCleared:false,
  customerDemandValidated:false,
  physicalIphoneSafariTested:false,
  independentSecurityPenetrationTested:false,
  provenanceAttestationContainedInThisManifest:false,
  attestationScope:"GitHub Actions workflow provenance, if separately verified; NOT legal ownership",
  files:Object.fromEntries([...files].map(([name,bytes])=>[name,{bytes:bytes.length,sha256:SHA(bytes)}]))
 };
 const manifestBytes=Buffer.from(JSON.stringify(manifest,null,2)+"\n");
 files.set("MANIFEST.json",manifestBytes);
 files.set("SHA256SUMS",Buffer.from([...files].map(([name,bytes])=>SHA(bytes)+"  "+name).join("\n")+"\n"));
 return {files,manifest};
}
export function runCandidateDossier(operation,stage,out,sha){
 if(!["build","verify"].includes(operation)||!sha40(sha)||
   typeof stage!=="string"||!stage||typeof out!=="string"||!out)
  reject("Usage: build|verify STAGING_DIR OUTPUT_DIR EXACT_GIT_SHA");
 const src=resolve(stage),target=resolve(out);
 if(src===target||target===ROOT||target==="/"||src===ROOT||
   target.length<8||src.length<8)reject("unsafe dossier directories");
 const generated=packet(src,sha);
 if(operation==="build"){
  mkdirSync(target,{recursive:true,mode:0o700});
  if(readdirSync(target).length)reject("refuse nonempty output folder");
  for(const [name,bytes] of generated.files)
   writeFileSync(join(target,name),bytes,{flag:"wx",mode:0o600});
 }
 for(const [name,bytes] of generated.files){
  const actual=boundedRead(join(target,name),Math.max(bytes.length,1));
  if(!actual.equals(bytes))reject("altered dossier file: "+name);
 }
 if(readdirSync(target).sort().join("\n")!==TARGETS.slice().sort().join("\n"))
  reject("dossier contains unexpected or missing files");
 return generated.manifest;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 if(process.argv.length!==6)reject("expected four CLI arguments");
 const [, ,operation,stage,out,sha]=process.argv;
 const m=runCandidateDossier(operation,stage,out,sha);
 process.stdout.write("B9 candidate "+operation+" verified: "+m.sourceCommitSha+
  " (ownership, demand and production status NOT independently verified)\n");
}

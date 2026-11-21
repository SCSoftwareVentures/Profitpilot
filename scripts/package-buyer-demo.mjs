#!/usr/bin/env node
// Produce the exact, dependency-free, synthetic buyer demonstration evaluated by CI.
// Explicitly not a signed release, a customer-data export, or a deployable SaaS.
import {createHash} from "node:crypto";
import {readFileSync,writeFileSync,mkdirSync,readdirSync,openSync,readSync,fstatSync,closeSync,constants} from "node:fs";
import {join,resolve,dirname} from "node:path";
import {fileURLToPath} from "node:url";

const root=resolve(dirname(fileURLToPath(import.meta.url)),"..");
const hash=bytes=>createHash("sha256").update(bytes).digest("hex");
const sha40=x=>typeof x==="string"&&/^[a-f0-9]{40}$/.test(x);
function failure(message){throw Error("Buyer package refused: "+message);}
function readFile(p){return readFileSync(join(root,p));}
function validateDemo(){
 const html=readFile("demo/buyer-walkthrough.html");
 const shell=readFile("demo/buyer-walkthrough.shell.html").toString("utf8");
 const core=readFile("src/buyer-walkthrough-core.js").toString("utf8");
 const marker="/*__BUYER_DEMO_CORE__*/";
 if(shell.split(marker).length!==2)failure("unexpected template marker count");
 const expected=shell.replace(marker,core.replace(/^export (?=(?:const|function)\b)/gm,""));
 if(!html.equals(Buffer.from(expected,"utf8")))failure("standalone file differs from audited source");
 const text=html.toString("utf8");
 const prohibited=["https://","http://","<script src=","fetch(","XMLHttpRequest","navigator.sendBeacon",
  "localStorage","sessionStorage","document.write(","<form"];
 for(const p of prohibited)if(text.includes(p))failure("unreviewed external/dynamic browser capability");
 if(!text.includes("connect-src 'none'")||!text.includes("script-src 'unsafe-inline'")||
  !text.includes("Fictional browser-only")||!text.includes("No approval path in this demonstration")||
  !text.includes("View the current synthetic evidence JSON on this device"))
  failure("missing local-only boundary or truthful buyer disclosure");
 if(html.length>512*1024)failure("oversized standalone demo");
 return html;
}
function packet(sha){
 if(!sha40(sha))failure("40-character Git commit is mandatory");
 const demo=validateDemo();
 const guide=readFile("demo/BUYER_README_B3.txt");
 if(guide.length>16*1024||!guide.toString("utf8").includes("NOT"))
  failure("missing bounded buyer disclosure");
 const manifest={
  schema:"profitpilot.buyer-handoff.b3.v1",
  sourceRepository:"SCSoftwareVentures/Profitpilot",
  sourceCommitSha:sha,
  deliverable:"synthetic-offline-demo-only",
  notAProductionRelease:true,
  customerDataIncluded:false,
  trustedPublisherSignature:false,
  physicalIphoneWebkitTestingPerformed:false,
  verifiedBy:"GitHub Actions required checks; independent third-party QA unperformed",
  files:{
   "ProfitPilot_Buyer_Demo.html":{sha256:hash(demo),bytes:demo.length},
   "README.txt":{sha256:hash(guide),bytes:guide.length}
  }
 };
 const manifestBytes=Buffer.from(JSON.stringify(manifest,null,2)+"\n","utf8");
 const files=new Map([
  ["ProfitPilot_Buyer_Demo.html",demo],
  ["README.txt",guide],
  ["MANIFEST.json",manifestBytes]
 ]);
 const checksums=Buffer.from([...files].map(([name,bytes])=>hash(bytes)+"  "+name).join("\n")+"\n");
 files.set("SHA256SUMS",checksums);
 return {files,manifest};
}
function verifyFiles(out,sha){
 const expected=packet(sha);
 // Open each expected file first. A directory listing is not an access-authority
 // check: checking entries and then opening by path creates a TOCTOU window.
 // Use O_NOFOLLOW and compare via the same verified file descriptor.
 for(const [name,bytes] of expected.files){
  const p=join(out,name);
  // Hold a single no-follow file descriptor through type validation and comparison.
  // O_NONBLOCK prevents a substituted FIFO from blocking the verifier.
  const fd=openSync(p,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  try{
   // Read a bounded amount from the opened no-follow descriptor, then check its type.
   // This avoids a check-then-read race and refuses unbounded file contents.
   const observed=Buffer.alloc(bytes.length+1);
   let count=0;
   while(count<observed.length){
    let n;
    try{n=readSync(fd,observed,count,observed.length-count,null);}
    catch(err){
     if(err?.code==="EISDIR")failure("distribution file altered: "+name);
     throw err;
    }
    if(n===0)break;
    count+=n;
   }
   if(count!==bytes.length||!observed.subarray(0,count).equals(bytes)||
      !fstatSync(fd).isFile())failure("distribution file altered: "+name);
  }finally{closeSync(fd);}
 }
 // Only after examining the expected files, reject extra and missing entries.
 // This inventory is a consistency check, not proof of an immutable directory.
 const items=readdirSync(out).sort();
 if(items.join("\n")!==[...expected.files.keys()].sort().join("\n"))
  failure("distribution has unexpected or missing files");
 return expected.manifest;
}
export function runPackaging(operation,out,sha){
 if(!["build","verify"].includes(operation)||typeof out!=="string"||!out||
  !sha40(sha))failure("Usage: build|verify OUTPUT_DIRECTORY GIT_COMMIT_SHA40");
 const target=resolve(out);
 if(target===root||target==="/"||target.length<8)failure("unsafe distribution directory");
 if(operation==="build"){
  mkdirSync(target,{recursive:true,mode:0o700});
  if(readdirSync(target).length!==0)failure("refuse nonempty output directory");
  for(const [name,bytes] of packet(sha).files)
   writeFileSync(join(target,name),bytes,{flag:"wx",mode:0o600});
 }
 return verifyFiles(target,sha);
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const [operation,out,sha]=process.argv.slice(2);
 if(process.argv.length!==5)failure("three arguments required");
 const manifest=runPackaging(operation,out,sha);
 process.stdout.write("Buyer demo "+operation+" verified for source commit "+
  manifest.sourceCommitSha+"; synthetic only, iPhone QA unperformed\n");
}

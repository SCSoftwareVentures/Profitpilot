#!/usr/bin/env node
// Run from a Git worktree. Output includes only tracked filenames, hashes and package metadata.
import {execFileSync} from "node:child_process";
import {createHash} from "node:crypto";
import {openSync,readSync,fstatSync,closeSync,readFileSync,constants} from "node:fs";
import {dirname,join,resolve} from "node:path";
import {fileURLToPath} from "node:url";
import {buildAcquisitionAssessment} from "../src/buyer-acquisition-audit.js";
const root=resolve(dirname(fileURLToPath(import.meta.url)),"..");
const git=(...args)=>execFileSync("git",["-C",root,...args],{encoding:"utf8",maxBuffer:1024*1024});
function sourceBytes(path){
 // Never check a path and then reopen it: hold the same no-follow descriptor.
 const fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{
  const st=fstatSync(fd);
  if(!st.isFile()||st.size>5*1024*1024)throw Error("Nonregular or oversized tracked source file");
  const buf=Buffer.alloc(st.size+1);
  let count=0;
  while(count<buf.length){
   const n=readSync(fd,buf,count,buf.length-count,null);
   if(n===0)break;
   count+=n;
  }
  if(count!==st.size||!fstatSync(fd).isFile())throw Error("Tracked source file altered during inventory");
  return buf.subarray(0,count);
 }finally{closeSync(fd);}
}
function manifest(){
 const paths=git("ls-files","--cached","-z").split("\0").filter(Boolean);
 if(paths.length>2000)throw Error("Too many tracked paths for bounded buyer inventory");
 return paths.map(path=>{
  if(path.startsWith("/")||path.includes("\\")||path.split("/").some(k=>k===".."||k==="."||!k))
   throw Error("Unsafe Git source path");
  const data=sourceBytes(join(root,path));
  return {path,bytes:data.length,sha256:createHash("sha256").update(data).digest("hex")};
 });
}
export function createLocalBuyerInventory(){
 if(git("status","--porcelain","--untracked-files=no").trim())
  throw Error("Tracked worktree is dirty: inventory requires exact commit content");
 const commit=git("rev-parse","HEAD").trim();
 const pkg=JSON.parse(readFileSync(join(root,"package.json"),"utf8"));
 const lock=JSON.parse(readFileSync(join(root,"package-lock.json"),"utf8"));
 return buildAcquisitionAssessment({packageJson:pkg,packageLock:lock,trackedFiles:manifest(),sourceCommit:commit});
}
const mode=process.argv[2];
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 if(!["--check","--json"].includes(mode)||process.argv.length!==3)
  throw Error("Usage: build-buyer-acquisition-audit.mjs --check|--json");
 const report=createLocalBuyerInventory();
 if(mode==="--json")process.stdout.write(JSON.stringify(report,null,2)+"\n");
 else{
  if(!report.automatedMetadataChecksPassed)
   throw Error("Buyer source/dependency metadata checks failed; inspect --json output");
  process.stdout.write("B6 tracked-file and dependency metadata verified at "+report.sourceCommit+
   "; tracked files="+report.source.fileCount+
   "; third-party packages="+report.npm.resolvedThirdPartyPackageCount+
   "; independent IP, demand and production clearance still UNVERIFIED\n");
 }
}

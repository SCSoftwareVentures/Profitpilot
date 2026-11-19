import {spawn,execFileSync} from "node:child_process";
import {pathToFileURL} from "node:url";
import {inspectTrackedFile} from "./source-security-preflight.js";
const OID=/^[0-9a-f]{40}$/;
const MAX_BLOB=16*1024*1024,MAX_OBJECTS=200000,MAX_BYTES=2*1024*1024*1024;
function git(args,options={}){return execFileSync("git",args,{maxBuffer:64*1024*1024,...options});}
export async function scanHistory({cwd=process.cwd(),emit=()=>{}}={}){
 if(git(["rev-parse","--is-shallow-repository"],{cwd}).toString().trim()!=="false")throw Error("Complete reachable history required");
 const objects=[...new Set(git(["rev-list","--objects","--all","--no-object-names"],{cwd}).toString().trim().split("\n").filter(Boolean))];
 if(!objects.length||objects.length>MAX_OBJECTS||objects.some(x=>!OID.test(x)))throw Error("History object inventory unsupported");
 const metadata=git(["cat-file","--batch-check"],{cwd,input:objects.join("\n")+"\n"}).toString().trim().split("\n");
 if(metadata.length!==objects.length)throw Error("Incomplete object metadata");
 let bytes=0,findings=0;const blobs=[];
 for(let i=0;i<metadata.length;i++){
  const [id,type,size,...rest]=metadata[i].split(" "),n=Number(size);
  if(id!==objects[i]||rest.length||!["blob","tree","commit","tag"].includes(type)||!Number.isSafeInteger(n)||n<0)throw Error("Invalid history object metadata");
  if(type!=="blob")continue;
  if(n>MAX_BLOB||(bytes+=n)>MAX_BYTES)throw Error("History scan bounds exceeded");
  blobs.push({id,size:n});
 }
 // Inspect historical filenames independently from content-deduplicated blobs.
 const paths=git(["log","--all","--format=","--name-only","--no-renames","-z","--"],{cwd}).toString("utf8").split("\0").map(x=>x.replace(/^\n+/,"")).filter(Boolean);
 for(const path of new Set(paths)){
  for(const category of inspectTrackedFile(path,"")){
   findings++;emit({event:"history_filename_finding",category});
  }
 }
 const child=spawn("git",["cat-file","--batch"],{cwd,stdio:["pipe","pipe","pipe"]});
 const done=new Promise((resolve,reject)=>{
  child.once("error",reject);child.once("close",code=>code===0?resolve():reject(Error("Git object reader failed")));
 });
 done.catch(()=>{});child.stderr.resume();child.stdin.on("error",()=>{});
 child.stdin.end(blobs.map(x=>x.id).join("\n")+"\n");
 let pending=Buffer.alloc(0),pos=0,header=false;
 try{
  for await(const chunk of child.stdout){
   pending=Buffer.concat([pending,chunk]);
   while(pos<blobs.length){
    const b=blobs[pos];
    if(!header){
     const i=pending.indexOf(10);
     if(i<0){if(pending.length>160)throw Error("Invalid history object header");break;}
     if(pending.subarray(0,i).toString()!==b.id+" blob "+b.size)throw Error("History object mismatch");
     pending=pending.subarray(i+1);header=true;
    }
    if(pending.length<b.size+1)break;
    if(pending[b.size]!==10)throw Error("Invalid history object terminator");
    const content=pending.subarray(0,b.size).toString("utf8");
    for(const category of inspectTrackedFile("history-content",content)){
     findings++;emit({event:"history_content_finding",object:b.id,category});
    }
    pending=pending.subarray(b.size+1);pos++;header=false;
   }
  }
  await done;
  if(pos!==blobs.length||pending.length!==0||header)throw Error("Incomplete history object stream");
 }catch(e){child.kill();await done.catch(()=>{});throw e;}
 return {objects:objects.length,blobs:pos,bytes,findings};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 scanHistory({emit:e=>process.stderr.write(JSON.stringify(e)+"\n")}).then(report=>{
  process.stdout.write(JSON.stringify({event:"reachable_history_scan",...report})+"\n");
  if(report.findings)process.exitCode=1;
 }).catch(()=>{process.stderr.write("History scan incomplete; release blocked.\n");process.exitCode=1;});
}

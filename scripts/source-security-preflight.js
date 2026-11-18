import {readFileSync,lstatSync} from "node:fs";
import {execFileSync} from "node:child_process";
import {basename} from "node:path";
import {pathToFileURL} from "node:url";

// Narrow, local preflight: no third-party service receives repository contents.
// This recognizes common credential formats, not arbitrary secrets or history.
const markers=[
 ["private key",/-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/],
 ["GitHub token",/\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b/],
 ["AWS access key",/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/],
 ["OpenAI project key",/\bsk-(?:proj|svcacct)-[A-Za-z0-9_-]{40,}\b/],
 ["Slack token",/\bxox[baprs]-[A-Za-z0-9-]{20,}\b/]
];
export function inspectTrackedFile(path,text){
 const findings=[],name=basename(path).toLowerCase();
 if((/^\.env(?:\.|$)/.test(name)&&name!==".env.example")||
 /(?:^id_(?:rsa|ed25519|ecdsa|dsa)$|\.(?:key|p12|pfx|dump|pgdump|bak)$)/.test(name))findings.push("restricted credential or backup filename");
 // PEM marker may appear in literal regex/test expressions, but never as an
 // actual PEM block with a line terminator and base64 payload.
 for(const [type,pattern] of markers){
  if(type==="private key"){
   if(/-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----\r?\n[A-Za-z0-9+/=]{16,}/.test(text))findings.push(type);
  }else if(pattern.test(text))findings.push(type);
 }
 return findings;
}
export function validateLock(manifest,lock){
 if(lock.lockfileVersion!==3||!lock.packages||!lock.packages[""])throw new Error("Expected npm lockfile v3");
 const direct={...(manifest.dependencies||{}),...(manifest.devDependencies||{}),...(manifest.optionalDependencies||{})};
 for(const field of ["dependencies","devDependencies","optionalDependencies"]){
  const declared=manifest[field]||{},locked=lock.packages[""][field]||{};
  if(Object.keys(declared).length!==Object.keys(locked).length||Object.entries(declared).some(([name,version])=>locked[name]!==version))
   throw new Error("Manifest and lockfile root dependencies differ");
 }
 for(const [name,version] of Object.entries(direct)){
  if(typeof version!=="string"||!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version)||lock.packages["node_modules/"+name]?.version!==version)throw new Error("Direct dependencies must use exact locked versions");
 }
 for(const [path,entry] of Object.entries(lock.packages)){
  if(!path)continue;
  const name=path.split("node_modules/").at(-1);
  const namePattern=/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/;
  if(!path.startsWith("node_modules/")||!namePattern.test(name)||!/^(\d+\.\d+\.\d+)(?:-[0-9A-Za-z.-]+)?$/.test(entry.version)||entry.name&&entry.name!==name)
   throw new Error("Dependency identity does not match a locked registry package");
  let url;try{url=new URL(entry.resolved);}catch{throw new Error("Dependency has no valid registry source");}
  if(url.origin!=="https://registry.npmjs.org"||url.username||url.password||url.search||url.hash||url.pathname!=="/"+name+"/-/"+name.split("/").at(-1)+"-"+entry.version+".tgz"||
   typeof entry.integrity!=="string"||!/^sha512-[A-Za-z0-9+/]{86}==$/.test(entry.integrity)||entry.link||entry.hasInstallScript)
    throw new Error("Dependency violates registry integrity or install-script policy");
 }
 return Object.keys(lock.packages).length-1;
}
async function main(){
 const files=execFileSync("git",["ls-files","-z"],{maxBuffer:16*1024*1024}).toString("utf8").split("\0").filter(Boolean);
 let violations=0;
 for(const path of files){
  const stat=lstatSync(path);
  if(!stat.isFile()||stat.size>16*1024*1024){process.stderr.write(JSON.stringify({event:"source_scan_unsupported_file",path})+"\n");violations++;continue;}
  const findings=inspectTrackedFile(path,readFileSync(path).toString("utf8"));
  for(const type of findings){process.stderr.write(JSON.stringify({event:"source_scan_finding",path,type})+"\n");violations++;}
 }
 const count=validateLock(JSON.parse(readFileSync("package.json","utf8")),JSON.parse(readFileSync("package-lock.json","utf8")));
 process.stdout.write(JSON.stringify({event:"source_preflight",files:files.length,lockedDependencies:count,violations})+"\n");
 if(violations)process.exitCode=1;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 main().catch(()=>{process.stderr.write("Source integrity preflight failed; sensitive details suppressed.\n");process.exitCode=1;});
}

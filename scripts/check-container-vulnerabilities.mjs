import {readFileSync} from "node:fs";
const paths=process.argv.slice(2);
if(paths.length!==2)throw Error("Both container reports are required");
let blocked=0;
for(const path of paths){
 const r=JSON.parse(readFileSync(path,"utf8"));
 if(!Array.isArray(r.matches)||!r.source||!r.descriptor)throw Error("Invalid scan report: "+path);
 const counts=Object.create(null);
 for(const match of r.matches){
  const v=match.vulnerability;
  if(!v||typeof v.severity!=="string"||!match.artifact)throw Error("Invalid finding in "+path);
  const severity=v.severity.toUpperCase();
  counts[severity]=(counts[severity]||0)+1;
  const versions=v.fix?.versions||[];
  if(severity==="CRITICAL"||(severity==="HIGH"&&versions.length>0)){
   blocked++;console.error(path,v.id,match.artifact.name,match.artifact.version,versions.join(",")||"no fix");
  }
 }
 console.log(path,JSON.stringify(counts));
}
if(blocked){console.error("Blocking container vulnerability findings:",blocked);process.exitCode=1;}

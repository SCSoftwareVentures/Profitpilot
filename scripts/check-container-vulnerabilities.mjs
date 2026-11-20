import {readFileSync} from "node:fs";
const paths=process.argv.slice(2);
if(paths.length!==2)throw Error("Both container reports are required");
let blocked=0;
for(const path of paths){
 const r=JSON.parse(readFileSync(path,"utf8"));
 if(!Array.isArray(r.Results)||!r.Results.length)throw Error("Missing scan results: "+path);
 const findings=r.Results.flatMap(x=>x.Vulnerabilities||[]);
 const counts=Object.create(null);
 for(const v of findings){
  counts[v.Severity]=(counts[v.Severity]||0)+1;
  // Critical findings always block. High findings with a published fix block.
  // Unfixed high findings remain visible and require buyer risk review.
  if(v.Severity==="CRITICAL"||(v.Severity==="HIGH"&&String(v.FixedVersion||"").trim())){
   blocked++; console.error(path,v.VulnerabilityID,v.PkgName,v.InstalledVersion,v.FixedVersion||"no fix");
  }
 }
 console.log(path,JSON.stringify(counts));
}
if(blocked){console.error("Blocking container vulnerability findings:",blocked);process.exitCode=1;}

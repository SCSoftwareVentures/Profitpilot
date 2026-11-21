import {openSync,fstatSync,readSync,closeSync,constants} from "node:fs";

// Strict CI release gate, not a vulnerability exploitability assessment.
// The exact expected image tags and scan timestamps bind the Grype evidence
// to the two image profiles built by this workflow.
const expected=[
 ["prototype-vulnerabilities.json","profitpilot-api:security"],
 ["protected-vulnerabilities.json","profitpilot-protected:security"]
];
const paths=process.argv.slice(2);
if(paths.length!==2)throw Error("Both container reports are required");
const now=Date.now(),hour=60*60*1000;
const digest=x=>typeof x==="string"&&/^sha256:[0-9a-f]{64}$/.test(x);
const recent=(value,maxAge,label)=>{
 const parsed=typeof value==="string"?Date.parse(value):NaN;
 if(!Number.isFinite(parsed)||parsed>now+5*60*1000||parsed<now-maxAge)
  throw Error("Invalid or stale "+label);
};
const object=x=>x!==null&&typeof x==="object"&&!Array.isArray(x);
const observedImages=new Set();
const expectedIds=[
 process.env.PROFITPILOT_EXPECTED_API_IMAGE_ID,
 process.env.PROFITPILOT_EXPECTED_PROTECTED_IMAGE_ID
];
if(expectedIds.some(x=>!digest(x))||expectedIds[0]===expectedIds[1])
 throw Error("Both distinct Docker-inspected image IDs are required");
let blocked=0;
for(let i=0;i<paths.length;i++){
 const path=paths[i], [canonical,expectedImage]=expected[i];
 if(path!==canonical)throw Error("Expected canonical report "+canonical+" in order");
 // Pin the validated file to a single descriptor. A path-level stat/read
 // introduces a check/use race; a bounded descriptor read cannot follow
 // a substituted symlink or silently expand to an unbounded file.
 const fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW);
 let r;
 try{
  const stat=fstatSync(fd),size=stat.size;
  if(!stat.isFile()||size<=0||size>16*1024*1024)
   throw Error("Invalid scan report size: "+path);
  const bytes=Buffer.alloc(size);
  let offset=0;
  while(offset<size){
   const n=readSync(fd,bytes,offset,size-offset,offset);
   if(n===0)throw Error("Scan report truncated during read: "+path);
   offset+=n;
  }
  if(readSync(fd,Buffer.alloc(1),0,1,size)!==0)
   throw Error("Scan report enlarged during read: "+path);
  r=JSON.parse(bytes.toString("utf8"));
 }finally{closeSync(fd)}
 if(!object(r)||!Array.isArray(r.matches)||!object(r.source)||!object(r.descriptor))
  throw Error("Invalid scan report: "+path);
 const target=r.source.target,descriptor=r.descriptor,config=descriptor.configuration,db=descriptor.db?.status;
 if(r.source.type!=="image"||!object(target)||
   target.userInput!==expectedImage||
   !Array.isArray(target.tags)||!target.tags.includes(expectedImage)||
   !digest(target.imageID)||!digest(target.manifestDigest))
  throw Error("Scan target does not match image profile: "+path);
 if(target.imageID!==expectedIds[i])throw Error("Grype image ID differs from independently inspected Docker image: "+path+" inspected="+expectedIds[i]+" reported="+target.imageID);
 if(observedImages.has(target.imageID))throw Error("Repeated image identity");
 observedImages.add(target.imageID);
 if(descriptor.name!=="grype"||descriptor.version!=="0.104.1"||
   !object(db)||db.valid!==true)
  throw Error("Missing or unverified Grype database or scanner identity");
 recent(descriptor.timestamp,24*hour,"scan timestamp");
 recent(db.built,7*24*hour,"vulnerability database");
 if(!object(config)||config["only-fixed"]!==false||
  config["only-notfixed"]!==false||config["ignore-wontfix"]!==""||
  !Array.isArray(config.exclude)||config.exclude.length>0||
  !Array.isArray(config["vex-documents"])||config["vex-documents"].length>0||
  !Array.isArray(config.ignore)||
  config.ignore.some(rule=>!object(rule)||
   (typeof rule.vulnerability==="string"&&rule.vulnerability.trim()!=="")||
   (typeof rule.reason==="string"&&rule.reason.trim()!=="")||
   rule.package?.type==="apk"))
  throw Error("Vulnerability filter or exclusion detected: "+path);
 if(r.ignoredMatches!==undefined&&(!Array.isArray(r.ignoredMatches)||r.ignoredMatches.length!==0))
  throw Error("Suppressed Grype matches detected: "+path);
 if(!object(r.distro)||r.distro.name!=="alpine")
  throw Error("Unexpected image distribution: "+path);
 const counts=Object.create(null);
 for(const match of r.matches){
  const v=match?.vulnerability,artifact=match?.artifact;
  if(!object(v)||typeof v.severity!=="string"||
    !v.id||!object(artifact)||!artifact.name||!artifact.version)
   throw Error("Invalid finding in "+path);
  const severity=v.severity.toUpperCase();
  counts[severity]=(counts[severity]||0)+1;
  const versions=v.fix?.versions||[];
  if(!["LOW","NEGLIGIBLE"].includes(severity)){
   blocked++;console.error(path,v.id,artifact.name,artifact.version,
    Array.isArray(versions)?versions.join(",")||"no fix":"unverified fix");
  }
 }
 console.log(path,"image",target.imageID,"Grype",descriptor.version,
  "database built",db.built,JSON.stringify(counts));
}
if(blocked){console.error("Blocking container vulnerability findings:",blocked);process.exitCode=1;}

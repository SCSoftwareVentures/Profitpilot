// B6 acquisition inventory: verifiable repository metadata only; never IP or sale clearance.
const OWN_REQUIRED=["README.md","package.json","package-lock.json","Dockerfile",".github/workflows/ci.yml","database/schema.sql","server/index.js","src/buyer-walkthrough-core.js","demo/buyer-walkthrough.html","docs/VALIDATION_GATES.md"];
const LICENCE_NAMES=new Set(["LICENSE","LICENSE.md","LICENSE.txt","LICENCE","LICENCE.md","LICENCE.txt","COPYING","COPYING.md","COPYING.txt"]);
const LICENCE_BUCKETS=["MIT","BSD-2-Clause","BSD-3-Clause","ISC"];
const gate=(name,evidence)=>({name,status:"UNVERIFIED_REQUIRES_HUMAN_EVIDENCE",evidence});
function refuse(msg){throw Error("Buyer inventory rejected: "+msg);}
function obj(v){return v!==null&&typeof v==="object"&&!Array.isArray(v)&&Object.getPrototypeOf(v)===Object.prototype;}
function cleanPath(p){
 if(typeof p!=="string"||!p||p.includes("\\")||p.startsWith("/")||p.includes("\0")||p.split("/").some(s=>!s||s==="."||s===".."))refuse("invalid source path");
 return p;
}
function safeSha(s){return typeof s==="string"&&/^[0-9a-f]{64}$/.test(s);}
export function buildAcquisitionAssessment({packageJson,packageLock,trackedFiles,sourceCommit}){
 if(!obj(packageJson)||!obj(packageLock)||!obj(packageLock.packages)||!obj(packageLock.packages[""]))refuse("package metadata missing");
 if(!/^[0-9a-f]{40}$/.test(sourceCommit||""))refuse("exact source commit required");
 if(packageJson.name!==packageLock.name||packageJson.version!==packageLock.version||packageLock.lockfileVersion!==3)refuse("package-lock root does not match package");
 const a=packageJson.dependencies||{},b=packageLock.packages[""].dependencies||{};
 if(!obj(a)||!obj(b)||Object.keys(a).length!==Object.keys(b).length||
    Object.entries(a).some(([k,v])=>b[k]!==v))refuse("runtime dependency declarations drifted from lock");
 if(!Array.isArray(trackedFiles)||trackedFiles.length===0||trackedFiles.length>2000)refuse("bounded tracked-file manifest required");
 const seen=new Set(),files=[];
 let totalBytes=0;
 for(const f of trackedFiles){
  if(!obj(f))refuse("invalid file record");
  const path=cleanPath(f.path);
  if(seen.has(path))refuse("duplicate source path");
  seen.add(path);
  if(!Number.isSafeInteger(f.bytes)||f.bytes<0||f.bytes>5*1024*1024||!safeSha(f.sha256))refuse("invalid source file digest or length");
  totalBytes+=f.bytes;
  if(totalBytes>64*1024*1024)refuse("source inventory exceeds 64 MiB limit");
  files.push({path,bytes:f.bytes,sha256:f.sha256});
 }
 files.sort((x,y)=>x.path.localeCompare(y.path,"en"));
 const missingCriticalFiles=OWN_REQUIRED.filter(p=>!seen.has(p));
 const sensitiveNamedPaths=files.filter(x=>/(^|\/)(\.env$|\.env\.(?!example$)|id_rsa|id_ed25519|private[-_]key|service[-_]account|credentials(?:\.|$))/i.test(x.path)).map(x=>x.path);
 const licenseFiles=files.filter(x=>LICENCE_NAMES.has(x.path)).map(x=>x.path);
 const transitive=Object.entries(packageLock.packages).filter(([p])=>p).map(([path,v])=>{
  if(!path.startsWith("node_modules/")||!obj(v)||typeof v.version!=="string")refuse("invalid resolved package "+path);
  const license=typeof v.license==="string"&&v.license.trim()?v.license:"UNDECLARED";
  return {path,version:v.version,license,
   integrityPresent:typeof v.integrity==="string"&&v.integrity.startsWith("sha"),
   resolvedSourcePresent:typeof v.resolved==="string"&&v.resolved.length>0};
 });
 transitive.sort((x,y)=>x.path.localeCompare(y.path,"en"));
 const missingDeclared=Object.keys(a).filter(k=>!packageLock.packages["node_modules/"+k]);
 if(missingDeclared.length)refuse("direct dependency missing from lock: "+missingDeclared.join(", "));
 const declaredLicenseCounts=Object.fromEntries(LICENCE_BUCKETS.map(k=>[k,transitive.filter(p=>p.license===k).length]));
 const licenseMetadataReview=transitive.filter(x=>!LICENCE_BUCKETS.includes(x.license)).map(x=>({path:x.path,license:x.license}));
 const unverifiedIntegrity=transitive.filter(x=>!x.integrityPresent||!x.resolvedSourcePresent).map(x=>x.path);
 const machineReadiness=missingCriticalFiles.length===0&&sensitiveNamedPaths.length===0&&licenseMetadataReview.length===0&&unverifiedIntegrity.length===0;
 return {
  schema:"profitpilot.acquisition-inventory.b6.v1",
  repository:"SCSoftwareVentures/Profitpilot",
  sourceCommit,
  inventoryScope:"tracked repository files and npm lock metadata only",
  project:{name:packageJson.name,version:packageJson.version,privatePackage:packageJson.private===true,
   rootLicenseFileFound:licenseFiles.length>0,rootLicenseFiles:licenseFiles},
  source:{fileCount:files.length,totalBytes,missingCriticalFiles,sensitiveNamedPaths,files},
  npm:{lockfileVersion:packageLock.lockfileVersion,directDependencyCount:Object.keys(a).length,
   resolvedThirdPartyPackageCount:transitive.length,declaredLicenseCounts,licenseMetadataReview,
   missingResolvedOrIntegrity:unverifiedIntegrity,packages:transitive},
  automatedMetadataChecksPassed:machineReadiness,
  permissionsTransferAssured:false,
  ipChainOfTitleVerified:false,
  standaloneProjectLicensingCleared:false,
  externalRuntimeImageLicensingCleared:false,
  legalPrivacyComplianceCertified:false,
  realCustomerDemandVerified:false,
  mobileSafariAccessibilityVerified:false,
  sourceProvenanceIndependentlyVerified:false,
  productionReleaseApproved:false,
  saleReadiness:"PENDING_INDEPENDENT_DUE_DILIGENCE",
  unverifiedExternalGates:[
   gate("source ownership and contributor assignments","Copyright chain of title, contributor permissions, external source inventory and licence counsel review"),
   gate("transfer permissions and platform accounts","Written confirmation of repository/account transfer rights and any vendor agreements"),
   gate("container and operating-system components","Docker/Alpine, PostgreSQL and ClamAV licence and redistribution obligations, including notices"),
   gate("dependency licence obligations","Review complete licence texts, notices, attribution and distribution conditions for every package"),
   gate("customer demand and valuation","Independent target-customer evidence, paid demand and negotiated acquirer indications"),
   gate("mobile and accessibility","Physical iPhone Safari/WebKit and assistive technology acceptance checks"),
   gate("production controls","Live deployments, legal and privacy clearance, provider sign-offs and independent security assessment"),
   gate("G0–G5 build authorisation","Independent source/competitive evidence and explicit signed GO"),
   gate("release provenance","Signed source/release provenance for the exact buyer-delivered commit")
  ]
 };
}

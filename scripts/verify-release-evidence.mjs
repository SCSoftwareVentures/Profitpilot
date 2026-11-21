#!/usr/bin/env node
// B17: verify separately provided REVIEW EVIDENCE BYTES against the exact
// digests authenticated by the B13 two-signature proof. Review-only; no deploy.
import {createHash,timingSafeEqual} from "node:crypto";
import {openSync,readSync,fstatSync,closeSync,constants,realpathSync} from "node:fs";
import {resolve,sep,join} from "node:path";
import {fileURLToPath} from "node:url";
import {verifyReleaseReviewFiles} from "./verify-release-review.mjs";

const SOURCE_ROOT=resolve(fileURLToPath(new URL("..",import.meta.url)));
const EVIDENCE_TYPES=["penetrationTest","legalPrivacy","deviceAccessibility","recoveryOperations","ipLicensing"];
const shaRe=/^sha256:[0-9a-f]{64}$/;
const own=(obj,keys)=>obj!==null&&typeof obj==="object"&&!Array.isArray(obj)&&
 Object.getPrototypeOf(obj)===Object.prototype&&
 Object.keys(obj).length===keys.length&&keys.every(k=>Object.hasOwn(obj,k));
const refuse=reason=>{throw Error("Release evidence denied: "+reason);};
const boundedHash=(path,maxSize)=>{
 const resolved=resolve(path);
 const actualPath=realpathSync(resolved);
 if(actualPath===SOURCE_ROOT||actualPath.startsWith(SOURCE_ROOT+sep))
  refuse("review evidence must be external to editable source");
 const fd=openSync(resolved,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{
  const before=fstatSync(fd);
  if(!before.isFile()||before.size<1||before.size>maxSize)
   refuse("nonregular, empty or oversized evidence file");
  const hash=createHash("sha256"),buffer=Buffer.alloc(64*1024);
  let readTotal=0;
  while(readTotal<before.size){
   const n=readSync(fd,buffer,0,Math.min(buffer.length,before.size-readTotal),null);
   if(n===0)refuse("evidence truncated during read");
   hash.update(buffer.subarray(0,n));
   readTotal+=n;
  }
  if(readSync(fd,buffer,0,1,null)!==0)
   refuse("evidence expanded during read");
  const after=fstatSync(fd);
  if(after.size!==before.size||after.ino!==before.ino||after.dev!==before.dev||
     after.mtimeMs!==before.mtimeMs||after.ctimeMs!==before.ctimeMs)
   refuse("evidence changed during reading");
  return {digest:"sha256:"+hash.digest("hex"),identity:String(before.dev)+":"+String(before.ino),bytes:readTotal};
 }finally{closeSync(fd);}
};
export function verifySignedEvidenceFiles(verified,paths,{maxBytes=8*1024*1024}={}){
 if(!verified||verified.schema!=="profitpilot.b13.verified-review.v1"||
   verified.cryptographicSignaturesVerified!==true||
   verified.productionReleaseApproved!==false||
   verified.deploymentAuthorized!==false||
   !own(verified.signedEvidenceDigests,EVIDENCE_TYPES)||
   !own(paths,EVIDENCE_TYPES)||!Number.isSafeInteger(maxBytes)||
   maxBytes<1024||maxBytes>8*1024*1024)
  refuse("signed review and all five independent evidence paths required");
 const identities=new Set(),items=[];
 for(const type of EVIDENCE_TYPES){
  const expected=verified.signedEvidenceDigests[type],path=paths[type];
  if(!shaRe.test(expected)||typeof path!=="string"||!path||path.includes("\0"))
   refuse("malformed evidence path or signed digest for "+type);
  const actual=boundedHash(path,maxBytes);
  if(identities.has(actual.identity))refuse("same evidence file supplied under multiple types");
  identities.add(actual.identity);
  if(!timingSafeEqual(Buffer.from(actual.digest.slice(7),"hex"),Buffer.from(expected.slice(7),"hex")))
   refuse("signed digest mismatch for "+type);
  items.push({type,sha256:actual.digest,bytes:actual.bytes});
 }
 return Object.freeze({
  schema:"profitpilot.b17.evidence-integrity.v1",
  sourceCommit:verified.sourceCommit,reviewProofDigest:verified.signedProofDigest,
  files:items,evidenceByteDigestsMatched:true,
  externalReportAuthenticityVerified:false,
  independentReviewQualityVerified:false,
  independentSignerIdentityVerified:false,
  productionReleaseApproved:false,deploymentAuthorized:false
 });
}
export function verifyReleaseEvidenceFromFiles(expected,env=process.env,now=Date.now()){
 const dir=env.PROFITPILOT_RELEASE_EVIDENCE_DIR;
 if(typeof dir!=="string"||!dir||dir.includes("\0"))
  refuse("external review evidence directory required");
 const verified=verifyReleaseReviewFiles(expected,env,now);
 const paths=Object.fromEntries(EVIDENCE_TYPES.map(type=>[type,join(dir,type+".evidence")]));
 return verifySignedEvidenceFiles(verified,paths);
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 if(process.argv.length!==7)
  refuse("Usage: COMMIT API_IMAGE_DIGEST PROTECTED_IMAGE_DIGEST SOURCE_DOSSIER_DIGEST TICKET");
 const [, ,commitSha,apiImageDigest,protectedImageDigest,sourceDossierDigest,ticket]=process.argv;
 const report=verifyReleaseEvidenceFromFiles({
  repository:"SCSoftwareVentures/Profitpilot",commitSha,apiImageDigest,
  protectedImageDigest,sourceDossierDigest,ticket
 });
 process.stdout.write(JSON.stringify(report)+"\n");
}

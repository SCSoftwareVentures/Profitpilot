#!/usr/bin/env node
// Offline, read-only release-review SIGNATURE verification. Never a deploy action.
// Trusted public key policy and signed approval must come from separately governed
// paths, never user-controlled source files or GitHub Actions build artifacts.
import {openSync,readSync,fstatSync,closeSync,constants} from "node:fs";
import {createHash,timingSafeEqual} from "node:crypto";
import {resolve,sep} from "node:path";
import {fileURLToPath} from "node:url";
import {loadReleaseReviewPolicy,verifyReleaseReview} from "../src/release-authorization.js";

const root=resolve(fileURLToPath(new URL("..",import.meta.url)));
const fail=m=>{throw Error("Release review denied: "+m);};
function safeJson(path,max,expectedSha=null){
 if(typeof path!=="string"||!path||path.includes("\0"))fail("missing trusted file path");
 const filename=resolve(path);
 if(filename===root||filename.startsWith(root+sep))fail("approval material inside editable source tree");
 const fd=openSync(filename,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{
  const st=fstatSync(fd);
  if(!st.isFile()||st.size<1||st.size>max)fail("nonregular or oversized approval file");
  const bytes=Buffer.alloc(st.size+1);
  let offset=0;
  while(offset<bytes.length){
   const n=readSync(fd,bytes,offset,bytes.length-offset,null);
   if(n===0)break;
   offset+=n;
  }
  if(offset!==st.size)fail("approval file changed during read");
  const raw=bytes.subarray(0,offset);
  if(expectedSha!==null){
   if(typeof expectedSha!=="string"||!/^[a-f0-9]{64}$/.test(expectedSha))
    fail("independent pinned key-policy fingerprint required");
   const actual=createHash("sha256").update(raw).digest("hex");
   if(!timingSafeEqual(Buffer.from(expectedSha,"hex"),Buffer.from(actual,"hex")))
    fail("trusted reviewer-key policy fingerprint mismatch");
  }
  let value;
  try{value=JSON.parse(raw.toString("utf8"));}
  catch{fail("malformed approval JSON");}
  return value;
 }finally{closeSync(fd);}
}
export function verifyReleaseReviewFiles(expected,env=process.env,now=Date.now()){
 if(!expected||Object.keys(expected).sort().join("|")!==
  ["apiImageDigest","commitSha","protectedImageDigest","repository","sourceDossierDigest","ticket"].sort().join("|"))
  fail("exact release scope required");
 const policyPath=env.PROFITPILOT_RELEASE_REVIEW_POLICY_FILE;
 const approvalPath=env.PROFITPILOT_RELEASE_REVIEW_BUNDLE_FILE;
 if(!policyPath||!approvalPath||resolve(policyPath)===resolve(approvalPath))
  fail("separate out-of-repository policy and approval files required");
 const pin=env.PROFITPILOT_RELEASE_REVIEW_POLICY_SHA256;
 if(typeof pin!=="string"||!/^[a-f0-9]{64}$/.test(pin))
  fail("independently pinned reviewer policy fingerprint required");
 const policy=loadReleaseReviewPolicy(safeJson(policyPath,16*1024,pin));
 const bundle=safeJson(approvalPath,32*1024);
 return verifyReleaseReview(bundle,policy,expected,now);
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 if(process.argv.length!==7)fail("Usage: COMMIT API_DIGEST SCANNER_DIGEST DOSSIER_DIGEST TICKET");
 const [, ,commitSha,apiImageDigest,protectedImageDigest,sourceDossierDigest,ticket]=process.argv;
 const result=verifyReleaseReviewFiles({repository:"SCSoftwareVentures/Profitpilot",
  commitSha,apiImageDigest,protectedImageDigest,sourceDossierDigest,ticket});
 process.stdout.write(JSON.stringify(result)+"\n");
}

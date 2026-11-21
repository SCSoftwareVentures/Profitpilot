import test from "node:test";
import assert from "node:assert/strict";
import {generateKeyPairSync,randomBytes,createHash,sign} from "node:crypto";
import {mkdtempSync,mkdirSync,writeFileSync,symlinkSync,rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {releaseReviewBytes} from "../src/release-authorization.js";
import {verifyReleaseEvidenceFromFiles,verifySignedEvidenceFiles} from "../scripts/verify-release-evidence.mjs";

const SHA=b=>"sha256:"+createHash("sha256").update(b).digest("hex");
const types=["penetrationTest","legalPrivacy","deviceAccessibility","recoveryOperations","ipLicensing"];
const scope={repository:"SCSoftwareVentures/Profitpilot",commitSha:"a".repeat(40),
 apiImageDigest:"sha256:"+"b".repeat(64),protectedImageDigest:"sha256:"+"c".repeat(64),
 sourceDossierDigest:"sha256:"+"d".repeat(64),ticket:"synthetic-review-B17"};
function fixture(){
 const dir=mkdtempSync(join(tmpdir(),"pp-b17-"));
 const docs=join(dir,"docs");mkdirSync(docs,{mode:0o700});
 const paths={},evidenceDigests={};
 for(const [i,type] of types.entries()){
  const body=Buffer.from("synthetic-only unsigned test report "+type+" "+i);
  paths[type]=join(docs,type+".evidence");writeFileSync(paths[type],body,{mode:0o600});
  evidenceDigests[type]=SHA(body);
 }
 const owner=generateKeyPairSync("ed25519"),reviewer=generateKeyPairSync("ed25519");
 const approvers=[owner,reviewer].map((key,i)=>({
  role:i?"independent-security-reviewer":"owner",
  keyId:i?"security-test":"owner-test",
  publicKeyPem:key.publicKey.export({type:"spki",format:"pem"})
 }));
 const policy={format:"profitpilot.b13.pinned-reviewers.v1",approvers};
 const now=Date.now();
 const request={schema:"profitpilot.b13.review-request.v1",...scope,
  nonce:randomBytes(16).toString("hex"),issuedAt:new Date(now-1000).toISOString(),
  expiresAt:new Date(now+600000).toISOString(),
  purpose:"source-candidate-independent-review",evidenceDigests,noDeployment:true};
 const body=releaseReviewBytes(request);
 const bundle={request,signatures:[owner,reviewer].map((key,i)=>({
  role:approvers[i].role,keyId:approvers[i].keyId,
  signature:sign(null,body,key.privateKey).toString("base64")
 }))};
 const policyFile=join(dir,"policy.json"),bundleFile=join(dir,"bundle.json");
 const policyBytes=JSON.stringify(policy);
 writeFileSync(policyFile,policyBytes,{mode:0o600});
 writeFileSync(bundleFile,JSON.stringify(bundle),{mode:0o600});
 const env={PROFITPILOT_RELEASE_REVIEW_POLICY_FILE:policyFile,
  PROFITPILOT_RELEASE_REVIEW_BUNDLE_FILE:bundleFile,
  PROFITPILOT_RELEASE_REVIEW_POLICY_SHA256:SHA(policyBytes).slice(7),
  PROFITPILOT_RELEASE_EVIDENCE_DIR:docs};
 return {dir,paths,docs,env,bundle,policy};
}
function withFixture(fn){
 const f=fixture();
 try{return fn(f);}finally{rmSync(f.dir,{recursive:true,force:true});}
}
test("B17 binds real five external report byte streams to two separately pinned signatures",()=>{
 withFixture(f=>{
  const result=verifyReleaseEvidenceFromFiles(scope,f.env);
  assert.equal(result.schema,"profitpilot.b17.evidence-integrity.v1");
  assert.equal(result.evidenceByteDigestsMatched,true);
  assert.equal(result.files.length,5);
  assert.equal(result.sourceCommit,scope.commitSha);
  for(const k of ["externalReportAuthenticityVerified","independentReviewQualityVerified",
   "independentSignerIdentityVerified","productionReleaseApproved","deploymentAuthorized"])
   assert.equal(result[k],false);
 });
});
test("B17 fails closed on changed evidence, incomplete files and substituted report paths",()=>{
 withFixture(f=>{
  writeFileSync(f.paths.penetrationTest,"different content", {mode:0o600});
  assert.throws(()=>verifyReleaseEvidenceFromFiles(scope,f.env),/signed digest mismatch/);
 });
 withFixture(f=>{
  rmSync(f.paths.ipLicensing);
  assert.throws(()=>verifyReleaseEvidenceFromFiles(scope,f.env));
 });
 withFixture(f=>{
  const renamed=f.paths.legalPrivacy,old=f.paths.recoveryOperations;
  rmSync(renamed);symlinkSync(old,renamed);
  assert.throws(()=>verifyReleaseEvidenceFromFiles(scope,f.env));
 });
});
test("B17 rejects untrusted review policy changes, altered scope and rewritten signed evidence claims",()=>{
 withFixture(f=>{
  assert.throws(()=>verifyReleaseEvidenceFromFiles({...scope,commitSha:"f".repeat(40)},f.env),/not bound/);
  assert.throws(()=>verifyReleaseEvidenceFromFiles(scope,{...f.env,
   PROFITPILOT_RELEASE_REVIEW_POLICY_SHA256:"f".repeat(64)}),/fingerprint mismatch/);
  const bad={...f.bundle,request:{...f.bundle.request,evidenceDigests:{
   ...f.bundle.request.evidenceDigests,legalPrivacy:SHA("forgery")}}};
  writeFileSync(f.env.PROFITPILOT_RELEASE_REVIEW_BUNDLE_FILE,JSON.stringify(bad));
  assert.throws(()=>verifyReleaseEvidenceFromFiles(scope,f.env),/invalid signature/);
 });
});
test("B17 rejects missing directory and obviously incomplete or forged verified-review shape",()=>{
 withFixture(f=>{
  assert.throws(()=>verifyReleaseEvidenceFromFiles(scope,{...f.env,
   PROFITPILOT_RELEASE_EVIDENCE_DIR:""}),/external review evidence/);
  assert.throws(()=>verifySignedEvidenceFiles({},f.paths),/signed review/);
  assert.throws(()=>verifySignedEvidenceFiles({schema:"profitpilot.b13.verified-review.v1",
   cryptographicSignaturesVerified:true,productionReleaseApproved:true,
   deploymentAuthorized:false,signedEvidenceDigests:f.bundle.request.evidenceDigests},f.paths),/signed review/);
 });
});

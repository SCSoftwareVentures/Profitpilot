import test from "node:test";
import assert from "node:assert/strict";
import {createHash,generateKeyPairSync,randomBytes,sign} from "node:crypto";
import {loadReleaseReviewPolicy,releaseReviewBytes,verifyReleaseReview} from "../src/release-authorization.js";

const person=()=>generateKeyPairSync("ed25519");
const owner=person(),security=person(),untrusted=person();
const pem=k=>k.export({type:"spki",format:"pem"});
const dg=char=>"sha256:"+char.repeat(64);
const sha40="a".repeat(40);
const expected={repository:"SCSoftwareVentures/Profitpilot",commitSha:sha40,
 apiImageDigest:dg("b"),protectedImageDigest:dg("c"),sourceDossierDigest:dg("d"),
 ticket:"security.release-001"};
function signedRequest(changes={},keys=[owner.privateKey,security.privateKey]){
 const now=Date.now();
 const request={
  schema:"profitpilot.b13.review-request.v1",...expected,
  nonce:randomBytes(16).toString("hex"),
  issuedAt:new Date(now-1000).toISOString(),
  expiresAt:new Date(now+600000).toISOString(),
  purpose:"source-candidate-independent-review",
  evidenceDigests:{penetrationTest:dg("1"),legalPrivacy:dg("2"),
   deviceAccessibility:dg("3"),recoveryOperations:dg("4"),ipLicensing:dg("5")},
  noDeployment:true,...changes
 };
 const message=releaseReviewBytes(request);
 const roles=["owner","independent-security-reviewer"],ids=["owner-approved","security-approved"];
 return {request,signatures:roles.map((role,i)=>({
  role,keyId:ids[i],signature:sign(null,message,keys[i]).toString("base64")
 }))};
}
const policyJson={format:"profitpilot.b13.pinned-reviewers.v1",approvers:[
 {role:"owner",keyId:"owner-approved",publicKeyPem:pem(owner.publicKey)},
 {role:"independent-security-reviewer",keyId:"security-approved",publicKeyPem:pem(security.publicKey)}
]};
const policy=loadReleaseReviewPolicy(policyJson);

test("B13 two independent scoped signatures verify but never certify external assurance",()=>{
 const bundle=signedRequest(),out=verifyReleaseReview(bundle,policy,expected);
 assert.equal(out.cryptographicSignaturesVerified,true);
 assert.equal(out.signers.length,2);
 assert.equal(out.sourceCommit,sha40);
 assert.equal(out.signedProofDigest.length,64);
 for(const field of ["independentHumanIdentityVerified","externalEvidenceIndependentlyAssessed",
  "productionReleaseApproved","deploymentAuthorized","actualBuyerDemandVerified"])
  assert.equal(out[field],false);
});

test("B13 requires exact commit, both image digests, dossier digest and change ticket",()=>{
 const b=signedRequest();
 for(const [key,value] of Object.entries({...expected,apiImageDigest:dg("9")})){
  if(value===expected[key])continue;
  assert.throws(()=>verifyReleaseReview(b,policy,{...expected,[key]:value}),/not bound/);
 }
 for(const key of ["commitSha","apiImageDigest","protectedImageDigest","sourceDossierDigest","ticket"]){
  const forged={...expected,[key]:key==="ticket"?"other-ticket":key==="commitSha"?"f".repeat(40):dg("f")};
  assert.throws(()=>verifyReleaseReview(b,policy,forged),/not bound/);
 }
});
test("B13 rejects altered evidence and forged second signature",()=>{
 const b=signedRequest();
 const changed={...b,request:{...b.request,evidenceDigests:{...b.request.evidenceDigests,penetrationTest:dg("f")}}};
 assert.throws(()=>verifyReleaseReview(changed,policy,expected),/invalid signature/);
 const forged=signedRequest({},[owner.privateKey,untrusted.privateKey]);
 assert.throws(()=>verifyReleaseReview(forged,policy,expected),/invalid signature/);
 assert.throws(()=>verifyReleaseReview({...b,signatures:[b.signatures[0],b.signatures[0]]},policy,expected));
 assert.throws(()=>verifyReleaseReview({...b,signatures:[b.signatures[0]]},policy,expected));
});

test("B13 rejects one key for two reviewers or duplicate key IDs",()=>{
 const shared={...policyJson,approvers:[
  policyJson.approvers[0],
  {...policyJson.approvers[1],publicKeyPem:policyJson.approvers[0].publicKeyPem}
 ]};
 assert.throws(()=>loadReleaseReviewPolicy(shared),/same signing key/);
 assert.throws(()=>loadReleaseReviewPolicy({...policyJson,approvers:[
  policyJson.approvers[0],{...policyJson.approvers[1],keyId:"owner-approved"}
 ]}),/duplicate/);
 assert.throws(()=>loadReleaseReviewPolicy({...policyJson,approvers:[
  {...policyJson.approvers[0],publicKeyPem:pem(generateKeyPairSync("rsa",{modulusLength:2048}).publicKey)},
  policyJson.approvers[1]
 ]}),/Ed25519/);
});

test("B13 fails closed on expired, backdated, future and overbroad review windows",()=>{
 const q=signedRequest();
 const start=Date.parse(q.request.issuedAt);
 assert.throws(()=>verifyReleaseReview(q,policy,expected,start+700000),/expired/);
 const future=signedRequest({issuedAt:new Date(Date.now()+120000).toISOString(),
   expiresAt:new Date(Date.now()+240000).toISOString()});
 assert.throws(()=>verifyReleaseReview(future,policy,expected),/expired/);
 const old=signedRequest({issuedAt:new Date(Date.now()-7200000).toISOString()});
 assert.throws(()=>verifyReleaseReview(old,policy,expected),/expired/);
 const long=signedRequest({expiresAt:new Date(Date.now()+7200000).toISOString()});
 assert.throws(()=>verifyReleaseReview(long,policy,expected),/expired/);
});

test("B13 rejects malformed request shape, duplicate or missing evidence, noncanonical dates and nonreview purpose",()=>{
 const b=signedRequest();
 const bad=[
  {purpose:"production-deploy"},
  {noDeployment:false},
  {schema:"unexpected"},
  {evidenceDigests:{...b.request.evidenceDigests,missing:"x"}},
  {evidenceDigests:{...b.request.evidenceDigests,legalPrivacy:"unverified"}},
  {issuedAt:"2026-02-30T00:00:00.000Z"},
  {apiImageDigest:b.request.protectedImageDigest}
 ];
 for(const changes of bad)
  assert.throws(()=>releaseReviewBytes({...b.request,...changes}),/Invalid or incomplete/);
 const changed={...b,request:{...b.request,nonce:"X".repeat(32)}};
 assert.throws(()=>verifyReleaseReview(changed,policy,expected));
});

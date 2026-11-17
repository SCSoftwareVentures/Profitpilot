import test from "node:test";
import assert from "node:assert/strict";
import {generateKeyPairSync,sign} from "node:crypto";
import {requiredReleaseControls,releaseSigningBytes,verifyReleaseApproval,releaseConfigDigest,releaseStillApproved,readProductionReleaseApproval} from "../server/release-approval.js";
const technical=generateKeyPairSync("ed25519"),privacy=generateKeyPairSync("ed25519");
const pub=k=>k.publicKey.export({format:"der",type:"spki"}).toString("base64url");
const now=Date.parse("2026-11-17T00:00:00Z"),buildRevision="a".repeat(40),deploymentId="synthetic-ci",configurationDigest="b".repeat(64);
const options={buildRevision,deploymentId,configurationDigest,technicalPublicKey:pub(technical),privacyPublicKey:pub(privacy),now};
function payload(patch={}){
 return {version:1,buildRevision,deploymentId,configurationDigest,issuedAt:new Date(now-1000).toISOString(),expiresAt:new Date(now+86400000).toISOString(),controls:Object.fromEntries(requiredReleaseControls.map(id=>[id,{status:"verified",evidenceSha256:"c".repeat(64)}])),...patch};
}
function signed(p,key2=privacy){
 const body=JSON.stringify(p);
 return {payload:body,technicalSignature:sign(null,releaseSigningBytes(body,"technical"),technical.privateKey).toString("base64url"),privacySignature:sign(null,releaseSigningBytes(body,"privacy"),key2.privateKey).toString("base64url")};
}
test("only complete independent, exact release evidence succeeds and expires",()=>{
 const ok=verifyReleaseApproval(signed(payload()),options);
 assert.equal(ok.verified,true);assert.equal(ok.buildRevision,buildRevision);
 assert.equal(releaseStillApproved(ok,now),true);assert.equal(releaseStillApproved(ok,ok.expiresAt),false);
 assert.equal(readProductionReleaseApproval({NODE_ENV:"test"}),null);
 assert.throws(()=>readProductionReleaseApproval({NODE_ENV:"production"}),/Production release evidence/);
});
test("missing controls, stale approvals, altered evidence, scope mismatch and shared approval keys are denied",()=>{
 const original=signed(payload());
 for(const candidate of [
  {...original,payload:original.payload.replace("verified","rejected")},
  {...original,privacySignature:original.technicalSignature},
  {...original,unexpected:"field"},
  signed(payload({buildRevision:"f".repeat(40)})),
  signed(payload({deploymentId:"other-target"})),
  signed(payload({configurationDigest:"e".repeat(64)})),
  signed(payload({expiresAt:new Date(now).toISOString()})),
  signed(payload({issuedAt:new Date(now+1000).toISOString()})),
  signed(payload({expiresAt:new Date(now+31*86400000).toISOString()})),
  signed(payload({controls:{}})),
  signed(payload({controls:{...payload().controls,independent_penetration_retest:{status:"pending",evidenceSha256:"c".repeat(64)}}})),
  signed(payload({controls:{...payload().controls,privacy_retention_and_processors:{status:"verified",evidenceSha256:"0".repeat(64)}}}))
 ])assert.throws(()=>verifyReleaseApproval(candidate,options),/Production release evidence/);
 assert.throws(()=>verifyReleaseApproval(signed(payload(),technical),{...options,privacyPublicKey:pub(technical)}),/Production release evidence/);
});
test("configuration fingerprint excludes secrets and notices security-scope changes",()=>{
 const env={DATABASE_URL:"postgresql://profitpilot_app:synthetic@db.example.invalid/profitpilot",DATABASE_SSL:"true",AUTH_ISSUER:"https://id.example.invalid/",AUTH_AUDIENCE:"profitpilot-api",AUTH_JWKS_URL:"https://id.example.invalid/jwks",AUTH_STEP_UP_ACR:"urn:synthetic:mfa",CORS_ORIGIN:"https://app.example.invalid",TENANT_CONTEXT_HMAC_SECRET:"synthetic-secret"};
 const first=releaseConfigDigest(env);
 assert.equal(releaseConfigDigest({...env,DATABASE_URL:env.DATABASE_URL.replace(":synthetic@",":other-secret@"),TENANT_CONTEXT_HMAC_SECRET:"other-secret"}),first);
 for(const change of [{AUTH_AUDIENCE:"another-api"},{AUTH_ISSUER:"https://other.example.invalid"},{CORS_ORIGIN:"https://other.example.invalid"},{TENANT_CONTEXT_HMAC_KEY_ID:"next"}])assert.notEqual(releaseConfigDigest({...env,...change}),first);
});

#!/usr/bin/env node
// Generates disposable CI-only Ed25519 keys and signed synthetic requests.
// NEVER commit generated files, use for real evidence, or infer real operator identities.
import {generateKeyPairSync,randomUUID} from "node:crypto";
import {writeFileSync} from "node:fs";
import {join} from "node:path";
import {signRecoveryApprovalRequest} from "../../src/securepay-recovery-controls.js";
const dir=process.argv[2];
if(process.env.NODE_ENV!=="test"||process.env.GITHUB_ACTIONS!=="true"||!dir||process.argv.length!==3)
 throw Error("CI-only synthetic approval generation");
const pair=()=>generateKeyPairSync("ed25519");
const custodian=pair(),privacy=pair(),audit=pair();
const publicPem=k=>k.export({type:"spki",format:"pem"});
const privatePem=k=>k.export({type:"pkcs8",format:"pem"});
const save=(file,value)=>writeFileSync(join(dir,file),value,{mode:0o600,flag:"wx"});
const policy={format:"profitpilot.s11.3.approvers.v1",approvers:[
 {role:"custodian",keyId:"ci-2026-custodian",publicKeyPem:publicPem(custodian.publicKey)},
 {role:"privacy-reviewer",keyId:"ci-2026-privacy",publicKeyPem:publicPem(privacy.publicKey)}
]};
save("recovery-approvers.json",JSON.stringify(policy));
save("recovery-audit-private.pem",privatePem(audit.privateKey));
save("recovery-audit-public.pem",publicPem(audit.publicKey));
const common={version:"profitpilot.s11.3.request.v1",
 tenantId:"abababab-abab-4bab-8bab-abababababab",
 operatorId:"efefefef-efef-4fef-8fef-efefefefefef",
 issuedAt:new Date(Date.now()-30000).toISOString(),
 expiresAt:new Date(Date.now()+2700000).toISOString(),
 purpose:"synthetic-offline-integrity-rehearsal",legalHoldState:"no_declared_hold",
 retentionStatus:"unverified_review_only",syntheticOnly:true};
for(const [file,ticketRef] of [
 ["recovery-approval-good.json","ci.s11-2.restored"],
 ["recovery-approval-wrongkey.json","ci.s11-2.wrongkey"]
]){
 const request={...common,ticketRef,requestId:randomUUID()};
 const signatures=[
  {role:"custodian",keyId:"ci-2026-custodian",signature:signRecoveryApprovalRequest(request,custodian.privateKey)},
  {role:"privacy-reviewer",keyId:"ci-2026-privacy",signature:signRecoveryApprovalRequest(request,privacy.privateKey)}
 ];
 save(file,JSON.stringify({request,signatures}));
}

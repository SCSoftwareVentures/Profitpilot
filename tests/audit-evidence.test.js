import test from "node:test";
import assert from "node:assert/strict";
import {generateKeyPairSync} from "node:crypto";
import {mkdtempSync,writeFileSync,rmSync} from "node:fs";
import {join} from "node:path";
import {tmpdir} from "node:os";
import {spawnSync} from "node:child_process";
import {buildAuditManifest,signAuditManifest,verifyAuditCheckpoint,assertCheckpointMatchesRows,loadAuditRows} from "../src/audit-evidence.js";
const TENANT="11111111-1111-4111-8111-111111111111";
const id=n=>"33333333-3333-4333-8333-"+String(n).padStart(12,"0");
const row=(n,metadata="{}")=>({id:id(n),tenant_id:TENANT,actor_user_id:id(11),action:"calculation_created",
 object_type:"calculation_run",object_id:id(21),reason:null,correlation_id:null,metadata,
 created_at:"2026-11-20T12:00:00.000001Z"});
test("Ed25519 audit snapshot is deterministic, detects tampering and verifies offline",()=>{
 const {privateKey,publicKey}=generateKeyPairSync("ed25519");
 const rows=[row(1),row(2)];
 const manifest=buildAuditManifest(TENANT,rows,{capturedAt:"2026-11-20T12:01:00.000Z"});
 const bundle=signAuditManifest(manifest,privateKey);
 assert.deepEqual(verifyAuditCheckpoint(bundle,publicKey),manifest);
 assert.equal(assertCheckpointMatchesRows(bundle,publicKey,rows),true);
 assert.throws(()=>assertCheckpointMatchesRows(bundle,publicKey,[row(1,'{"tampered":true}'),row(2)]));
 assert.throws(()=>assertCheckpointMatchesRows(bundle,publicKey,[row(1)]));
 assert.throws(()=>assertCheckpointMatchesRows(bundle,publicKey,[row(2),row(1)]));
 assert.throws(()=>buildAuditManifest(TENANT,[row(1),row(1)]));
 assert.throws(()=>buildAuditManifest(TENANT,[{...row(1),tenant_id:id(12)}]));
 const bad=structuredClone(bundle);bad.manifest.entries[0].digest="f".repeat(64);
 assert.throws(()=>verifyAuditCheckpoint(bad,publicKey));
 const wrong=generateKeyPairSync("ed25519").publicKey;
 assert.throws(()=>verifyAuditCheckpoint(bundle,wrong));
 assert.ok(!JSON.stringify(bundle).includes("calculation_created"));
});
test("offline checkpoint CLI verifies without private key or database access",()=>{
 const {privateKey,publicKey}=generateKeyPairSync("ed25519");
 const bundle=signAuditManifest(buildAuditManifest(TENANT,[row(1)]),privateKey);
 const dir=mkdtempSync(join(tmpdir(),"pp-audit-proof-"));
 try{
  const proof=join(dir,"proof.json"),pub=join(dir,"pub.pem");
  writeFileSync(proof,JSON.stringify(bundle));writeFileSync(pub,publicKey.export({type:"spki",format:"pem"}));
  const ok=spawnSync(process.execPath,["scripts/audit-checkpoint.mjs","verify",proof,pub],{encoding:"utf8",timeout:10000});
  assert.equal(ok.status,0,ok.stderr);
  const edited=structuredClone(bundle);edited.manifest.count=2;writeFileSync(proof,JSON.stringify(edited));
  const no=spawnSync(process.execPath,["scripts/audit-checkpoint.mjs","verify",proof,pub],{encoding:"utf8",timeout:10000});
  assert.equal(no.status,1);
 }finally{rmSync(dir,{recursive:true,force:true});}
});
test("database loader requires tenant predicate and consistent microsecond ordering",async()=>{
 const stub={query:async(sql,args)=>{
  assert.match(sql,/tenant_id=\$1/);assert.match(sql,/ORDER BY created_at,id/);assert.deepEqual(args,[TENANT]);return {rows:[row(1)]};
 }};
 const rows=await loadAuditRows(stub,TENANT);assert.equal(rows.length,1);
});

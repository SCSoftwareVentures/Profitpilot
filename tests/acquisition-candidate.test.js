import test from "node:test";
import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {syntheticTar,syntheticInventory,syntheticSbom} from "./fixtures/source-handoff-synthetic.js";
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,readdirSync,rmSync,symlinkSync} from "node:fs";
import {join} from "node:path";
import {tmpdir} from "node:os";
import {runCandidateDossier} from "../scripts/package-acquisition-candidate.mjs";
const sha="a".repeat(40);
const digest=b=>createHash("sha256").update(b).digest("hex");
function evidence(){
 const root=mkdtempSync(join(tmpdir(),"profitpilot-b9-"));
 const staging=join(root,"staging"),out=join(root,"out");
 mkdirSync(staging);
 const inventory={
  ...syntheticInventory(),
  schema:"profitpilot.acquisition-inventory.b6.v1",
  repository:"SCSoftwareVentures/Profitpilot",
  sourceCommit:sha,
  automatedMetadataChecksPassed:true,
  ipChainOfTitleVerified:false,
  permissionsTransferAssured:false,
  productionReleaseApproved:false,
  realCustomerDemandVerified:false,
  saleReadiness:"PENDING_INDEPENDENT_DUE_DILIGENCE"
 };
 const sbom=syntheticSbom();
 writeFileSync(join(staging,"ProfitPilot_Source.tar.gz"),syntheticTar());
 writeFileSync(join(staging,"dependencies.cdx.json"),JSON.stringify(sbom));
 writeFileSync(join(staging,"acquisition-inventory.json"),JSON.stringify(inventory));
 return {root,staging,out,inventory,sbom};
}
test("B9 generates a bounded, exact six-file dossier without declaring a commercial or legal clearance",()=>{
 const e=evidence();
 try{
  const m=runCandidateDossier("build",e.staging,e.out,sha);
  assert.equal(m.sourceCommitSha,sha);
  assert.equal(m.notAProductionRelease,true);
  assert.equal(m.sourceOwnershipCertified,false);
  assert.equal(m.customerDemandValidated,false);
  assert.equal(m.independentSecurityPenetrationTested,false);
  assert.equal(m.provenanceAttestationContainedInThisManifest,false);
  assert.deepEqual(readdirSync(e.out).sort(),[
   "ProfitPilot_Source.tar.gz","dependencies.cdx.json","acquisition-inventory.json",
   "README.txt","MANIFEST.json","SHA256SUMS"].sort());
  assert.deepEqual(runCandidateDossier("verify",e.staging,e.out,sha),m);
  const checksums=readFileSync(join(e.out,"SHA256SUMS"),"utf8");
  for(const file of Object.keys(m.files))assert.ok(checksums.includes(digest(readFileSync(join(e.out,file)))+"  "+file));
  assert.match(readFileSync(join(e.out,"README.txt"),"utf8"),/NOT proof of customer demand/);
  assert.throws(()=>runCandidateDossier("build",e.staging,e.out,sha),/nonempty/);
 }finally{rmSync(e.root,{recursive:true,force:true});}
});
test("B9 rejects wrong source commits, contradictory title claims and invalid SBOM",()=>{
 const e=evidence();
 try{
  assert.throws(()=>runCandidateDossier("build",e.staging,e.out,"bad"),/Usage/);
  assert.throws(()=>runCandidateDossier("build",e.staging,e.out,"b".repeat(40)),/stale/);
  const file=join(e.staging,"acquisition-inventory.json");
  writeFileSync(file,JSON.stringify({...e.inventory,ipChainOfTitleVerified:true}));
  assert.throws(()=>runCandidateDossier("build",e.staging,e.out,sha),/stale/);
  writeFileSync(file,JSON.stringify(e.inventory));
  writeFileSync(join(e.staging,"dependencies.cdx.json"),JSON.stringify({bomFormat:"CycloneDX",components:[]}));
  assert.throws(()=>runCandidateDossier("build",e.staging,e.out,sha),/CycloneDX/);
 }finally{rmSync(e.root,{recursive:true,force:true});}
});
test("B9 refuses corrupted, absent or extra output and unexpected staging files",()=>{
 const e=evidence();
 try{
  runCandidateDossier("build",e.staging,e.out,sha);
  writeFileSync(join(e.out,"README.txt"),"false claims");
  assert.throws(()=>runCandidateDossier("verify",e.staging,e.out,sha),/dossier file/);
  rmSync(e.out,{recursive:true,force:true});
  runCandidateDossier("build",e.staging,e.out,sha);
  writeFileSync(join(e.out,"extraneous-data.txt"),"other");
  assert.throws(()=>runCandidateDossier("verify",e.staging,e.out,sha),/unexpected/);
  rmSync(e.out,{recursive:true,force:true});
  writeFileSync(join(e.staging,"extra.json"),"false");
  assert.throws(()=>runCandidateDossier("build",e.staging,e.out,sha),/unexpected/);
 }finally{rmSync(e.root,{recursive:true,force:true});}
});
test("B9 refuses symlink substitutions and missing gzip magic",()=>{
 const e=evidence();
 try{
  rmSync(join(e.staging,"ProfitPilot_Source.tar.gz"));
  symlinkSync(join(e.staging,"dependencies.cdx.json"),join(e.staging,"ProfitPilot_Source.tar.gz"));
  assert.throws(()=>runCandidateDossier("build",e.staging,e.out,sha),/ELOOP|symbolic link/i);
  rmSync(join(e.staging,"ProfitPilot_Source.tar.gz"));
  writeFileSync(join(e.staging,"ProfitPilot_Source.tar.gz"),Buffer.alloc(256,65));
  assert.throws(()=>runCandidateDossier("build",e.staging,e.out,sha),/gzip/);
 }finally{rmSync(e.root,{recursive:true,force:true});}
});
test("B9 CI release-candidate job is gated and cannot run on main or a PR event",async()=>{
 const {readFileSync}=await import("node:fs");
 const {resolve}=await import("node:path");
 const {fileURLToPath}=await import("node:url");
 const root=resolve(fileURLToPath(new URL("..",import.meta.url)));
 const content=readFileSync(resolve(root,".github/workflows/ci.yml"),"utf8");
 assert.match(content,/buyer_candidate:\n    name: Draft source-acquisition candidate and verified provenance/);
 assert.match(content,/needs: \[verify, database, static_analysis, container_security, compose_rehearsal\]/);
 assert.match(content,/github\.ref == 'refs\/heads\/feature\/release-b9-buyer-source-dossier'/);
 assert.match(content,/github\.event_name == 'push'/);
 assert.match(content,/gh attestation verify/);
});

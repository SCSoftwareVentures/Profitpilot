import test from "node:test";
import assert from "node:assert/strict";
import {mkdtempSync,writeFileSync,readFileSync,rmSync,symlinkSync} from "node:fs";
import {join} from "node:path";
import {tmpdir} from "node:os";
import {buildManifest,verifyManifest,FILES,expectedRepository} from "../scripts/release-candidate-manifest.js";
const meta={repository:expectedRepository(),commit:"a".repeat(40),runId:"123",runAttempt:"1",platform:"linux/amd64",apiImage:"sha256:"+"a".repeat(64),databaseImage:"sha256:"+"b".repeat(64)};
const expected={repository:meta.repository,commit:meta.commit,runId:meta.runId,runAttempt:meta.runAttempt};
function fixture(){
 const dir=mkdtempSync(join(tmpdir(),"pp-candidate-"));const put=(name,data)=>writeFileSync(join(dir,name),typeof data==="string"?data:JSON.stringify(data));
 for(const file of FILES)put(file,"synthetic "+file);
 const scan=(id)=>({SchemaVersion:2,ArtifactType:"container_image",Metadata:{ImageID:id},Results:[{Target:"fixture"}]});
 put("api-scan.json",scan(meta.apiImage));put("database-scan.json",scan(meta.databaseImage));put("sbom.json",{bomFormat:"CycloneDX",components:[{name:"synthetic"}]});
 const seal=async()=>{const manifest=await buildManifest(dir,meta);put("manifest.json",manifest);return manifest;};
 return {dir,put,seal,scan,dispose:()=>rmSync(dir,{recursive:true,force:true})};
}
test("candidate manifest detects substituted artifacts, mismatched run or commit and extra files",async()=>{
 const f=fixture();
 try{
  const m=await f.seal();assert.deepEqual(await verifyManifest(f.dir,expected),m);
  for(const bad of [{commit:"b".repeat(40)},{repository:"wrong/repo"},{runId:"124"},{runAttempt:"2"}])await assert.rejects(()=>verifyManifest(f.dir,{...expected,...bad}));
  f.put("api-image.tar.gz","changed");await assert.rejects(()=>verifyManifest(f.dir,expected),/digest mismatch/);
  f.put("api-image.tar.gz","synthetic api-image.tar.gz");
  f.put("extra.txt","extra");await assert.rejects(()=>verifyManifest(f.dir,expected),/inventory/);
  rmSync(join(f.dir,"extra.txt"));f.put("manifest.json",{...m,artifacts:[...m.artifacts].reverse()});await assert.rejects(()=>verifyManifest(f.dir,expected),/entry/);
  f.put("manifest.json",m);rmSync(join(f.dir,"api-image.tar.gz"));symlinkSync(join(f.dir,"database-image.tar.gz"),join(f.dir,"api-image.tar.gz"));await assert.rejects(()=>verifyManifest(f.dir,expected),/Invalid candidate file/);
 }finally{f.dispose();}
});
test("missing scanner evidence, mismatched image ID, high vulnerability and missing SBOM block manifest creation",async()=>{
 const f=fixture();
 try{
  f.put("api-scan.json",f.scan(meta.databaseImage));await assert.rejects(()=>buildManifest(f.dir,meta),/does not match/);
  f.put("api-scan.json",{...f.scan(meta.apiImage),Results:[{Target:"fixture",Vulnerabilities:[{Severity:"HIGH"}]}]});
  await assert.rejects(()=>buildManifest(f.dir,meta),/severe vulnerability/);
  f.put("api-scan.json",f.scan(meta.apiImage));f.put("sbom.json",{bomFormat:"CycloneDX",components:[]});
  await assert.rejects(()=>buildManifest(f.dir,meta),/SBOM/);
 }finally{f.dispose();}
});

test("release repository identity survives account renames",()=>{
 const ci={GITHUB_ACTIONS:"true",GITHUB_REPOSITORY_ID:"1459605816",GITHUB_REPOSITORY_OWNER_ID:"355722999",GITHUB_REPOSITORY:"renamed-owner/Profitpilot"};
 assert.equal(expectedRepository(ci),ci.GITHUB_REPOSITORY);
 assert.equal(expectedRepository({...ci,GITHUB_REPOSITORY_ID:"123"}),"luxhustle01-ux/Profitpilot");
 assert.equal(expectedRepository({...ci,GITHUB_REPOSITORY_OWNER_ID:"123"}),"luxhustle01-ux/Profitpilot");
 assert.equal(expectedRepository({PROFITPILOT_EXPECTED_REPOSITORY:ci.GITHUB_REPOSITORY}),ci.GITHUB_REPOSITORY);
 assert.throws(()=>expectedRepository({...ci,GITHUB_REPOSITORY:"renamed-owner/Unrelated"}));
 assert.throws(()=>expectedRepository({...ci,GITHUB_REPOSITORY:""}));
});

import test from "node:test";
import assert from "node:assert/strict";
import {buildAcquisitionAssessment} from "../src/buyer-acquisition-audit.js";
const x="a".repeat(64),sha="b".repeat(40);
const required=["README.md","package.json","package-lock.json","Dockerfile",".github/workflows/ci.yml","database/schema.sql","server/index.js","src/buyer-walkthrough-core.js","demo/buyer-walkthrough.html","docs/VALIDATION_GATES.md"];
const files=()=>required.map(path=>({path,bytes:11,sha256:x}));
const pkg=()=>({name:"profitpilot-core",version:"0.2.0",private:true,dependencies:{express:"^4.21.2"}});
const lock=()=>({name:"profitpilot-core",version:"0.2.0",lockfileVersion:3,packages:{
 "":{dependencies:{express:"^4.21.2"}},
 "node_modules/express":{version:"4.22.3",license:"MIT",integrity:"sha512-test",resolved:"https://registry.npmjs.org/express/-/express-4.22.3.tgz"}
}});
const audit=(overrides={})=>buildAcquisitionAssessment({packageJson:pkg(),packageLock:lock(),trackedFiles:files(),sourceCommit:sha,...overrides});
test("B6 machine inventory is honest even when all metadata checks pass",()=>{
 const r=audit();
 assert.equal(r.automatedMetadataChecksPassed,true);
 assert.equal(r.npm.directDependencyCount,1);
 assert.equal(r.npm.resolvedThirdPartyPackageCount,1);
 assert.equal(r.npm.declaredLicenseCounts.MIT,1);
 assert.equal(r.project.rootLicenseFileFound,false);
 assert.equal(r.ipChainOfTitleVerified,false);
 assert.equal(r.permissionsTransferAssured,false);
 assert.equal(r.realCustomerDemandVerified,false);
 assert.equal(r.productionReleaseApproved,false);
 assert.match(r.saleReadiness,/PENDING/);
 assert.ok(r.unverifiedExternalGates.length>=7);
});
test("B6 source licence file records presence without claiming transfer clearance",()=>{
 const r=audit({trackedFiles:[...files(),{path:"LICENSE",bytes:30,sha256:x}]});
 assert.equal(r.project.rootLicenseFileFound,true);
 assert.equal(r.ipChainOfTitleVerified,false);
 assert.equal(r.standaloneProjectLicensingCleared,false);
});
test("B6 never treats unfamiliar or absent dependency licence metadata as clear",()=>{
 const l=lock();l.packages["node_modules/express"].license="GPL-3.0-only";
 const r=audit({packageLock:l});
 assert.equal(r.automatedMetadataChecksPassed,false);
 assert.deepEqual(r.npm.licenseMetadataReview,[{path:"node_modules/express",license:"GPL-3.0-only"}]);
});
test("B6 rejects stale lockfile, missing direct dependency and invalid Git commit",()=>{
 const bad=lock();bad.packages[""].dependencies.express="^4.22.0";
 assert.throws(()=>audit({packageLock:bad}),/drifted/);
 const empty=lock();delete empty.packages["node_modules/express"];
 assert.throws(()=>audit({packageLock:empty}),/missing from lock/);
 assert.throws(()=>audit({sourceCommit:"main"}),/exact source commit/);
});
test("B6 fails closed on duplicate, traversal, symlink-like or oversized records",()=>{
 assert.throws(()=>audit({trackedFiles:[...files(),files()[0]]}),/duplicate/);
 assert.throws(()=>audit({trackedFiles:[...files(),{path:"../passwords",bytes:1,sha256:x}]}),/invalid source path/);
 assert.throws(()=>audit({trackedFiles:[...files(),{path:"extra",bytes:5*1024*1024+1,sha256:x}]}),/invalid source file digest or length/);
 assert.throws(()=>audit({trackedFiles:[...files(),{path:"extra",bytes:1,sha256:"invalid"}]}),/invalid source file digest/);
});
test("B6 exposes critical-source gaps and suspicious filenames without hiding them",()=>{
 const paths=files().filter(f=>f.path!=="server/index.js");
 const a=audit({trackedFiles:paths});
 assert.equal(a.automatedMetadataChecksPassed,false);
 assert.deepEqual(a.source.missingCriticalFiles,["server/index.js"]);
 const b=audit({trackedFiles:[...files(),{path:".env",bytes:1,sha256:x}]});
 assert.equal(b.automatedMetadataChecksPassed,false);
 assert.deepEqual(b.source.sensitiveNamedPaths,[".env"]);
});
test("B6 flags missing package integrity or source resolution",()=>{
 const l=lock();delete l.packages["node_modules/express"].integrity;
 const r=audit({packageLock:l});
 assert.deepEqual(r.npm.missingResolvedOrIntegrity,["node_modules/express"]);
 assert.equal(r.automatedMetadataChecksPassed,false);
});

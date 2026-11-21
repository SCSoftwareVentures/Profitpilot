import test from "node:test";
import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {mkdtempSync,readFileSync,writeFileSync,rmSync,readdirSync,symlinkSync,mkdirSync} from "node:fs";
import {join} from "node:path";
import {tmpdir} from "node:os";
import {runPackaging} from "../scripts/package-buyer-demo.mjs";

const sourceSha="a".repeat(40);
const digest=x=>createHash("sha256").update(x).digest("hex");
test("B3 packs only a reproducible fictional demo and a truthful evaluation guide",()=>{
 const root=mkdtempSync(join(tmpdir(),"pp-buyer-pack-")),out=join(root,"share");
 try{
  const manifest=runPackaging("build",out,sourceSha);
  assert.equal(manifest.sourceCommitSha,sourceSha);
  assert.equal(manifest.customerDataIncluded,false);
  assert.equal(manifest.notAProductionRelease,true);
  assert.equal(manifest.trustedPublisherSignature,false);
  assert.equal(manifest.physicalIphoneWebkitTestingPerformed,false);
  assert.equal(manifest.deliverable,"synthetic-offline-demo-only");
  assert.deepEqual(readdirSync(out).sort(),["MANIFEST.json","ProfitPilot_Buyer_Demo.html","README.txt","SHA256SUMS"].sort());
  assert.deepEqual(manifest,runPackaging("verify",out,sourceSha));
  const read=name=>readFileSync(join(out,name));
  const html=read("ProfitPilot_Buyer_Demo.html");
  const guide=read("README.txt").toString("utf8");
  const sums=read("SHA256SUMS").toString("utf8");
  assert.match(html.toString("utf8"),/60-second guided review/);
  assert.match(guide,/NOT\s+been performed/);
  assert.match(guide,/This package is not cryptographically/);
  assert.equal(manifest.files["ProfitPilot_Buyer_Demo.html"].sha256,digest(html));
  for(const name of ["ProfitPilot_Buyer_Demo.html","README.txt","MANIFEST.json"])
   assert.ok(sums.includes(digest(read(name))+"  "+name));
  assert.throws(()=>runPackaging("build",out,sourceSha),/nonempty/);
 }finally{rmSync(root,{recursive:true,force:true});}
});
test("B3 refuses altered outputs, wrong commits, missing files and extra files",()=>{
 const root=mkdtempSync(join(tmpdir(),"pp-buyer-pack-fail-")),out=join(root,"share");
 try{
  assert.throws(()=>runPackaging("build",out,"broken"),/mandatory|Usage/);
  runPackaging("build",out,sourceSha);
  assert.throws(()=>runPackaging("verify",out,"b".repeat(40)),/altered|distribution/);
  writeFileSync(join(out,"README.txt"),"fake instruction");
  assert.throws(()=>runPackaging("verify",out,sourceSha),/altered/);
  rmSync(out,{recursive:true,force:true});
  runPackaging("build",out,sourceSha);
  writeFileSync(join(out,"extra-customer-data.csv"),"NOT AN ACTUAL RECORD");
  assert.throws(()=>runPackaging("verify",out,sourceSha),/unexpected/);
 }finally{rmSync(root,{recursive:true,force:true});}
});
test("B3 rejects substituted symlinks and directories during verification",()=>{
 const root=mkdtempSync(join(tmpdir(),"pp-buyer-nofollow-")),out=join(root,"share");
 try{
  runPackaging("build",out,sourceSha);
  const guide=join(out,"README.txt");
  rmSync(guide);
  symlinkSync(join(out,"MANIFEST.json"),guide);
  assert.throws(()=>runPackaging("verify",out,sourceSha),/ELOOP|symbolic link/i);
  rmSync(guide);
  mkdirSync(guide);
  assert.throws(()=>runPackaging("verify",out,sourceSha),/altered/);
 }finally{rmSync(root,{recursive:true,force:true});}
});

test("B3 rejects oversized and truncated files without loading unbounded contents",()=>{
 const root=mkdtempSync(join(tmpdir(),"pp-buyer-bounded-")),out=join(root,"share");
 try{
  runPackaging("build",out,sourceSha);
  const guide=join(out,"README.txt");
  const expected=readFileSync(guide);
  writeFileSync(guide,Buffer.concat([expected,Buffer.from("unexpected appended bytes")]));
  assert.throws(()=>runPackaging("verify",out,sourceSha),/altered/);
  writeFileSync(guide,expected.subarray(0,expected.length-1));
  assert.throws(()=>runPackaging("verify",out,sourceSha),/altered/);
  writeFileSync(guide,expected);
  assert.equal(runPackaging("verify",out,sourceSha).sourceCommitSha,sourceSha);
 }finally{rmSync(root,{recursive:true,force:true});}
});

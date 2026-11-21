import test from "node:test";
import assert from "node:assert/strict";
import {mkdtempSync,rmSync,writeFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {join,resolve} from "node:path";
import {fileURLToPath} from "node:url";
import {spawnSync} from "node:child_process";

const script=resolve(fileURLToPath(new URL("../scripts/check-container-vulnerabilities.mjs",import.meta.url)));
const images=["profitpilot-api:security","profitpilot-protected:security"];
const digest=c=>"sha256:"+c.repeat(64);
function report(index){
 const image=images[index],now=new Date().toISOString();
 return {
  matches:[],
  source:{type:"image",target:{
   userInput:image,tags:[image],imageID:digest(index?"b":"a"),manifestDigest:digest(index?"d":"c")
  }},
  distro:{name:"alpine",version:"3.24.4"},
  descriptor:{
   name:"grype",version:"0.104.1",timestamp:now,
   db:{status:{valid:true,built:now}},
   configuration:{"only-fixed":false,"only-notfixed":false,
    "ignore-wontfix":"","exclude":[],"vex-documents":[],"ignore":[]}
  }
 };
}
function check(mutator=()=>{}){
 const dir=mkdtempSync(join(tmpdir(),"profitpilot-grype-gate-"));
 try{
  const a=report(0),b=report(1);
  mutator(a,b);
  writeFileSync(join(dir,"prototype-vulnerabilities.json"),JSON.stringify(a));
  writeFileSync(join(dir,"protected-vulnerabilities.json"),JSON.stringify(b));
  return spawnSync(process.execPath,[script,"prototype-vulnerabilities.json","protected-vulnerabilities.json"],{
   cwd:dir,encoding:"utf8",timeout:5000,
   env:{...process.env,PROFITPILOT_EXPECTED_API_IMAGE_ID:digest("a"),
    PROFITPILOT_EXPECTED_PROTECTED_IMAGE_ID:digest("b")}
  });
 }finally{rmSync(dir,{recursive:true,force:true});}
}
test("B12 accepts two fresh, full, distinctly identified Grype image reports",()=>{
 const result=check();
 assert.equal(result.status,0,result.stderr);
});
test("B12 still blocks all medium/high findings, even with no fix",()=>{
 const result=check((a,b)=>b.matches.push({
  vulnerability:{id:"CVE-2026-124709",severity:"High",fix:{versions:[]}},
  artifact:{name:"libcrypto3",version:"3.5.9-r1"}
 }));
 assert.equal(result.status,1,result.stderr);
 assert.match(result.stderr,/Blocking container vulnerability findings: 1/);
});
test("B12 fails closed when reports are swapped, repeated, stale, filtered or suppressed",()=>{
 const cases=[
  ["swapped image identity",(a,b)=>{b.source.target.userInput=images[0];}],
  ["duplicate image",(a,b)=>{b.source.target.imageID=a.source.target.imageID;}],
  ["forged image ID",(a)=>{a.source.target.imageID=digest("e");}],
  ["missing image digest",(a)=>{delete a.source.target.manifestDigest;}],
  ["stale scanner result",(a)=>{a.descriptor.timestamp="2026-01-01T00:00:00Z";}],
  ["stale vulnerability database",(a)=>{a.descriptor.db.status.built="2026-01-01T00:00:00Z";}],
  ["unverified vulnerability database",(a)=>{a.descriptor.db.status.valid=false;}],
  ["exclude filter",(a)=>{a.descriptor.configuration.exclude=["/lib/"]; }],
  ["only-fixed filter",(a)=>{a.descriptor.configuration["only-fixed"]=true;}],
  ["VEX exclusion",(a)=>{a.descriptor.configuration["vex-documents"]=["disallowed.vex.json"];}],
  ["direct ignore filter",(a)=>{a.descriptor.configuration.ignore=[{vulnerability:"CVE-2026-124709"}];}],
  ["ignored match",(a)=>{a.ignoredMatches=[{vulnerability:{id:"CVE-2026-124709"}}];}],
  ["wrong distribution",(a)=>{a.distro.name="unknown";}],
  ["missing scanner identity",(a)=>{a.descriptor.name="other";}]
 ];
 for(const [name,mutate] of cases){
  const r=check(mutate);
  assert.notEqual(r.status,0,name+" unexpectedly passed: "+r.stdout);
 }
});

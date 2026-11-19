import test from "node:test";
import assert from "node:assert/strict";
import {inspectTrackedFile,validateLock} from "../scripts/source-security-preflight.js";
const manifest={dependencies:{example:"1.2.3"}};
const integrity="sha512-"+"A".repeat(86)+"==";
const lock=entry=>({lockfileVersion:3,packages:{"":{dependencies:manifest.dependencies},"node_modules/example":{version:"1.2.3",resolved:"https://registry.npmjs.org/example/-/example-1.2.3.tgz",integrity,...entry}}});
test("source preflight catches common credential shapes without returning credential values",()=>{
 const samples=[["gh"+"p_"+"a".repeat(36),"GitHub token"],["AK"+"IA"+"A".repeat(16),"AWS access key"],["sk-"+"proj-"+"x".repeat(45),"OpenAI project key"],["-----BEGIN "+"PRIVATE KEY-----\n"+"A".repeat(20),"private key"]];
 for(const [input,type] of samples){const findings=inspectTrackedFile("fixture.txt",input);assert.deepEqual(findings,[type]);assert.ok(!JSON.stringify(findings).includes(input));}
 assert.deepEqual(inspectTrackedFile("nested/.env.production","placeholder"),["restricted credential or backup filename"]);
 assert.deepEqual(inspectTrackedFile("database.dump","placeholder"),["restricted credential or backup filename"]);
 assert.deepEqual(inspectTrackedFile(".env.example","PLACEHOLDER"),[]);
});
test("lock preflight rejects alternate registries, nonexact versions, scripts and missing integrity",()=>{
 assert.equal(validateLock(manifest,lock({})),1);
 for(const override of [{resolved:"http://registry.npmjs.org/example.tgz"},{resolved:"https://evil.example.invalid/example.tgz"},{resolved:"https://registry.npmjs.org@evil.example.invalid/example.tgz"},{integrity:"sha1-"+ "x".repeat(27)},{hasInstallScript:true},{link:true},{version:"1.2.4"},{resolved:undefined},{resolved:"https://registry.npmjs.org/another/-/another-1.2.3.tgz"},{resolved:"https://registry.npmjs.org/example/-/example-1.2.4.tgz"},{name:"another"}]){
  assert.throws(()=>validateLock(manifest,lock(override)));
 }
 assert.throws(()=>validateLock({dependencies:{example:"^1.2.3"}},lock({})));
});

test("lock root and package identities must match the reviewed manifest",()=>{
 const mismatched=lock({});mismatched.packages[""].dependencies={example:"1.2.4"};
 assert.throws(()=>validateLock(manifest,mismatched));
 const extra=lock({});extra.packages[""].dependencies={...manifest.dependencies,unreviewed:"1.0.0"};
 assert.throws(()=>validateLock(manifest,extra));
});

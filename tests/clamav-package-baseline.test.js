import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {assertPatchedClamavInventory} from "../src/clamav-package-baseline.js";

const entry=(name,v)=>"P:"+name+"\nV:"+v+"\nA:x86_64\n";
const inventory=(libs="1.4.7-r0",unrar="1.4.7-r0")=>
 [entry("musl","1.2.5-r1"),entry("clamav-libs",libs),entry("clamav-libunrar",unrar)].join("\n");
test("B18 accepts two vendor-patched ClamAV packages in the actual APK ledger",()=>{
 for(const [a,b] of [["1.4.7-r0","1.4.7-r0"],["1.4.8-r0","1.4.7-r3"],["1.5.5-r0","1.5.5-r0"]]){
  const r=assertPatchedClamavInventory(inventory(a,b));
  assert.equal(r.scannerPatched,true);
  assert.equal(r.packages["clamav-libs"],a);
 }
});
test("B18 rejects outdated, malformed, duplicated or missing scanner packages",()=>{
 for(const [a,b] of [["1.4.6-r0","1.4.7-r0"],["1.4.7-r0","1.4.6-r0"],
   ["1.3.10-r0","1.4.7-r0"],["1.4.7","1.4.7-r0"],
   ["1.4.7-r0",""],["0.104.1-r0","1.4.7-r0"]]){
  assert.throws(()=>assertPatchedClamavInventory(inventory(a,b)));
 }
 assert.throws(()=>assertPatchedClamavInventory("P:musl\nV:1.2.5\n"));
 assert.throws(()=>assertPatchedClamavInventory(inventory()+"\n"+entry("clamav-libs","1.4.7-r0")));
 assert.throws(()=>assertPatchedClamavInventory("x".repeat(1024*1024+1)));
});
test("B18 requires the stable signed package floor in both build and runtime stages",()=>{
 const docker=readFileSync(new URL("../Dockerfile",import.meta.url),"utf8");
 assert.match(docker,/apk add --no-cache build-base 'clamav-dev>=1\.4\.7-r0'/);
 assert.match(docker,/apk --root \/rootfs --no-scripts --no-cache add 'clamav-libs>=1\.4\.7-r0' 'clamav-libunrar>=1\.4\.7-r0'/);
 assert.doesNotMatch(docker,/edge\/community|allow-untrusted|--force-broken-world|apk --allow-untrusted/);
});

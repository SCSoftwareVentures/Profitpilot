import test from "node:test";
import assert from "node:assert/strict";
import {assertPatchedOpenSslInventory} from "../src/openssl-package-floor.js";

const entry=(name,version)=>"P:"+name+"\nV:"+version+"\nA:x86_64\n";
const inventory=(crypto="3.5.10-r0",ssl=crypto)=>
 [entry("musl","1.2.5-r1"),entry("libcrypto3",crypto),entry("libssl3",ssl)].join("\n");

test("B19 accepts a matched vendor-patched OpenSSL 3.5.10+ pair",()=>{
 for(const version of ["3.5.10-r0","3.5.10-r1","3.5.11-r0","3.5.20-r4"]){
  const result=assertPatchedOpenSslInventory(inventory(version));
  assert.equal(result.vendorPatchFloorVerified,true);
  assert.equal(result.opensslVendorVersion,version);
  assert.equal(result.packageVersions.libssl3,version);
  assert.equal(result.releaseApproved,false);
  assert.equal(result.vulnerabilityScanVerified,false);
 }
});
test("B19 refuses the exact known vulnerable runtime and any older upstream 3.5 release",()=>{
 for(const version of ["3.5.9-r1","3.5.9-r99","3.5.8-r4","3.4.9-r0","3.0.24-r0","4.1.1-r0",
 "3.5.10","3.5.10-rc1","3.5.010-r?","3.5.9-r0"]){
  assert.throws(()=>assertPatchedOpenSslInventory(inventory(version)),/vulnerable|Unsupported/);
 }
});
test("B19 prevents missing, duplicated and mismatched security library inventory",()=>{
 assert.throws(()=>assertPatchedOpenSslInventory(entry("libcrypto3","3.5.10-r0")),/Missing protected/);
 assert.throws(()=>assertPatchedOpenSslInventory(inventory("3.5.10-r0","3.5.11-r0")),/mismatched/);
 assert.throws(()=>assertPatchedOpenSslInventory(inventory()+"\n"+entry("libcrypto3","3.5.10-r0")) ,/duplicate/);
 assert.throws(()=>assertPatchedOpenSslInventory(""),/Invalid/);
 assert.throws(()=>assertPatchedOpenSslInventory("x".repeat(1024*1024+1)),/Invalid|oversized/);
});
test("B19 rejects one patched library paired with vulnerable companion",()=>{
 assert.throws(()=>assertPatchedOpenSslInventory(inventory("3.5.10-r0","3.5.9-r1")),/vulnerable/);
 assert.throws(()=>assertPatchedOpenSslInventory(inventory("3.5.9-r1","3.5.10-r0")),/vulnerable/);
});

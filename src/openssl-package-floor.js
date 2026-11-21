// Independent, fail-closed verification of the installed Alpine OpenSSL ABI.
// This deliberately rejects the currently vulnerable 3.5.9-r1 release even if
// a future vulnerability database is missing the November 2026 advisories.
// The minimum may be revised ONLY for a documented, independently verified
// stable-distribution backport that actually resolves all seven findings.
const names=["libcrypto3","libssl3"];
function pkgVersion(raw){
 if(typeof raw!=="string")return null;
 const m=/^([0-9]+)\.([0-9]+)\.([0-9]+)-r([0-9]+)$/.exec(raw);
 if(!m)return null;
 const values=m.slice(1).map(Number);
 if(values.some(n=>!Number.isSafeInteger(n)))return null;
 return values;
}
export function assertPatchedOpenSslInventory(ledger){
 if(typeof ledger!=="string"||ledger.length<1||ledger.length>1024*1024)
  throw Error("Invalid or oversized installed APK ledger");
 const found=new Map();
 for(const record of ledger.split(/\r?\n\r?\n/)){
  const packageName=/^P:([^\r\n]+)$/m.exec(record)?.[1];
  if(!names.includes(packageName))continue;
  const version=/^V:([^\r\n]+)$/m.exec(record)?.[1];
  if(found.has(packageName)||!version)
   throw Error("Missing or duplicate OpenSSL APK package metadata: "+packageName);
  const parts=pkgVersion(version);
  if(!parts||parts[0]!==3||parts[1]!==5||parts[2]<10)
   throw Error("Unsupported or vulnerable OpenSSL 3.5 package: "+packageName+" "+version);
  found.set(packageName,version);
 }
 for(const name of names)
  if(!found.has(name))throw Error("Missing protected OpenSSL package: "+name);
 if(found.get("libcrypto3")!==found.get("libssl3"))
  throw Error("OpenSSL crypto and TLS shared libraries have mismatched APK versions");
 return Object.freeze({
  opensslVendorVersion:found.get("libcrypto3"),
  packageVersions:Object.freeze(Object.fromEntries(found)),
  vendorPatchFloorVerified:true,
  vulnerabilityScanVerified:false,
  releaseApproved:false
 });
}

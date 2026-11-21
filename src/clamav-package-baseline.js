// Fail-closed assertion of the actual signed Alpine APK installation ledger.
// Runs in unit tests and against the BUILT protected image, not just Dockerfile text.
const required=["clamav-libs","clamav-libunrar"];
const patchedVersion=v=>{
 if(typeof v!=="string")return false;
 const m=/^(\d+)\.(\d+)\.(\d+)-r(\d+)$/.exec(v);
 if(!m)return false;
 const [major,minor,patch]=m.slice(1,4).map(Number);
 return major>1||(major===1&&(minor>4||(minor===4&&patch>=7)));
};
export function assertPatchedClamavInventory(ledger){
 if(typeof ledger!=="string"||ledger.length>1024*1024||ledger.length<1)
  throw Error("Valid bounded signed APK installed-package ledger required");
 const installed=new Map();
 for(const block of ledger.split(/\n\n/)){
  const name=/^P:([^\n\r]+)$/m.exec(block)?.[1];
  if(!required.includes(name))continue;
  const version=/^V:([^\n\r]+)$/m.exec(block)?.[1];
  if(installed.has(name)||!patchedVersion(version))
   throw Error("ClamAV package missing vendor-patched version: "+name);
  installed.set(name,version);
 }
 for(const name of required)
  if(!installed.has(name))throw Error("Required ClamAV scanner package is missing: "+name);
 return {scannerPatched:true,packages:Object.fromEntries(installed)};
}

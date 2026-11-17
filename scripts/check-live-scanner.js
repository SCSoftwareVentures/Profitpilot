import {pathToFileURL} from "node:url";
import {scanClamav} from "../server/clamav.js";

// Run solely against an approved isolated live ClamAV socket. The EICAR
// antivirus test pattern is harmless and is never persisted to disk.
export async function checkLiveScanner(scan){
 const clean=Buffer.from("ProfitPilot synthetic invoice acceptance\n");
 const testPattern=Buffer.from("X5O!P%@AP[4\\PZX54(P^)7CC)7}$"+"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
 try{
  if(await scan(clean)!=="clean")throw new Error("Clean control failed");
  if(await scan(testPattern)!=="infected")throw new Error("Malware detection control failed");
  return true;
 }finally{clean.fill(0);testPattern.fill(0);}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 checkLiveScanner(bytes=>scanClamav(bytes,{socketPath:process.env.CLAMAV_SOCKET_PATH})).then(()=>{
  process.stdout.write(JSON.stringify({event:"live_scanner_acceptance",status:"passed"})+"\n");
 }).catch(()=>{
  process.stderr.write(JSON.stringify({event:"live_scanner_acceptance",status:"failed"})+"\n");process.exitCode=1;
 });
}

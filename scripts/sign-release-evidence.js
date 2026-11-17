// Independently run by each approver, outside the application and repository checkout.
import {readFile,writeFile} from "node:fs/promises";
import {createPrivateKey,sign} from "node:crypto";
import {releaseSigningBytes} from "../server/release-approval.js";
async function main(){
 const [role,payloadFile,keyFile,outputFile]=process.argv.slice(2);
 if(!["technical","privacy"].includes(role)||!payloadFile||!keyFile||!outputFile)throw Error("Usage: technical|privacy payload.json private-key.pem signature.txt");
 const payload=await readFile(payloadFile,"utf8");
 const key=createPrivateKey(await readFile(keyFile));
 if(key.asymmetricKeyType!=="ed25519")throw Error("Ed25519 approval key required");
 const signature=sign(null,releaseSigningBytes(payload,role),key).toString("base64url");
 await writeFile(outputFile,signature+"\n",{flag:"wx",mode:0o600});
}
main().catch(()=>{console.error("Release approval signature was not created.");process.exitCode=1;});

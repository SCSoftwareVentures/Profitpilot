// Standalone sandbox authority. Launch as a distinct OS identity with private
// secrets and a dedicated database login. Never launch from the staff API.
import express from "express";
import {createServer} from "node:http";
import {lstat,chmod,unlink} from "node:fs/promises";
import {isAbsolute,dirname} from "node:path";
import {fileURLToPath} from "node:url";
import {createSecurePayRouterFromEnv} from "./securepay-router.js";
export async function startAuthority(env=process.env){
 if(env.SECUREPAY_SANDBOX_ENABLED!=="true"||!["development","test"].includes(env.NODE_ENV))
  throw Error("SecurePay authority disabled");
 if(["DATABASE_URL","TENANT_CONTEXT_HMAC_SECRET"].some(k=>env[k]!==undefined))throw Error("Staff secrets forbidden in authority");
 const path=env.SECUREPAY_AUTHORITY_SOCKET;
 if(typeof path!=="string"||!isAbsolute(path)||path.length>100||path.includes("\0"))throw Error("SecurePay authority socket required");
 const parent=await lstat(dirname(path));
 if(!parent.isDirectory()||(parent.mode&0o007)!==0||(parent.mode&0o020)!==0||parent.uid!==process.getuid())throw Error("Unsafe authority socket directory");
 const app=express();app.disable("x-powered-by");
 app.use("/v1/securepay",createSecurePayRouterFromEnv(env));
 app.use((req,res)=>res.status(404).json({error:"Not found"}));
 const server=createServer(app);
 server.requestTimeout=12000;server.headersTimeout=5000;server.maxHeadersCount=32;
 // Do not remove an existing socket at startup: a live authority may own it.
 await new Promise((resolve,reject)=>{server.once("error",reject);server.listen(path,resolve);});
 try{await chmod(path,0o660);}catch(e){server.close();throw e;}
 const close=async()=>{await new Promise((resolve,reject)=>server.close(e=>e?reject(e):resolve()));try{await unlink(path);}catch(e){if(e.code!=="ENOENT")throw e;}};
 return {server,close};
}
if(process.argv[1]===fileURLToPath(import.meta.url)){
 try{
  const authority=await startAuthority();
  process.stdout.write("SecurePay sandbox authority ready\n");
  let stopping=false;
  const stop=async()=>{if(stopping)return;stopping=true;try{await authority.close();process.exit(0);}catch{process.exit(1);}};
  process.on("SIGTERM",stop);process.on("SIGINT",stop);
 }catch{process.stderr.write("SecurePay authority startup failed\n");process.exitCode=1;}
}

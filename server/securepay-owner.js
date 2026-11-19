// Separate read-only owner reporting process. Never mount this on the payer gateway.
// Single explicitly provisioned tenant/owner per sandbox process.
import express from "express";
import rateLimit from "express-rate-limit";
import pg from "pg";
import {createRemoteJWKSet} from "jose";
import {createServer} from "node:http";
import {fileURLToPath} from "node:url";
import {createPayerTokenVerifier} from "./securepay-router.js";
import {authoritySecrets} from "./securepay-gateway.js";
import {ownerDashboardPage,sendPortalPage} from "./securepay-portal-page.js";
import {loadReconciliationReport,summarizeReport} from "../securepay/db/reconciliation-report.mjs";
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
export function createOwnerRouter({enabled=false,subject,tenantId,verifyToken,loadReport}={}){
 const router=express.Router();
 router.use((req,res,next)=>{res.set("Cache-Control","no-store");if(!enabled)return res.status(404).json({error:"Not found"});next();});
 if(!enabled)return router;
 if(typeof subject!=="string"||!subject||subject.length>512||!uuid.test(tenantId)||typeof verifyToken!=="function"||typeof loadReport!=="function")throw Error("Owner reporting unavailable");
 router.use(rateLimit({windowMs:60000,limit:15,standardHeaders:true,legacyHeaders:false}));
 router.get("/dashboard",(req,res)=>req.originalUrl.includes("?")?res.status(404).json({error:"Not found"}):sendPortalPage(res,ownerDashboardPage()));
 router.post("/report",async(req,res,next)=>{
  if(req.originalUrl.includes("?"))return res.status(404).json({error:"Not found"});
  try{
   const token=req.headers.authorization?.match(/^Bearer ([^\s]{1,8192})$/i)?.[1];
   if(!token)return res.status(401).json({error:"Owner authentication required"});
   const identity=await verifyToken(token);
   if(identity?.subject!==subject)return res.status(403).json({error:"Authorization denied"});
   next();
  }catch{return res.status(401).json({error:"Owner authentication required"});}
 },express.json({limit:"1kb",strict:true}),async(req,res)=>{
  if(!req.is("application/json"))return res.status(415).json({error:"JSON required"});
  if(!req.body||Array.isArray(req.body)||typeof req.body!=="object"||Object.keys(req.body).length!==0)return res.status(400).json({error:"Invalid request"});
  try{
   const report=await loadReport();
   if(report?.tenantId!==tenantId||report.mode!=="sandbox"||report.moneyMoved!==false)throw Error("Invalid scope");
   return res.json({report,summary:summarizeReport(report)});
  }catch{return res.status(503).json({error:"Reporting unavailable"});}
 });
 router.use((req,res)=>res.status(404).json({error:"Not found"}));
 router.use((err,req,res,next)=>res.status(err.type==="entity.too.large"?413:400).json({error:"Invalid request"}));
 return router;
}
export async function startOwnerDashboard(env=process.env){
 if(env.SECUREPAY_OWNER_SANDBOX_ENABLED!=="true"||!["development","test"].includes(env.NODE_ENV))throw Error("Owner dashboard disabled");
 if([...authoritySecrets,"DATABASE_URL","TENANT_CONTEXT_HMAC_SECRET"].some(k=>env[k]!==undefined))throw Error("Payment or staff secrets forbidden in owner dashboard");
 const {SECUREPAY_OWNER_ISSUER:issuer,SECUREPAY_OWNER_AUDIENCE:audience,SECUREPAY_OWNER_REQUIRED_ACR:requiredAcr,SECUREPAY_OWNER_JWKS_URL:jwks,SECUREPAY_OWNER_SUBJECT:subject,SECUREPAY_REPORT_TENANT_ID:tenantId,SECUREPAY_REPORT_ACTOR_ID:actorId,SECUREPAY_REPORT_DATABASE_URL:databaseUrl,SECUREPAY_REPORT_ACTOR_KEY:key}=env;
 const port=Number(env.SECUREPAY_OWNER_PORT??"3081");
 if(!issuer||!audience||!env.SECUREPAY_AUTH_AUDIENCE||audience===env.SECUREPAY_AUTH_AUDIENCE||audience===env.SECUREPAY_RECOVERY_AUDIENCE||audience===env.AUTH_AUDIENCE||!requiredAcr||!subject||!uuid.test(tenantId)||!uuid.test(actorId)||!databaseUrl||!/^[a-f0-9]{64}$/i.test(key??"")||!Number.isInteger(port)||port<0||port>65535)throw Error("Owner configuration incomplete");
 const url=new URL(jwks);
 if(url.protocol!=="https:"&&!(env.NODE_ENV==="test"&&url.protocol==="http:"&&["127.0.0.1","localhost"].includes(url.hostname)))throw Error("JWKS requires HTTPS");
 const pool=new pg.Pool({connectionString:databaseUrl,max:2,connectionTimeoutMillis:5000,statement_timeout:10000,ssl:env.SECUREPAY_REPORT_DATABASE_SSL==="true"?{rejectUnauthorized:true}:false});
 try{
  const {rows:[r]}=await pool.query("SELECT current_user AS role");if(r.role!=="securepay_reporting_runtime")throw Error("Incorrect reporting role");
  const app=express();app.disable("x-powered-by");
  app.use("/v1/securepay-owner",createOwnerRouter({enabled:true,subject,tenantId,verifyToken:createPayerTokenVerifier({issuer,audience,requiredAcr,keyResolver:createRemoteJWKSet(url)}),loadReport:()=>loadReconciliationReport(pool,{tenantId,actorId,key:Buffer.from(key,"hex")})}));
  const server=createServer(app);server.requestTimeout=12000;server.headersTimeout=5000;
  await new Promise((resolve,reject)=>{server.once("error",reject);server.listen(port,"127.0.0.1",resolve);});
  return {server,close:async()=>{await new Promise((resolve,reject)=>server.close(e=>e?reject(e):resolve()));await pool.end();}};
 }catch(e){await pool.end();throw e;}
}
if(process.argv[1]===fileURLToPath(import.meta.url)){
 try{
  const owner=await startOwnerDashboard();
  process.stdout.write("SecurePay owner sandbox ready\n");
  let stopping=false;const stop=async()=>{if(stopping)return;stopping=true;try{await owner.close();process.exit(0);}catch{process.exit(1);}};
  process.on("SIGTERM",stop);process.on("SIGINT",stop);
 }catch{process.stderr.write("SecurePay owner startup failed\n");process.exitCode=1;}
}

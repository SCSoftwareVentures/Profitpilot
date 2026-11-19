// Independent reviewer sandbox process, no payment mutation or provider credentials.
import express from "express";
import rateLimit from "express-rate-limit";
import pg from "pg";
import {createRemoteJWKSet} from "jose";
import {createServer} from "node:http";
import {fileURLToPath} from "node:url";
import {createPayerTokenVerifier} from "./securepay-router.js";
import {authoritySecrets} from "./securepay-gateway.js";
import {reviewerPage,sendPortalPage} from "./securepay-portal-page.js";
import {makeGovernanceActor,independenceAttestation} from "../securepay/db/governance.mjs";
import {makeReviewer} from "../securepay/db/reviewer.mjs";
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const id=x=>typeof x==="string"&&uuid.test(x);
const exact=(x,keys)=>x&&typeof x==="object"&&!Array.isArray(x)&&Object.keys(x).length===keys.length&&keys.every(k=>Object.hasOwn(x,k));
export function createReviewerRouter({enabled=false,subject,verifyToken,reviewer,governance}={}){
 const router=express.Router();
 router.use((req,res,next)=>{res.set("Cache-Control","no-store");if(!enabled)return res.status(404).json({error:"Not found"});next();});
 if(!enabled)return router;
 if(typeof subject!=="string"||!subject||typeof verifyToken!=="function"||!reviewer)throw Error("Reviewer unavailable");
 router.use(rateLimit({windowMs:60000,limit:100,standardHeaders:true,legacyHeaders:false}));
 router.get("/dashboard",(req,res)=>req.originalUrl.includes("?")?res.status(404).json({error:"Not found"}):sendPortalPage(res,reviewerPage()));
 router.post("/:action",async(req,res,next)=>{
  if(req.originalUrl.includes("?")||!["queue","case","photo","decision","assignments","declare"].includes(req.params.action))return res.status(404).json({error:"Not found"});
  try{const token=req.headers.authorization?.match(/^Bearer ([^\s]{1,8192})$/i)?.[1];if(!token)return res.status(401).json({error:"Authentication required"});const identity=await verifyToken(token);if(identity?.subject!==subject)return res.status(403).json({error:"Authorization denied"});if(!req.is("application/json"))return res.status(415).json({error:"JSON required"});next();}catch{return res.status(401).json({error:"Authentication required"});}
 },express.json({limit:"16kb",strict:true}),async(req,res)=>{
  const a=req.params.action,b=req.body;let result;
  try{
   if(a==="assignments"){if(!governance||!exact(b,[]))return res.status(400).json({error:"Invalid request"});result=await governance.queue();if(result===null)return res.status(403).json({error:"Authorization denied"});return res.json({mode:"sandbox",moneyMoved:false,cases:result});}
   if(a==="declare"){if(!governance||!exact(b,["caseId","attestation"])||!id(b.caseId)||b.attestation!==independenceAttestation)return res.status(400).json({error:"Invalid request"});result=await governance.declare(b);if(!result.ok)return res.status(403).json({error:"Authorization denied"});return res.json({mode:"sandbox",moneyMoved:false,status:"declared"});}
   if(a==="queue"){if(!exact(b,[]))return res.status(400).json({error:"Invalid request"});result=await reviewer.queue();}
   else if(a==="case"){if(!exact(b,["caseId"])||!id(b.caseId))return res.status(400).json({error:"Invalid request"});result=await reviewer.read(b.caseId);}
   else if(a==="photo"){if(!exact(b,["caseId","photoId","source"])||!id(b.caseId)||!id(b.photoId)||!["dispute","completion"].includes(b.source))return res.status(400).json({error:"Invalid request"});result=await reviewer.photo(b);}
   else{if(!exact(b,["caseId","action","reason","payoutCents","refundCents","stateDigest"])||!id(b.caseId)||!["decide","finalize"].includes(b.action)||typeof b.reason!=="string"||b.reason.trim().length<10||b.reason.length>4000||b.reason.includes("\0")||![b.payoutCents,b.refundCents].every(x=>Number.isSafeInteger(x)&&x>=0)||typeof b.stateDigest!=="string"||!/^[a-f0-9]{64}$/.test(b.stateDigest))return res.status(400).json({error:"Invalid request"});result=await reviewer.decide(b);if(!result?.ok)return res.status(403).json({error:"Authorization denied"});return res.json({mode:"sandbox",moneyMoved:false,status:"decision_recorded"});}
   if(result===null||result===undefined)return res.status(403).json({error:"Authorization denied"});
   return res.json({mode:"sandbox",moneyMoved:false,[a==="queue"?"cases":a==="case"?"review":"photo"]:result});
  }catch{return res.status(503).json({error:"Reviewer service unavailable"});}
 });
 router.use((req,res)=>res.status(404).json({error:"Not found"}));
 router.use((err,req,res,next)=>res.status(err.type==="entity.too.large"?413:400).json({error:"Invalid request"}));
 return router;
}
export async function startReviewerService(env=process.env){
 if(env.SECUREPAY_REVIEWER_SANDBOX_ENABLED!=="true"||!["development","test"].includes(env.NODE_ENV))throw Error("Reviewer disabled");
 if([...authoritySecrets,"DATABASE_URL","TENANT_CONTEXT_HMAC_SECRET","SECUREPAY_REPORT_ACTOR_KEY","SECUREPAY_REPORT_DATABASE_URL","SECUREPAY_COMPLETION_ACTOR_KEY","SECUREPAY_COMPLETION_SCAN_KEY","SECUREPAY_COMPLETION_DATABASE_URL"].some(k=>env[k]!==undefined))throw Error("Unrelated authority secrets forbidden");
 const {SECUREPAY_REVIEWER_ISSUER:issuer,SECUREPAY_REVIEWER_AUDIENCE:audience,SECUREPAY_REVIEWER_REQUIRED_ACR:requiredAcr,SECUREPAY_REVIEWER_JWKS_URL:jwks,SECUREPAY_REVIEWER_SUBJECT:subject,SECUREPAY_REVIEWER_TENANT_ID:tenantId,SECUREPAY_REVIEWER_ACTOR_ID:actorId,SECUREPAY_REVIEWER_DATABASE_URL:databaseUrl,SECUREPAY_REVIEWER_ACTOR_KEY:key}=env;
 const port=Number(env.SECUREPAY_REVIEWER_PORT??"3083");
 if(!issuer||!audience||![env.SECUREPAY_AUTH_AUDIENCE,env.SECUREPAY_OWNER_AUDIENCE,env.SECUREPAY_COMPLETION_AUDIENCE].every(x=>typeof x==="string"&&x&&x!==audience)||[env.SECUREPAY_RECOVERY_AUDIENCE,env.AUTH_AUDIENCE].includes(audience)||!requiredAcr||!subject||!id(tenantId)||!id(actorId)||!databaseUrl||typeof key!=="string"||!/^[a-f0-9]{64}$/i.test(key)||!Number.isInteger(port)||port<0||port>65535)throw Error("Reviewer configuration incomplete");
 const url=new URL(jwks);if(url.protocol!=="https:"&&!(env.NODE_ENV==="test"&&url.protocol==="http:"&&["127.0.0.1","localhost"].includes(url.hostname)))throw Error("JWKS requires HTTPS");
 const pool=new pg.Pool({connectionString:databaseUrl,max:2,connectionTimeoutMillis:5000,statement_timeout:10000,ssl:env.SECUREPAY_REVIEWER_DATABASE_SSL==="true"?{rejectUnauthorized:true}:false});
 try{
  const {rows:[r]}=await pool.query("SELECT current_user AS role");if(r.role!=="securepay_reviewer_runtime")throw Error("Incorrect reviewer role");
  const app=express();app.disable("x-powered-by");app.use("/v1/securepay-reviewer",createReviewerRouter({enabled:true,subject,verifyToken:createPayerTokenVerifier({issuer,audience,requiredAcr,keyResolver:createRemoteJWKSet(url)}),reviewer:makeReviewer({pool,tenantId,actorId,key:Buffer.from(key,"hex")}),governance:makeGovernanceActor({pool,tenantId,actorId,key:Buffer.from(key,"hex"),role:"reviewer"})}));
  const server=createServer(app);server.requestTimeout=15000;server.headersTimeout=5000;
  await new Promise((resolve,reject)=>{server.once("error",reject);server.listen(port,"127.0.0.1",resolve);});
  return {server,close:async()=>{await new Promise((resolve,reject)=>server.close(e=>e?reject(e):resolve()));await pool.end();}};
 }catch(e){await pool.end();throw e;}
}
if(process.argv[1]===fileURLToPath(import.meta.url)){try{const service=await startReviewerService();process.stdout.write("SecurePay reviewer sandbox ready\n");let stopping=false;const stop=async()=>{if(stopping)return;stopping=true;try{await service.close();process.exit(0);}catch{process.exit(1);}};process.on("SIGTERM",stop);process.on("SIGINT",stop);}catch{process.stderr.write("SecurePay reviewer startup failed\n");process.exitCode=1;}}

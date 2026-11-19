// Separate loopback service per operational role, sandbox only.
import express from "express";
import rateLimit from "express-rate-limit";
import pg from "pg";
import {createRemoteJWKSet} from "jose";
import {createServer} from "node:http";
import {fileURLToPath} from "node:url";
import {createPayerTokenVerifier} from "./securepay-router.js";
import {authoritySecrets} from "./securepay-gateway.js";
import {disputeAdminPage,settlementAuthorizationPage,postAuthorizationPage,sendPortalPage} from "./securepay-portal-page.js";
import {makeGovernanceActor,independenceAttestation} from "../securepay/db/governance.mjs";
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const id=x=>typeof x==="string"&&uuid.test(x);
const exact=(x,keys)=>x&&typeof x==="object"&&!Array.isArray(x)&&Object.keys(x).length===keys.length&&keys.every(k=>Object.hasOwn(x,k));
export function createGovernanceRouter({enabled=false,role,subject,verifyToken,actor}={}){
 const router=express.Router();router.use((req,res,next)=>{res.set("Cache-Control","no-store");if(!enabled)return res.status(404).json({error:"Not found"});next();});if(!enabled)return router;
 if(!["administrator","settlement"].includes(role)||!subject||!actor||typeof verifyToken!=="function")throw Error("Governance unavailable");
 const admin=role==="administrator",allowed=admin?["queue","action","reassessments","reassess","post-auth-start"]:["queue","declare","read","authorize","report-conflict","post-auth-read","post-auth-vote"];
 router.use(rateLimit({windowMs:60000,limit:60,standardHeaders:true,legacyHeaders:false}));
 router.get("/post-auth",(req,res)=>req.originalUrl.includes("?")?res.status(404).json({error:"Not found"}):sendPortalPage(res,postAuthorizationPage(role)));
 router.get("/dashboard",(req,res)=>req.originalUrl.includes("?")?res.status(404).json({error:"Not found"}):sendPortalPage(res,admin?disputeAdminPage():settlementAuthorizationPage()));
 router.post("/:action",async(req,res,next)=>{
  if(req.originalUrl.includes("?")||!allowed.includes(req.params.action))return res.status(404).json({error:"Not found"});
  try{const token=req.headers.authorization?.match(/^Bearer ([^\s]{1,8192})$/i)?.[1];if(!token)return res.status(401).json({error:"Authentication required"});const identity=await verifyToken(token);if(identity?.subject!==subject)return res.status(403).json({error:"Authorization denied"});if(!req.is("application/json"))return res.status(415).json({error:"JSON required"});next();}catch{return res.status(401).json({error:"Authentication required"});}
 },express.json({limit:"8kb",strict:true}),async(req,res)=>{
  const a=req.params.action,b=req.body;let result;
  try{
   if(a==="reassessments"){if(!exact(b,[]))return res.status(400).json({error:"Invalid request"});result=await actor.reassessments();if(result===null)return res.status(403).json({error:"Authorization denied"});return res.json({mode:"sandbox",moneyMoved:false,requests:result});}
   if(a==="reassess"){if(!exact(b,["caseId","requestId","action","reason","stateDigest"])||!id(b.caseId)||!id(b.requestId)||!["request","approve","withdraw"].includes(b.action)||typeof b.reason!=="string"||b.reason.trim().length<10||b.reason.length>1000||b.reason.includes("\0")||(b.action==="request")!==(b.stateDigest===null)||(b.stateDigest!==null&&(typeof b.stateDigest!=="string"||!/^[a-f0-9]{64}$/.test(b.stateDigest))))return res.status(400).json({error:"Invalid request"});result=await actor.reassess(b);if(!result?.ok)return res.status(403).json({error:"Authorization denied"});return res.json({mode:"sandbox",moneyMoved:false,reassessment:result.reassessment});}
   if(a==="post-auth-start"){if(!exact(b,["caseId","reviewerOne","reviewerTwo","authorizerId","reason"])||![b.caseId,b.reviewerOne,b.reviewerTwo,b.authorizerId].every(id)||typeof b.reason!=="string"||b.reason.trim().length<10||b.reason.length>1000||b.reason.includes("\0"))return res.status(400).json({error:"Invalid request"});result=await actor.startPostAuth(b);if(!result?.ok)return res.status(403).json({error:"Authorization denied"});return res.json({mode:"sandbox",moneyMoved:false,reviewId:result.reviewId});}
   if(a==="post-auth-read"){if(!actor||!exact(b,["caseId"])||!id(b.caseId))return res.status(400).json({error:"Invalid request"});result=await actor.postAuthRead(b.caseId);if(!result)return res.status(403).json({error:"Authorization denied"});return res.json({mode:"sandbox",moneyMoved:false,postAuth:result});}
   if(a==="post-auth-vote"){if(!actor||!exact(b,["caseId","reviewId","outcome","reason","stateDigest"])||!id(b.caseId)||!id(b.reviewId)||!["reaffirm","stop"].includes(b.outcome)||typeof b.reason!=="string"||b.reason.trim().length<10||b.reason.length>4000||b.reason.includes("\0")||typeof b.stateDigest!=="string"||!/^[a-f0-9]{64}$/.test(b.stateDigest))return res.status(400).json({error:"Invalid request"});result=await actor.postAuthVote(b);if(!result?.ok)return res.status(403).json({error:"Authorization denied"});return res.json({mode:"sandbox",moneyMoved:false,status:"review_recorded"});}
   if(a==="report-conflict"){if(!exact(b,["caseId","reason"])||!id(b.caseId)||typeof b.reason!=="string"||b.reason.trim().length<10||b.reason.length>1000||b.reason.includes("\0"))return res.status(400).json({error:"Invalid request"});result=await actor.reportConflict(b);if(!result?.ok)return res.status(403).json({error:"Authorization denied"});return res.json({mode:"sandbox",moneyMoved:false,status:"conflict_reported"});}
   if(a==="queue"){if(!exact(b,[]))return res.status(400).json({error:"Invalid request"});result=await actor.queue();if(result===null)return res.status(403).json({error:"Authorization denied"});return res.json({mode:"sandbox",moneyMoved:false,cases:result});}
   if(a==="read"){if(!exact(b,["caseId"])||!id(b.caseId))return res.status(400).json({error:"Invalid request"});result=await actor.read(b.caseId);if(!result)return res.status(403).json({error:"Authorization denied"});return res.json({mode:"sandbox",moneyMoved:false,review:result});}
   if(a==="action"){if(!exact(b,["caseId","target","action","reason"])||!id(b.caseId)||!(b.target===null||id(b.target))||!["enroll","assign","revoke","conflict"].includes(b.action)||(b.action==="enroll")!==(b.target===null)||typeof b.reason!=="string"||b.reason.trim().length<10||b.reason.length>1000||b.reason.includes("\0"))return res.status(400).json({error:"Invalid request"});result=await actor.action(b);}
   else if(a==="declare"){if(!exact(b,["caseId","attestation"])||!id(b.caseId)||b.attestation!==independenceAttestation)return res.status(400).json({error:"Invalid request"});result=await actor.declare(b);}
   else{if(!exact(b,["caseId","payoutCents","refundCents","stateDigest"])||!id(b.caseId)||![b.payoutCents,b.refundCents].every(x=>Number.isSafeInteger(x)&&x>=0)||typeof b.stateDigest!=="string"||!/^[a-f0-9]{64}$/.test(b.stateDigest))return res.status(400).json({error:"Invalid request"});result=await actor.authorize(b);}
   if(!result?.ok)return res.status(403).json({error:"Authorization denied"});
   return res.json({mode:"sandbox",moneyMoved:false,status:a==="authorize"?"settlement_authorized":a==="declare"?"declared":"recorded",...(a==="authorize"?{settlementId:result.settlementId}:{})});
  }catch{return res.status(503).json({error:"Governance unavailable"});}
 });
 router.use((req,res)=>res.status(404).json({error:"Not found"}));router.use((err,req,res,next)=>res.status(err.type==="entity.too.large"?413:400).json({error:"Invalid request"}));return router;
}
export async function startGovernanceService(env=process.env){
 if(env.SECUREPAY_GOVERNANCE_SANDBOX_ENABLED!=="true"||!["development","test"].includes(env.NODE_ENV))throw Error("Governance disabled");
 if([...authoritySecrets,"DATABASE_URL","TENANT_CONTEXT_HMAC_SECRET","SECUREPAY_REPORT_ACTOR_KEY","SECUREPAY_REPORT_DATABASE_URL","SECUREPAY_COMPLETION_ACTOR_KEY","SECUREPAY_COMPLETION_SCAN_KEY","SECUREPAY_COMPLETION_DATABASE_URL","SECUREPAY_REVIEWER_ACTOR_KEY","SECUREPAY_REVIEWER_DATABASE_URL"].some(k=>env[k]!==undefined))throw Error("Unrelated authority secrets forbidden");
 const {SECUREPAY_GOVERNANCE_ROLE:role,SECUREPAY_GOVERNANCE_ISSUER:issuer,SECUREPAY_GOVERNANCE_AUDIENCE:audience,SECUREPAY_GOVERNANCE_REQUIRED_ACR:requiredAcr,SECUREPAY_GOVERNANCE_JWKS_URL:jwks,SECUREPAY_GOVERNANCE_SUBJECT:subject,SECUREPAY_GOVERNANCE_TENANT_ID:tenantId,SECUREPAY_GOVERNANCE_ACTOR_ID:actorId,SECUREPAY_GOVERNANCE_DATABASE_URL:databaseUrl,SECUREPAY_GOVERNANCE_ACTOR_KEY:key}=env;
 const other=role==="administrator"?env.SECUREPAY_SETTLEMENT_AUDIENCE:env.SECUREPAY_ADMINISTRATOR_AUDIENCE;
 const port=Number(env.SECUREPAY_GOVERNANCE_PORT??(role==="administrator"?"3084":"3085"));
 if(!["administrator","settlement"].includes(role)||!issuer||!audience||![env.SECUREPAY_AUTH_AUDIENCE,env.SECUREPAY_OWNER_AUDIENCE,env.SECUREPAY_COMPLETION_AUDIENCE,env.SECUREPAY_REVIEWER_AUDIENCE,other].every(x=>typeof x==="string"&&x&&x!==audience)||[env.SECUREPAY_RECOVERY_AUDIENCE,env.AUTH_AUDIENCE].includes(audience)||!requiredAcr||!subject||!id(tenantId)||!id(actorId)||!databaseUrl||typeof key!=="string"||!/^[a-f0-9]{64}$/i.test(key)||!Number.isInteger(port)||port<0||port>65535)throw Error("Governance configuration incomplete");
 const url=new URL(jwks);if(url.protocol!=="https:"&&!(env.NODE_ENV==="test"&&url.protocol==="http:"&&["127.0.0.1","localhost"].includes(url.hostname)))throw Error("JWKS requires HTTPS");
 const pool=new pg.Pool({connectionString:databaseUrl,max:2,connectionTimeoutMillis:5000,statement_timeout:10000,ssl:env.SECUREPAY_GOVERNANCE_DATABASE_SSL==="true"?{rejectUnauthorized:true}:false});
 try{
  const {rows:[r]}=await pool.query("SELECT current_user AS role");if(r.role!==(role==="administrator"?"securepay_dispute_admin_runtime":"securepay_settlement_dashboard_runtime"))throw Error("Incorrect governance role");
  const app=express();app.disable("x-powered-by");app.use("/v1/securepay-governance",createGovernanceRouter({enabled:true,role,subject,verifyToken:createPayerTokenVerifier({issuer,audience,requiredAcr,keyResolver:createRemoteJWKSet(url)}),actor:makeGovernanceActor({pool,tenantId,actorId,key:Buffer.from(key,"hex"),role})}));
  const server=createServer(app);server.requestTimeout=15000;server.headersTimeout=5000;await new Promise((resolve,reject)=>{server.once("error",reject);server.listen(port,"127.0.0.1",resolve);});
  return {server,close:async()=>{await new Promise((resolve,reject)=>server.close(e=>e?reject(e):resolve()));await pool.end();}};
 }catch(e){await pool.end();throw e;}
}
if(process.argv[1]===fileURLToPath(import.meta.url)){try{const service=await startGovernanceService();process.stdout.write("SecurePay governance sandbox ready\n");let stopping=false;const stop=async()=>{if(stopping)return;stopping=true;try{await service.close();process.exit(0);}catch{process.exit(1);}};process.on("SIGTERM",stop);process.on("SIGINT",stop);}catch{process.stderr.write("SecurePay governance startup failed\n");process.exitCode=1;}}

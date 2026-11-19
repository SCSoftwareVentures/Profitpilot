// Dedicated sandbox completion service: no payment, reporting, or staff credentials.
import express from "express";
import rateLimit from "express-rate-limit";
import pg from "pg";
import {createRemoteJWKSet} from "jose";
import {createServer} from "node:http";
import {fileURLToPath} from "node:url";
import {createPayerTokenVerifier} from "./securepay-router.js";
import {authoritySecrets} from "./securepay-gateway.js";
import {ownerCompletionPage,ownerQuotePage,sendPortalPage} from "./securepay-portal-page.js";
import {makeWorkCompletionOwner} from "../securepay/db/work-completion.mjs";
import {makeEvidenceScanner,clamavScanner,jpegNormalizer} from "../securepay/db/evidence-scanner.mjs";
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const hex=/^[a-f0-9]{64}$/i;
const exact=(body,keys)=>body&&typeof body==="object"&&!Array.isArray(body)&&Object.keys(body).length===keys.length&&keys.every(k=>Object.hasOwn(body,k));
export function createCompletionRouter({enabled=false,tenantId,subject,verifyToken,owner}={}){
 const router=express.Router();
 router.use((req,res,next)=>{res.set("Cache-Control","no-store");if(!enabled)return res.status(404).json({error:"Not found"});next();});
 if(!enabled)return router;
 if(!uuid.test(tenantId)||typeof subject!=="string"||!subject||typeof verifyToken!=="function"||!owner)throw Error("Completion authority unavailable");
 router.use(rateLimit({windowMs:60000,limit:30,standardHeaders:true,legacyHeaders:false}));
 router.get("/quotes",(req,res)=>req.originalUrl.includes("?")?res.status(404).json({error:"Not found"}):sendPortalPage(res,ownerQuotePage()));
 router.get("/upload",(req,res)=>req.originalUrl.includes("?")?res.status(404).json({error:"Not found"}):sendPortalPage(res,ownerCompletionPage()));
 let uploading=false;
 router.post("/:milestoneId/:action",async(req,res,next)=>{
  if(req.originalUrl.includes("?")||!uuid.test(req.params.milestoneId)||!["status","start","upload","submit","quote-status","publish-quote","offer-plan","withdraw-plan"].includes(req.params.action))return res.status(404).json({error:"Not found"});
  try{
   const token=req.headers.authorization?.match(/^Bearer ([^\s]{1,8192})$/i)?.[1];
   if(!token)return res.status(401).json({error:"Authentication required"});
   const identity=await verifyToken(token);
   if(identity?.subject!==subject)return res.status(403).json({error:"Authorization denied"});
   if(!req.is("application/json"))return res.status(415).json({error:"JSON required"});
   next();
  }catch{return res.status(401).json({error:"Authentication required"});}
 },(req,res,next)=>{
  if(req.params.action!=="upload")return express.json({limit:req.params.action==="offer-plan"?"40kb":"8kb",strict:true})(req,res,next);
  if(uploading)return res.status(429).json({error:"Upload busy"});
  uploading=true;
  let released=false,processing=false,closed=false;
  const release=()=>{if(!released){released=true;uploading=false;}};
  res.on("close",()=>{closed=true;if(!processing)release();});
  express.json({limit:2800000,strict:true})(req,res,e=>{
   if(e||closed){release();if(e)next(e);return;}
   processing=true;res.locals.finishUpload=release;next();
  });
 },async(req,res)=>{
  const {milestoneId,action}=req.params,body=req.body,scope={tenantId,milestoneId};
  try{
   let result;
   if(action==="quote-status"||action==="publish-quote"||action==="offer-plan"||action==="withdraw-plan"){
    const jobId=milestoneId;
    if(action==="quote-status"){
     if(!exact(body,[]))return res.status(400).json({error:"Invalid request"});
     result=await owner.quoteStatus({tenantId,jobId});
    }else if(action==="publish-quote"){
     if(!exact(body,["previousDigest","description","totalCents"])||(body.previousDigest!==null&&!/^[a-f0-9]{64}$/.test(body.previousDigest))||typeof body.description!=="string"||!body.description.trim()||body.description.length>4000||body.description.includes("\0")||!Number.isSafeInteger(body.totalCents)||body.totalCents<=0)return res.status(400).json({error:"Invalid request"});
     result=await owner.publishQuote({tenantId,jobId,...body});
    }else if(action==="offer-plan"){
     if(!exact(body,["items"])||!Array.isArray(body.items)||body.items.length<1||body.items.length>20||body.items.some(x=>!exact(x,["milestoneId","amountCents","description","final"])||!uuid.test(x.milestoneId)||!Number.isSafeInteger(x.amountCents)||x.amountCents<=0||typeof x.description!=="string"||!x.description.trim()||x.description.length>500||x.description.includes("\0")||typeof x.final!=="boolean"))return res.status(400).json({error:"Invalid request"});
     // Only published customer-facing quotes can be offered through this interface.
     const current=await owner.quoteStatus({tenantId,jobId});
     if(!current.ok||!current.view.quote)return res.status(403).json({error:"Authorization denied"});
     result=await owner.offerPlan({tenantId,jobId,items:body.items});
    }else{
     if(!exact(body,["planId"])||!uuid.test(body.planId))return res.status(400).json({error:"Invalid request"});
     const current=await owner.quoteStatus({tenantId,jobId});
     if(!current.ok||current.view.plan?.planId!==body.planId)return res.status(403).json({error:"Authorization denied"});
     result=await owner.withdrawPlan({tenantId,planId:body.planId});
    }
    if(!result?.ok)return res.status(403).json({error:"Authorization denied"});
    if(action==="quote-status")return res.json({mode:"sandbox",moneyMoved:false,view:result.view});
    if(action==="publish-quote")return res.status(201).json({mode:"sandbox",moneyMoved:false,quote:result.quote});
    if(action==="offer-plan")return res.status(201).json({mode:"sandbox",moneyMoved:false,planId:result.planId,planDigest:result.planDigest});
    return res.json({mode:"sandbox",moneyMoved:false,status:"withdrawn"});
   }
   if(action==="status"||action==="start"){
    if(!exact(body,[]))return res.status(400).json({error:"Invalid request"});
    result=await owner[action](scope);
   }else if(action==="submit"){
    if(!exact(body,["completionId","comments"])||!uuid.test(body.completionId)||typeof body.comments!=="string"||body.comments.length>2000||body.comments.includes("\0"))return res.status(400).json({error:"Invalid request"});
    result=await owner.submit({...scope,...body});
   }else{
    if(!exact(body,["completionId","mediaType","content"])||!uuid.test(body.completionId)||!["image/png","image/jpeg"].includes(body.mediaType)||typeof body.content!=="string"||body.content.length>2796204||!/^[A-Za-z0-9+/]+={0,2}$/.test(body.content))return res.status(400).json({error:"Invalid request"});
    const bytes=Buffer.from(body.content,"base64");
    if(bytes.length<8||bytes.length>2097152||bytes.toString("base64")!==body.content)return res.status(400).json({error:"Invalid request"});
    result=await owner.upload({...scope,completionId:body.completionId,mediaType:body.mediaType,content:bytes});
   }
   if(!result?.ok)return res.status(403).json({error:"Authorization denied"});
   if(action==="status")return res.json({mode:"sandbox",moneyMoved:false,view:result.view});
   if(action==="start")return res.status(201).json({mode:"sandbox",moneyMoved:false,completionId:result.completionId});
   if(action==="upload")return res.status(201).json({mode:"sandbox",moneyMoved:false,photoId:result.photoId,digest:result.digest});
   return res.json({mode:"sandbox",moneyMoved:false,status:"submitted"});
  }catch{return res.status(503).json({error:"Completion unavailable"});}
  finally{res.locals.finishUpload?.();}
 });
 router.use((req,res)=>res.status(404).json({error:"Not found"}));
 router.use((err,req,res,next)=>res.status(err.type==="entity.too.large"?413:400).json({error:"Invalid request"}));
 return router;
}
export async function startCompletionService(env=process.env,{scanner}={}){
 if(env.SECUREPAY_COMPLETION_SANDBOX_ENABLED!=="true"||!["development","test"].includes(env.NODE_ENV))throw Error("Completion disabled");
 if([...authoritySecrets,"DATABASE_URL","TENANT_CONTEXT_HMAC_SECRET","SECUREPAY_REPORT_ACTOR_KEY","SECUREPAY_REPORT_DATABASE_URL"].some(k=>env[k]!==undefined))throw Error("Payment, staff or reporting secrets forbidden");
 if(scanner&&env.NODE_ENV!=="test")throw Error("Injected scanner restricted to tests");
 const {SECUREPAY_COMPLETION_ISSUER:issuer,SECUREPAY_COMPLETION_AUDIENCE:audience,SECUREPAY_COMPLETION_REQUIRED_ACR:requiredAcr,SECUREPAY_COMPLETION_JWKS_URL:jwks,SECUREPAY_COMPLETION_SUBJECT:subject,SECUREPAY_COMPLETION_TENANT_ID:tenantId,SECUREPAY_COMPLETION_ACTOR_ID:actorId,SECUREPAY_COMPLETION_DATABASE_URL:databaseUrl,SECUREPAY_COMPLETION_ACTOR_KEY:key}=env;
 const port=Number(env.SECUREPAY_COMPLETION_PORT??"3082");
 if(!issuer||!audience||!env.SECUREPAY_AUTH_AUDIENCE||!env.SECUREPAY_OWNER_AUDIENCE||[env.SECUREPAY_AUTH_AUDIENCE,env.SECUREPAY_OWNER_AUDIENCE,env.SECUREPAY_RECOVERY_AUDIENCE,env.AUTH_AUDIENCE].includes(audience)||!requiredAcr||!subject||!uuid.test(tenantId)||!uuid.test(actorId)||!databaseUrl||!hex.test(key??"")||!Number.isInteger(port)||port<0||port>65535)throw Error("Completion configuration incomplete");
 const url=new URL(jwks);
 if(url.protocol!=="https:"&&!(env.NODE_ENV==="test"&&url.protocol==="http:"&&["127.0.0.1","localhost"].includes(url.hostname)))throw Error("JWKS requires HTTPS");
 if(!scanner){
  if(!hex.test(env.SECUREPAY_COMPLETION_SCAN_KEY??"")||env.SECUREPAY_COMPLETION_SCAN_KEY.toLowerCase()===key.toLowerCase())throw Error("Independent scan key required");
  scanner=makeEvidenceScanner({key:Buffer.from(env.SECUREPAY_COMPLETION_SCAN_KEY,"hex"),keyId:env.SECUREPAY_COMPLETION_SCAN_KEY_ID??"primary",purpose:"completion",scan:clamavScanner(),normalizeJPEG:jpegNormalizer()});
 }
 const pool=new pg.Pool({connectionString:databaseUrl,max:2,connectionTimeoutMillis:5000,statement_timeout:10000,ssl:env.SECUREPAY_COMPLETION_DATABASE_SSL==="true"?{rejectUnauthorized:true}:false});
 try{
  const {rows:[r]}=await pool.query("SELECT current_user AS role");if(r.role!=="securepay_completion_runtime")throw Error("Incorrect completion role");
  const app=express();app.disable("x-powered-by");
  app.use("/v1/securepay-completion",createCompletionRouter({enabled:true,tenantId,subject,verifyToken:createPayerTokenVerifier({issuer,audience,requiredAcr,keyResolver:createRemoteJWKSet(url)}),owner:makeWorkCompletionOwner({pool,actorId,key:Buffer.from(key,"hex"),scanner})}));
  const server=createServer(app);server.requestTimeout=15000;server.headersTimeout=5000;
  await new Promise((resolve,reject)=>{server.once("error",reject);server.listen(port,"127.0.0.1",resolve);});
  return {server,close:async()=>{await new Promise((resolve,reject)=>server.close(e=>e?reject(e):resolve()));await pool.end();}};
 }catch(e){await pool.end();throw e;}
}
if(process.argv[1]===fileURLToPath(import.meta.url)){
 try{
  const service=await startCompletionService();process.stdout.write("SecurePay completion sandbox ready\n");
  let stopping=false;const stop=async()=>{if(stopping)return;stopping=true;try{await service.close();process.exit(0);}catch{process.exit(1);}};process.on("SIGTERM",stop);process.on("SIGINT",stop);
 }catch{process.stderr.write("SecurePay completion startup failed\n");process.exitCode=1;}
}

// SecurePay sandbox endpoints. No provider dispatch or live money handling.
import express from "express";
import rateLimit from "express-rate-limit";
import pg from "pg";
import {createRemoteJWKSet,jwtVerify} from "jose";
import {makeSharedCustomerBudget} from "../securepay/db/shared-budget.mjs";
import {validParticipantRequest,participantOps} from "../securepay/db/participant.mjs";
import {makeEvidenceScanner,clamavScanner,jpegNormalizer} from "../securepay/db/evidence-scanner.mjs";
import {projectParticipant} from "./securepay-participant-view.js";
import {makePayerService} from "../securepay/domain/payer-service.mjs";
import {validKeyId} from "../securepay/db/key-envelope.mjs";
import {createRecoveryVerifier} from "../securepay/db/recovery-grant.mjs";

// Require a distinct customer audience and recently verified MFA assurance.
export function createPayerTokenVerifier({issuer,audience,requiredAcr,keyResolver,clock=()=>Math.floor(Date.now()/1000)}){
 if(!issuer||!audience||!requiredAcr||!keyResolver)throw new Error("SecurePay authentication unavailable");
 return async token=>{
  const {payload}=await jwtVerify(token,keyResolver,{issuer,audience,algorithms:["RS256","ES256"],requiredClaims:["sub","exp","iat","auth_time","acr"],maxTokenAge:"5m",clockTolerance:5});
  const now=clock();
  if(typeof payload.sub!=="string"||!payload.sub||payload.sub.length>512||
     !(payload.aud===audience||(Array.isArray(payload.aud)&&payload.aud.length===1&&payload.aud[0]===audience))||
     payload.acr!==requiredAcr||!Number.isInteger(payload.auth_time)||
     payload.auth_time>now||payload.auth_time<now-300)
   throw new Error("Recent customer assurance required");
  return {subject:payload.sub,authTime:payload.auth_time};
 };
}
export function createSecurePayRouter({enabled=false,verifyToken,service,takeBudget}={}){
 const router=express.Router();
 router.use((req,res,next)=>{
  res.set("Cache-Control","no-store");
  if(!enabled)return res.status(404).json({error:"Not found"});
  next();
 });
 if(!enabled)return router;
 if(typeof verifyToken!=="function"||!service)throw new Error("SecurePay sandbox unavailable");
 router.use(rateLimit({windowMs:60_000,limit:30,standardHeaders:true,legacyHeaders:false}));
 router.use(async(req,res,next)=>{
  try{
   const token=req.headers.authorization?.match(/^Bearer ([^\s]+)$/i)?.[1];
   if(!token)return res.status(401).json({error:"Customer authentication required"});
   req.payerIdentity=await verifyToken(token);
   next();
  }catch{return res.status(401).json({error:"Customer authentication required"});}
 });
 router.use(async(req,res,next)=>{
  if(typeof takeBudget!=="function")return next(); // isolated fixture constructor only
  try{if(!await takeBudget(req.payerIdentity))return res.status(429).json({error:"Too many requests"});next();}
  catch{return res.status(503).json({error:"SecurePay unavailable"});}
 });
 let participantUploading=false;
 router.use((req,res,next)=>{
  if(!req.path.endsWith("/case-upload"))return express.json({limit:"8kb",strict:true})(req,res,next);
  if(!/^\/tenants\/[a-f0-9-]{36}\/milestones\/[a-f0-9-]{36}\/case-upload$/.test(req.path)||req.method!=="POST")return res.status(404).json({error:"Not found"});
  if(participantUploading)return res.status(429).json({error:"Upload busy"});
  participantUploading=true;let released=false,processing=false,closed=false;const release=()=>{if(!released){released=true;participantUploading=false;}};
  res.on("close",()=>{closed=true;if(!processing)release();});
  express.json({limit:2800000,strict:true})(req,res,e=>{if(e||closed){release();if(e)next(e);return;}processing=true;res.locals.finishParticipantUpload=release;next();});
 });
 const handle=fn=>async(req,res)=>{
  try{
   if(!req.is("application/json"))return res.status(415).json({error:"JSON required"});
   const result=await fn(req);
   if(!result?.ok)return res.status(403).json({error:"Authorization denied"});
   // Response whitelist: never return credentials, proof references or raw SQL errors.
   if(result.fundedCancellation)return res.json({mode:"sandbox",moneyMoved:false,cancellation:result.fundedCancellation});
   if(result.negotiatedCase)return res.json({mode:"sandbox",moneyMoved:false,status:"negotiation_opened",caseId:result.negotiatedCase});
   if(result.negotiatedAcknowledged)return res.json({mode:"sandbox",moneyMoved:false,status:"decision_acknowledged"});
   if(result.negotiatedAppealed)return res.json({mode:"sandbox",moneyMoved:false,status:"decision_appealed"});
   if(result.contract)return res.json({mode:"sandbox",moneyMoved:false,contract:result.contract});
   if(result.changeAccepted)return res.json({mode:"sandbox",moneyMoved:false,status:"change_accepted",changeId:result.changeAccepted});
   if(result.plan){if(!result.plan.quote)return res.status(403).json({error:"Authorization denied"});return res.json({mode:"sandbox",moneyMoved:false,...result.plan});}
   if(result.planAccepted)return res.json({mode:"sandbox",moneyMoved:false,status:"plan_accepted",planId:result.planAccepted});
   if(result.completion)return res.json({mode:"sandbox",moneyMoved:false,...result.completion});
   if(result.photo)return res.json({mode:"sandbox",moneyMoved:false,...result.photo});
   if(result.workRejected)return res.json({mode:"sandbox",moneyMoved:false,status:"work_rejected"});
   if(result.disputeOpened)return res.json({mode:"sandbox",moneyMoved:false,status:"dispute_opened",caseId:result.disputeOpened});
   if(result.workApproved)return res.json({mode:"sandbox",moneyMoved:false,status:"work_approved"});
   if(result.view)return res.status(200).json({mode:"sandbox",moneyMoved:false,...result.view});
   if(result.releaseRequestId)return res.status(202).json({
      mode:"sandbox",status:"reserved",releaseRequestId:result.releaseRequestId,
      milestoneId:result.milestoneId,amountCents:String(result.amountCents),moneyMoved:false
   });
   if(result.grantRef)return res.status(201).json({mode:"sandbox",status:"grant_issued",grantRef:result.grantRef});
   return res.status(200).json({mode:"sandbox",status:"pin_updated"});
  }catch(e){
   const status=e.status===400?400:e.code==="23505"?409:e.message==="Payer context denied"?403:503;
   return res.status(status).json({error:status===400?"Invalid request":status===409?"Conflicting request":status===403?"Authorization denied":"SecurePay unavailable"});
  }
 };
 for(const [route,method] of [["funded-cancellation","fundedCancellation"],["accept-funded-cancellation","acceptFundedCancellation"],["ack-negotiated","acknowledgeNegotiated"],["appeal-negotiated","appealNegotiated"]])router.post("/tenants/:tenantId/plans/:planId/"+route,handle(req=>service[method]({identity:req.payerIdentity,tenantId:req.params.tenantId,planId:req.params.planId,body:req.body})));
 router.post("/tenants/:tenantId/plans/:planId/contract",handle(req=>service.contract({identity:req.payerIdentity,tenantId:req.params.tenantId,planId:req.params.planId,body:req.body})));
 router.post("/tenants/:tenantId/plans/:planId/accept-change",handle(req=>service.acceptChange({identity:req.payerIdentity,tenantId:req.params.tenantId,planId:req.params.planId,body:req.body})));
 router.post("/tenants/:tenantId/plans/:planId/view",handle(req=>service.plan({identity:req.payerIdentity,tenantId:req.params.tenantId,planId:req.params.planId,body:req.body})));
 router.post("/tenants/:tenantId/plans/:planId/accept",handle(req=>service.acceptPlan({identity:req.payerIdentity,tenantId:req.params.tenantId,planId:req.params.planId,body:req.body,requireQuote:true})));
 router.post("/tenants/:tenantId/pin/grant",handle(req=>service.issueGrant({identity:req.payerIdentity,tenantId:req.params.tenantId,body:req.body})));
 router.post("/tenants/:tenantId/pin",handle(req=>service.setPin({identity:req.payerIdentity,tenantId:req.params.tenantId,body:req.body})));
 for(const op of participantOps)router.post("/tenants/:tenantId/milestones/:milestoneId/case-"+op,async(req,res)=>{
  try{if(req.originalUrl.includes("?")||!req.is("application/json")||!validParticipantRequest(op,req.body))return res.status(400).json({error:"Invalid request"});
   const {tenantId,milestoneId}=req.params,r=await service.participant({identity:req.payerIdentity,tenantId,milestoneId,op,body:req.body});
   if(!r?.ok)return res.status(403).json({error:"Authorization denied"});
   return res.json({mode:"sandbox",moneyMoved:false,participant:projectParticipant(op,r.participant,milestoneId,"customer",req.body)});
  }catch(e){const status=e.status===400?400:e.message==="Payer context denied"?403:503;return res.status(status).json({error:status===400?"Invalid request":status===403?"Authorization denied":"SecurePay unavailable"});}finally{res.locals.finishParticipantUpload?.();}
 });
 for(const action of ["completion","photo","approve","reject","dispute"])router.post("/tenants/:tenantId/milestones/:milestoneId/"+action,handle(req=>service[action]({identity:req.payerIdentity,tenantId:req.params.tenantId,milestoneId:req.params.milestoneId,body:req.body})));
 router.post("/tenants/:tenantId/milestones/:milestoneId/view",handle(req=>service.view({identity:req.payerIdentity,tenantId:req.params.tenantId,milestoneId:req.params.milestoneId,body:req.body})));
 router.post("/tenants/:tenantId/milestones/:milestoneId/reserve",handle(req=>service.reserve({identity:req.payerIdentity,tenantId:req.params.tenantId,milestoneId:req.params.milestoneId,body:req.body})));
 router.use((err,req,res,next)=>res.status(err.type==="entity.too.large"?413:400).json({error:"Invalid request"}));
 return router;
}
export function createSecurePayRouterFromEnv(env=process.env){
 // Deliberate deployment gate: no production enablement until independent review.
 if(env.SECUREPAY_SANDBOX_ENABLED!=="true"||!["development","test"].includes(env.NODE_ENV))return createSecurePayRouter();
 const {SECUREPAY_AUTH_ISSUER:issuer,SECUREPAY_AUTH_AUDIENCE:audience,SECUREPAY_AUTH_JWKS_URL:jwks,SECUREPAY_AUTH_REQUIRED_ACR:requiredAcr,SECUREPAY_DATABASE_URL:databaseUrl}=env;
 const hex=/^[a-f0-9]{64}$/i;
 if(!issuer||!audience||audience===env.AUTH_AUDIENCE||!jwks||!requiredAcr||!databaseUrl||
    !hex.test(env.SECUREPAY_CONTEXT_HMAC_SECRET??"")||!hex.test(env.SECUREPAY_PIN_PEPPER??"")||!hex.test(env.SECUREPAY_COMMAND_KEY??"")||!hex.test(env.SECUREPAY_RATE_LIMIT_KEY??"")||
    [env.SECUREPAY_CONTEXT_HMAC_SECRET,env.SECUREPAY_PIN_PEPPER,env.SECUREPAY_COMMAND_KEY,env.SECUREPAY_RECOVERY_KEY,env.TENANT_CONTEXT_HMAC_SECRET].some(k=>k?.toLowerCase()===env.SECUREPAY_RATE_LIMIT_KEY.toLowerCase())||!validKeyId(env.SECUREPAY_CONTEXT_KEY_ID??"primary")||!validKeyId(env.SECUREPAY_COMMAND_KEY_ID??"primary")||
    [env.SECUREPAY_CONTEXT_HMAC_SECRET,env.SECUREPAY_PIN_PEPPER,env.TENANT_CONTEXT_HMAC_SECRET].some(k=>k?.toLowerCase()===env.SECUREPAY_COMMAND_KEY.toLowerCase())||
    env.SECUREPAY_CONTEXT_HMAC_SECRET.toLowerCase()===env.SECUREPAY_PIN_PEPPER.toLowerCase()||
    [env.SECUREPAY_CONTEXT_HMAC_SECRET,env.SECUREPAY_PIN_PEPPER].some(k=>k.toLowerCase()===(env.TENANT_CONTEXT_HMAC_SECRET??"").toLowerCase())||databaseUrl===env.DATABASE_URL)
  throw new Error("SecurePay sandbox configuration incomplete");
 const jwksUrl=new URL(jwks);
 if(jwksUrl.protocol!=="https:"&&!(env.NODE_ENV==="test"&&jwksUrl.protocol==="http:"&&["127.0.0.1","localhost"].includes(jwksUrl.hostname)))
  throw new Error("SecurePay JWKS requires HTTPS");
 const pool=new pg.Pool({connectionString:databaseUrl,max:4,connectionTimeoutMillis:5000,statement_timeout:10000,ssl:env.SECUREPAY_DATABASE_SSL==="true"?{rejectUnauthorized:true}:false});
 const recovery={};
 if(env.SECUREPAY_RECOVERY_ENABLED==="true"){
  const recoveryAudience=env.SECUREPAY_RECOVERY_AUDIENCE, recoveryAcr=env.SECUREPAY_RECOVERY_REQUIRED_ACR;
  const recoveryJwks=new URL(env.SECUREPAY_RECOVERY_JWKS_URL||"");
  const recoveryIssuer=env.SECUREPAY_RECOVERY_ISSUER;
  if(!recoveryIssuer||!recoveryAudience||recoveryAudience===audience||recoveryAudience===env.AUTH_AUDIENCE||!recoveryAcr||
     !hex.test(env.SECUREPAY_RECOVERY_KEY??"")||
     [env.SECUREPAY_CONTEXT_HMAC_SECRET,env.SECUREPAY_PIN_PEPPER,env.SECUREPAY_COMMAND_KEY,env.TENANT_CONTEXT_HMAC_SECRET].some(k=>k?.toLowerCase()===env.SECUREPAY_RECOVERY_KEY.toLowerCase())||!validKeyId(env.SECUREPAY_RECOVERY_KEY_ID??"primary")||
     (recoveryJwks.protocol!=="https:"&&!(env.NODE_ENV==="test"&&recoveryJwks.protocol==="http:"&&["127.0.0.1","localhost"].includes(recoveryJwks.hostname))))
   throw new Error("SecurePay recovery configuration incomplete");
  recovery.recoveryKeyId=env.SECUREPAY_RECOVERY_KEY_ID??"primary";
  recovery.recoveryKey=Buffer.from(env.SECUREPAY_RECOVERY_KEY,"hex");
  recovery.verifyRecovery=createRecoveryVerifier({issuer:recoveryIssuer,audience:recoveryAudience,requiredAcr:recoveryAcr,keyResolver:createRemoteJWKSet(recoveryJwks)});
 }
 let disputeScanner;
 if(env.SECUREPAY_DISPUTE_SCAN_KEY!==undefined){if(!hex.test(env.SECUREPAY_DISPUTE_SCAN_KEY)||[env.SECUREPAY_CONTEXT_HMAC_SECRET,env.SECUREPAY_PIN_PEPPER,env.SECUREPAY_COMMAND_KEY,env.SECUREPAY_RATE_LIMIT_KEY,env.SECUREPAY_RECOVERY_KEY,env.TENANT_CONTEXT_HMAC_SECRET].some(k=>k?.toLowerCase()===env.SECUREPAY_DISPUTE_SCAN_KEY.toLowerCase()))throw Error("Independent dispute scan key required");disputeScanner=makeEvidenceScanner({key:Buffer.from(env.SECUREPAY_DISPUTE_SCAN_KEY,"hex"),keyId:env.SECUREPAY_DISPUTE_SCAN_KEY_ID??"primary",scan:clamavScanner({timeoutMs:7000}),normalizeJPEG:jpegNormalizer({timeoutMs:4000})});}
 const service=makePayerService({pool,disputeScanner,signingKey:Buffer.from(env.SECUREPAY_CONTEXT_HMAC_SECRET,"hex"),pepper:Buffer.from(env.SECUREPAY_PIN_PEPPER,"hex"),contextKeyId:env.SECUREPAY_CONTEXT_KEY_ID??"primary",commandAuthority:{id:env.SECUREPAY_COMMAND_KEY_ID??"primary",key:Buffer.from(env.SECUREPAY_COMMAND_KEY,"hex")},...recovery});
 return createSecurePayRouter({enabled:true,service,takeBudget:makeSharedCustomerBudget({pool,key:Buffer.from(env.SECUREPAY_RATE_LIMIT_KEY,"hex"),issuer}),verifyToken:createPayerTokenVerifier({issuer,audience,requiredAcr,keyResolver:createRemoteJWKSet(jwksUrl)})});
}

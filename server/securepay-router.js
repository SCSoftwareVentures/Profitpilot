// SecurePay sandbox endpoints. No provider dispatch or live money handling.
import express from "express";
import rateLimit from "express-rate-limit";
import pg from "pg";
import {createRemoteJWKSet,jwtVerify} from "jose";
import {makePayerService} from "../securepay/domain/payer-service.mjs";

// Require a distinct customer audience and recently verified MFA assurance.
export function createPayerTokenVerifier({issuer,audience,requiredAcr,keyResolver,clock=()=>Math.floor(Date.now()/1000)}){
 if(!issuer||!audience||!requiredAcr||!keyResolver)throw new Error("SecurePay authentication unavailable");
 return async token=>{
  const {payload}=await jwtVerify(token,keyResolver,{issuer,audience,algorithms:["RS256","ES256"],requiredClaims:["sub","exp","iat","auth_time","acr"],maxTokenAge:"5m",clockTolerance:5});
  const now=clock();
  if(typeof payload.sub!=="string"||!payload.sub||payload.sub.length>512||
     payload.acr!==requiredAcr||!Number.isInteger(payload.auth_time)||
     payload.auth_time>now+5||payload.auth_time<now-300)
   throw new Error("Recent customer assurance required");
  return {subject:payload.sub};
 };
}
export function createSecurePayRouter({enabled=false,verifyToken,service}={}){
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
 router.use(express.json({limit:"8kb",strict:true}));
 const handle=fn=>async(req,res)=>{
  try{
   if(!req.is("application/json"))return res.status(415).json({error:"JSON required"});
   const result=await fn(req);
   if(!result?.ok)return res.status(403).json({error:"Authorization denied"});
   // Response whitelist: never return credentials, proof references or raw SQL errors.
   if(result.releaseRequestId)return res.status(202).json({
      mode:"sandbox",status:"reserved",releaseRequestId:result.releaseRequestId,
      milestoneId:result.milestoneId,amountCents:String(result.amountCents),moneyMoved:false
   });
   return res.status(200).json({mode:"sandbox",status:"pin_updated"});
  }catch(e){
   const status=e.status===400?400:e.code==="23505"?409:e.message==="Payer context denied"?403:503;
   return res.status(status).json({error:status===400?"Invalid request":status===409?"Conflicting request":status===403?"Authorization denied":"SecurePay unavailable"});
  }
 };
 router.post("/tenants/:tenantId/pin",handle(req=>service.setPin({identity:req.payerIdentity,tenantId:req.params.tenantId,body:req.body})));
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
    !hex.test(env.SECUREPAY_CONTEXT_HMAC_SECRET??"")||!hex.test(env.SECUREPAY_PIN_PEPPER??"")||
    env.SECUREPAY_CONTEXT_HMAC_SECRET.toLowerCase()===env.SECUREPAY_PIN_PEPPER.toLowerCase())
  throw new Error("SecurePay sandbox configuration incomplete");
 const jwksUrl=new URL(jwks);
 if(jwksUrl.protocol!=="https:"&&!(env.NODE_ENV==="test"&&jwksUrl.protocol==="http:"&&["127.0.0.1","localhost"].includes(jwksUrl.hostname)))
  throw new Error("SecurePay JWKS requires HTTPS");
 const pool=new pg.Pool({connectionString:databaseUrl,max:4,connectionTimeoutMillis:5000,statement_timeout:10000,ssl:env.SECUREPAY_DATABASE_SSL==="true"?{rejectUnauthorized:true}:false});
 const service=makePayerService({pool,signingKey:Buffer.from(env.SECUREPAY_CONTEXT_HMAC_SECRET,"hex"),pepper:Buffer.from(env.SECUREPAY_PIN_PEPPER,"hex")});
 return createSecurePayRouter({enabled:true,service,verifyToken:createPayerTokenVerifier({issuer,audience,requiredAcr,keyResolver:createRemoteJWKSet(jwksUrl)})});
}

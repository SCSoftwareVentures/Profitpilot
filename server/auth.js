import {createRemoteJWKSet, jwtVerify} from "jose";
import {withTenant,registerAndCheckAuthSession} from "./db.js";

let jwks;
let jwksUrl;

function config(){
 const {AUTH_ISSUER,AUTH_AUDIENCE,AUTH_JWKS_URL}=process.env;
 if(!AUTH_ISSUER||!AUTH_AUDIENCE||!AUTH_JWKS_URL){
  const error=new Error("Authentication configuration is incomplete");
  error.code="AUTH_NOT_CONFIGURED";
  throw error;
 }
 let url;
 try{url=new URL(AUTH_JWKS_URL);}catch{
  const error=new Error("Authentication JWKS URL is invalid");
  error.code="AUTH_CONFIG_INVALID";
  throw error;
 }
 const localHttp=url.protocol==="http:"&&["localhost","127.0.0.1","::1"].includes(url.hostname);
 if(url.protocol!=="https:"&&!(process.env.NODE_ENV!=="production"&&localHttp)){
  const error=new Error("Authentication JWKS endpoint must use HTTPS");
  error.code="AUTH_CONFIG_INVALID";
  throw error;
 }
 if(url.username||url.password||url.hash){
  const error=new Error("Authentication JWKS URL contains prohibited URL components");
  error.code="AUTH_CONFIG_INVALID";
  throw error;
 }
 return {issuer:AUTH_ISSUER,audience:AUTH_AUDIENCE,url};
}

function remoteKeys(url){
 const value=url.href;
 if(!jwks||jwksUrl!==value){
  jwks=createRemoteJWKSet(url,{timeoutDuration:5000,cooldownDuration:30000,cacheMaxAge:300000});
  jwksUrl=value;
 }
 return jwks;
}

export function authRequired(){
 return async(req,res,next)=>{
  let c;
  try{c=config();}catch{return res.status(503).json({error:"Authentication service is not configured"});}
  const token=req.headers.authorization?.match(/^Bearer\\s+([^\\s]+)$/i)?.[1];
  if(!token)return res.status(401).json({error:"Authentication required"});
  if(token.length>8192)return res.status(401).json({error:"Invalid access token"});
  let payload;
  try{
   const verified=await jwtVerify(token,remoteKeys(c.url),{
    issuer:c.issuer,
    audience:c.audience,
    algorithms:["RS256","ES256"],
    requiredClaims:["exp","iat","sub","jti"],
    clockTolerance:5
   });
   payload=verified.payload;
   const now=Date.now()/1000;
   if(typeof payload.iat!=="number"||!Number.isFinite(payload.iat)||payload.iat>now+5||now-payload.iat>900)return res.status(401).json({error:"Invalid or expired access token"});
   if(typeof payload.exp!=="number"||!Number.isFinite(payload.exp)||typeof payload.jti!=="string"||payload.jti.length<16||payload.jti.length>128)return res.status(401).json({error:"Invalid access token"});
   if(typeof payload.sub!=="string"||!payload.sub.trim())return res.status(401).json({error:"Invalid access token"});
  }catch{return res.status(401).json({error:"Invalid or expired access token"});}
  let revoked;
  try{
   revoked=await registerAndCheckAuthSession({jti:payload.jti,subject:payload.sub,issuedAt:payload.iat,expiresAt:payload.exp});
  }catch{
   return res.status(503).json({error:"Session security service unavailable"});
  }
  if(revoked)return res.status(401).json({error:"Session revoked or unavailable"});
  req.identity={subject:payload.sub,email:typeof payload.email==="string"?payload.email:null,jti:payload.jti,authTime:Number.isInteger(payload.auth_time)?payload.auth_time:null,acr:typeof payload.acr==="string"?payload.acr:null};
  return next();
 };
}

export function requireRole(...roles){
 return (req,res,next)=>{
  if(!req.membership||!roles.includes(req.membership.role))return res.status(403).json({error:"Insufficient tenant role"});
  return next();
 };
}

export function requirePermission(permission){
 return async(req,res,next)=>{
  if(!req.membership)return res.status(403).json({error:"Insufficient tenant permission"});
  try{
   const result=await withTenant(req.membership.tenantId,req.identity.subject,client=>client.query(
    `SELECT CASE
      WHEN EXISTS (
       SELECT 1 FROM tenant_membership_permission_overrides o
       WHERE o.tenant_id=$1 AND o.user_id=$2 AND o.permission_key=$3 AND o.effect='deny'
      ) THEN false
      WHEN EXISTS (
       SELECT 1 FROM tenant_membership_permission_overrides o
       WHERE o.tenant_id=$1 AND o.user_id=$2 AND o.permission_key=$3 AND o.effect='grant'
      ) THEN true
      ELSE EXISTS (
       SELECT 1 FROM role_permissions rp
       WHERE rp.role=$4 AND rp.permission_key=$3
      )
     END AS allowed`,
    [req.membership.tenantId,req.membership.userId,permission,req.membership.role]
   ));
   if(!result.rows[0]?.allowed)return res.status(403).json({error:"Insufficient tenant permission"});
   return next();
  }catch(error){return next(error);}
 };
}

export function requireStepUp(){
 return (req,res,next)=>{
  const requiredAcr=process.env.AUTH_STEP_UP_ACR;
  const maxAge=Number(process.env.AUTH_STEP_UP_MAX_AGE_SECONDS||300);
  const authTime=req.identity?.authTime;
  const now=Math.floor(Date.now()/1000);
  const fresh=Number.isInteger(authTime)&&authTime<=now+5&&now-authTime<=maxAge;
  const acr=req.identity?.acr;
  if(!requiredAcr||!Number.isInteger(maxAge)||maxAge<30||maxAge>900||!fresh||acr!==requiredAcr){
   return res.status(403).json({error:"Recent step-up authentication required"});
  }
  return next();
 };
}

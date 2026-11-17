import {createRemoteJWKSet, jwtVerify} from "jose";
import {withTenant,registerAndCheckAuthSession} from "./db.js";
import {validAccessClaims} from "../src/access-claims.js";
import {withVerifiedRequestIdentity} from "./request-identity.js";

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
 const localHttp=url.protocol==="http:"&&["localhost","127.0.0.1","[::1]"].includes(url.hostname);
 if(process.env.NODE_TLS_REJECT_UNAUTHORIZED==="0")throw Object.assign(new Error("TLS verification disabled"),{code:"AUTH_CONFIG_INVALID"});
 if(url.protocol!=="https:"&&!(process.env.NODE_ENV!=="production"&&localHttp)){
  const error=new Error("Authentication JWKS endpoint must use HTTPS");
  error.code="AUTH_CONFIG_INVALID";
  throw error;
 }
 if(url.username||url.password||url.hash||url.search){
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
  const token=req.headers.authorization?.match(/^Bearer\s+([^\s]+)$/i)?.[1];
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
   // In production accept only explicit RFC 9068 access-token media types.
   // Generic JWT/ID-token profiles must not be accepted as access tokens.
   if((process.env.NODE_ENV==="production"||process.env.AUTH_REQUIRE_ACCESS_TOKEN_TYPE==="true")&&!["at+jwt","application/at+jwt"].includes(verified.protectedHeader.typ?.toLowerCase()))return res.status(401).json({error:"Invalid access token type"});
   payload=verified.payload;
   if(!validAccessClaims(payload))return res.status(401).json({error:"Invalid or expired access token"});
  }catch{return res.status(401).json({error:"Invalid or expired access token"});}
  const authTime=Number.isSafeInteger(payload.auth_time)&&payload.auth_time>=0&&payload.auth_time<=payload.iat+5?payload.auth_time:null;
  let revoked;
  try{
   revoked=await registerAndCheckAuthSession({jti:payload.jti,subject:payload.sub,issuer:c.issuer,issuedAt:payload.iat,expiresAt:payload.exp,authTime});
  }catch{
   return res.status(503).json({error:"Session security service unavailable"});
  }
  if(revoked)return res.status(401).json({error:"Session revoked or unavailable"});
  req.identity={subject:payload.sub,email:typeof payload.email==="string"?payload.email:null,emailVerified:payload.email_verified===true,issuedAt:payload.iat,expiresAt:payload.exp,issuer:c.issuer,jti:payload.jti,authTime,acr:typeof payload.acr==="string"?payload.acr:null,amr:Array.isArray(payload.amr)&&payload.amr.every(v=>typeof v==="string")?payload.amr:[]};
  return withVerifiedRequestIdentity(req.identity,next);
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
    "SELECT private.has_scoped_permission($1,$2) AS allowed",
    [req.membership.tenantId,permission]
   ));
   if(!result.rows[0]?.allowed)return res.status(403).json({error:"Insufficient tenant permission"});
   return next();
  }catch(error){return next(error);}
 };
}

export function requireStepUp(){
 return (req,res,next)=>{
  const requiredAcr=process.env.AUTH_STEP_UP_ACR;
  const maxAge=Number(process.env.AUTH_STEP_UP_MAX_AGE_SECONDS??300);
  const authTime=req.identity?.authTime;
  const now=Math.floor(Date.now()/1000);
  const fresh=Number.isSafeInteger(authTime)&&authTime>=0&&authTime<=now&&now-authTime<=maxAge;
  const acr=req.identity?.acr;
  const hasMfa=Array.isArray(req.identity?.amr)&&req.identity.amr.includes("mfa");
  if(!hasMfa||!requiredAcr||!Number.isInteger(maxAge)||maxAge<30||maxAge>900||!fresh||acr!==requiredAcr){
   return res.status(403).json({error:"Recent step-up authentication required"});
  }
  return next();
 };
}

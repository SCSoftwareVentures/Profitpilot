import {createRemoteJWKSet, jwtVerify} from "jose";

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
 if(url.protocol!=="https:"&&!(process.env.NODE_ENV==="test"&&localHttp)){
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
  try{
   c=config();
  }catch(error){
   return res.status(503).json({error:"Authentication service is not configured"});
  }
  const token=req.headers.authorization?.match(/^Bearer\\s+([^\\s]+)$/i)?.[1];
  if(!token)return res.status(401).json({error:"Authentication required"});
  if(token.length>16384)return res.status(401).json({error:"Invalid access token"});
  try{
   const {payload}=await jwtVerify(token,remoteKeys(c.url),{
    issuer:c.issuer,
    audience:c.audience,
    algorithms:["RS256","ES256"],
    requiredClaims:["exp","iat","sub"],
    maxTokenAge:"15m",
    clockTolerance:5
   });
   if(typeof payload.sub!=="string"||!payload.sub.trim())return res.status(401).json({error:"Invalid access token"});
   req.identity={subject:payload.sub,email:typeof payload.email==="string"?payload.email:null};
   return next();
  }catch{
   return res.status(401).json({error:"Invalid or expired access token"});
  }
 };
}

export function requireRole(...roles){
 return (req,res,next)=>{
  if(!req.membership||!roles.includes(req.membership.role))return res.status(403).json({error:"Insufficient tenant role"});
  return next();
 };
}

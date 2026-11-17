import {createRemoteJWKSet, jwtVerify} from "jose";

let jwks;
let jwksUrl;
function cIssuerIsHttps(value){try{return new URL(value).protocol==="https:";}catch{return false;}}
function config(){
 const {AUTH_ISSUER,AUTH_AUDIENCE,AUTH_JWKS_URL,NODE_ENV}=process.env;
 if(!AUTH_ISSUER||!AUTH_AUDIENCE||!AUTH_JWKS_URL)throw new Error("Authentication is not configured");
 const url=new URL(AUTH_JWKS_URL);
 if(NODE_ENV==="production"&&(url.protocol!=="https:"||!cIssuerIsHttps(AUTH_ISSUER)))throw new Error("Production issuer and JWKS endpoints must use HTTPS");
 return {issuer:AUTH_ISSUER,audience:AUTH_AUDIENCE,url};
}
export function authRequired(){
 return async(req,res,next)=>{
  try{
   const c=config();
   if(!jwks||jwksUrl!==c.url.href){
    jwks=createRemoteJWKSet(c.url,{timeoutDuration:5000,cacheMaxAge:300000,cooldownDuration:0});
    jwksUrl=c.url.href;
   }
   const token=req.headers.authorization?.match(/^Bearer\s+([^\s]+)$/i)?.[1];
   if(!token)return res.status(401).json({error:"Authentication required"});
   const {payload}=await jwtVerify(token,jwks,{
    issuer:c.issuer,
    audience:c.audience,
    algorithms:["RS256","ES256"],
    requiredClaims:["exp","iat","sub"],
    maxTokenAge:"15m",
    clockTolerance:5
   });
   if(typeof payload.sub!=="string"||!payload.sub||payload.sub.length>255)return res.status(401).json({error:"Invalid identity subject"});
   req.identity={subject:payload.sub,email:typeof payload.email==="string"?payload.email:null,authTime:payload.auth_time,issuedAt:payload.iat,mfa:Array.isArray(payload.amr)&&payload.amr.includes("mfa")};
   next();
  }catch(e){
   const unavailable=e.message==="Authentication is not configured"||e.message==="Production issuer and JWKS endpoints must use HTTPS";
   res.status(unavailable?503:401).json({error:unavailable?"Authentication unavailable":"Invalid or expired access token"});
  }
 };
}
export function requireRole(...roles){
 return (req,res,next)=>{if(!req.membership||!roles.includes(req.membership.role))return res.status(403).json({error:"Insufficient tenant role"});next();};
}

 // Only a verified issuer's explicit MFA claim and authentication timestamp count.
 // A recently refreshed access token alone does not prove recent authentication.
export function hasRecentMfa(identity,now=Math.floor(Date.now()/1000)){
 return identity?.mfa===true&&Number.isSafeInteger(identity.authTime)&&Number.isSafeInteger(identity.issuedAt)&&
  identity.authTime>0&&identity.authTime<=identity.issuedAt+5&&identity.authTime<=now+5&&now-identity.authTime<=300;
}
export function requireRecentMfa(req,res,next){
 if(!hasRecentMfa(req.identity))return res.status(403).json({error:"Recent multi-factor authentication required",code:"STEP_UP_REQUIRED"});
 next();
}

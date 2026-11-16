import {createRemoteJWKSet, jwtVerify} from "jose";

let jwks;
let jwksUrl;
function config(){
 const {AUTH_ISSUER,AUTH_AUDIENCE,AUTH_JWKS_URL,NODE_ENV}=process.env;
 if(!AUTH_ISSUER||!AUTH_AUDIENCE||!AUTH_JWKS_URL)throw new Error("Authentication is not configured");
 const url=new URL(AUTH_JWKS_URL);
 if(NODE_ENV==="production"&&url.protocol!=="https:")throw new Error("Production JWKS endpoint must use HTTPS");
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
   const token=req.headers.authorization?.match(/^Bearer\\s+([^\\s]+)$/i)?.[1];
   if(!token)return res.status(401).json({error:"Authentication required"});
   const {payload}=await jwtVerify(token,jwks,{
    issuer:c.issuer,
    audience:c.audience,
    algorithms:["RS256","ES256"],
    requiredClaims:["exp","iat","sub"],
    maxTokenAge:"15m",
    clockTolerance:5
   });
   if(typeof payload.sub!=="string"||!payload.sub)return res.status(401).json({error:"Invalid identity subject"});
   req.identity={subject:payload.sub,email:typeof payload.email==="string"?payload.email:null};
   next();
  }catch(e){
   const unavailable=e.message==="Authentication is not configured"||e.message==="Production JWKS endpoint must use HTTPS";
   res.status(unavailable?503:401).json({error:unavailable?"Authentication unavailable":"Invalid or expired access token"});
  }
 };
}
export function requireRole(...roles){
 return (req,res,next)=>{if(!req.membership||!roles.includes(req.membership.role))return res.status(403).json({error:"Insufficient tenant role"});next();};
}

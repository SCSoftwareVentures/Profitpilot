import {createRemoteJWKSet, jwtVerify} from "jose";
let jwks;
function config(){
 const {AUTH_ISSUER,AUTH_AUDIENCE,AUTH_JWKS_URL}=process.env;
 if(!AUTH_ISSUER||!AUTH_AUDIENCE||!AUTH_JWKS_URL)throw new Error("Authentication is not configured. Set AUTH_ISSUER, AUTH_AUDIENCE and AUTH_JWKS_URL.");
 return {issuer:AUTH_ISSUER,audience:AUTH_AUDIENCE,url:new URL(AUTH_JWKS_URL)};
}
export function authRequired(){
 return async(req,res,next)=>{
  try{
   const c=config();
   if(!jwks)jwks=createRemoteJWKSet(c.url);
   const token=req.headers.authorization?.match(/^Bearer\s+(.+)$/i)?.[1];
   if(!token)return res.status(401).json({error:"Authentication required"});
   const {payload}=await jwtVerify(token,jwks,{issuer:c.issuer,audience:c.audience,algorithms:["RS256","ES256"]});
   if(typeof payload.sub!=="string"||!payload.sub)return res.status(401).json({error:"Invalid identity subject"});
   req.identity={subject:payload.sub,email:typeof payload.email==="string"?payload.email:null};
   next();
  }catch(e){res.status(401).json({error:e.message.includes("not configured")?"Authentication unavailable":"Invalid or expired access token"});}
 };
}
export function requireRole(...roles){
 return (req,res,next)=>{if(!req.membership||!roles.includes(req.membership.role))return res.status(403).json({error:"Insufficient tenant role"});next();};
}

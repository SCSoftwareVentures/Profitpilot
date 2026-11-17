// Process-local account quota supplements the IP rate cap. Never retain raw subjects.
import {createHmac,randomBytes} from "node:crypto";
import rateLimit from "express-rate-limit";
export function accountRateLimit({limit=60,windowMs=60_000}={}){
 const key=randomBytes(32);
 const limiter=rateLimit({windowMs,limit,standardHeaders:true,legacyHeaders:false,
  keyGenerator:req=>createHmac("sha256",key).update(req.identity.subject).digest("hex"),
  message:{error:"Account request limit exceeded"}});
 return (req,res,next)=>{
  if(typeof req.identity?.subject!=="string"||!req.identity.subject)return res.status(401).json({error:"Authentication required"});
  return limiter(req,res,next);
 };
}

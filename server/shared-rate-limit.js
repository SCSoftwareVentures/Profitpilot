import {createHmac} from "node:crypto";
import {pool} from "./db.js";
// Atomic shared fixed-window counters across API replicas. Fail closed on DB errors.
export function sharedLimiter({limit,windowMs=60000,scope}){
 if(!Number.isSafeInteger(limit)||limit<1||!Number.isSafeInteger(windowMs)||windowMs<1000||!scope)throw new Error("Invalid rate limit configuration");
 return async(req,res,next)=>{
  try{
   const secret=process.env.RATE_LIMIT_HASH_SECRET||process.env.TENANT_CONTEXT_HMAC_SECRET;
   if(!secret||!/^[a-f0-9]{64,}$/i.test(secret))throw new Error("Rate limit hashing secret unavailable");
   const ip=req.ip||req.socket.remoteAddress||"unknown";
   const digest=createHmac("sha256",Buffer.from(secret,"hex")).update(scope+"\n"+ip).digest("hex");
   const bucket=scope+":"+digest;
   const start=Math.floor(Date.now()/windowMs);
   const result=await pool.query(`INSERT INTO api_rate_limits(bucket_key,window_start,request_count) VALUES($1,$2,1)
    ON CONFLICT(bucket_key,window_start) DO UPDATE SET request_count=api_rate_limits.request_count+1
    RETURNING request_count`,[bucket,start]);
   const count=result.rows[0].request_count;
   const retryAfter=Math.max(1,Math.ceil(((start+1)*windowMs-Date.now())/1000));
   res.set("RateLimit-Limit",String(limit));
   res.set("RateLimit-Remaining",String(Math.max(0,limit-count)));
   if(count>limit){res.set("Retry-After",String(retryAfter));return res.status(429).json({error:"Too many requests; retry later"});}
   next();
  }catch{
   res.set("Retry-After","5");
   return res.status(503).json({error:"Request protection temporarily unavailable"});
  }
 };
}

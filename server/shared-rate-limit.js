import {createHmac} from "node:crypto";
import {isIP} from "node:net";
import {pool} from "./db.js";

// Production replicas must share the same independent rate-limit key.
// Never reuse or fall back to the tenant-signing secret.
export function sharedLimiter({limit,windowMs=60000,scope},db=pool,env=process.env){
 if(windowMs!==60000||!Object.hasOwn({global:100,write:60},scope)||limit!==({global:100,write:60})[scope])throw new Error("Invalid rate limit configuration");
 let pending=0;
 return async(req,res,next)=>{
  // Bound per-instance pressure on the DB connection pool.
  const unavailable=()=>{res.set("Retry-After","5");return res.status(503).json({error:"Request protection temporarily unavailable"});};
  if(pending>=20)return unavailable();
  pending++;
  try{
   const secret=env.RATE_LIMIT_HASH_SECRET;
   if(!secret||!/^[a-f0-9]{64}$/i.test(secret))throw new Error("Rate limit hashing secret unavailable");
   const ip=req.ip||req.socket.remoteAddress;
   if(typeof ip!=="string"||!isIP(ip))throw new Error("Client address unavailable");
   // Canonicalize IPv4-mapped IPv6 and use a /64 for IPv6 to curb address rotation.
   let address=ip.toLowerCase();
   if(address.startsWith("::ffff:")&&isIP(address.slice(7))===4)address=address.slice(7);
   if(isIP(address)===6){
    const canonical=new URL("http://["+address+"]/").hostname.slice(1,-1);
    const [head,tail]=canonical.split("::");
    const a=head?head.split(":"):[],z=tail?tail.split(":"):[];
    const parts=tail===undefined?a:[...a,...Array(8-a.length-z.length).fill("0"),...z];
    const words=parts.map(x=>parseInt(x,16));
    if(words.slice(0,5).every(x=>x===0)&&words[5]===65535){
     address=[words[6]>>8,words[6]&255,words[7]>>8,words[7]&255].join(".");
    }else address=parts.slice(0,4).map(x=>x.padStart(4,"0")).join(":")+"::/64";
   }
   const digest=createHmac("sha256",Buffer.from(secret,"hex")).update(scope+"\n"+address).digest("hex");
   const result=await db.query("SELECT total_hits,retry_after FROM public.consume_api_rate_limit($1)",[scope+":"+digest]);
   const {total_hits:count,retry_after:retry}=result.rows[0]||{};
   if(!Number.isInteger(count)||count<1||count>limit+1||!Number.isInteger(retry)||retry<1||retry>60)throw new Error("Invalid limiter response");
   // Write limit may be tighter than global; do not advertise a larger remainder.
   const prior=Number(res.get("RateLimit-Remaining")??limit);
   res.set("RateLimit-Limit",String(limit));
   res.set("RateLimit-Remaining",String(Math.min(prior,Math.max(0,limit-count))));
   if(count>limit){res.set("Retry-After",String(retry));return res.status(429).json({error:"Too many requests; retry later"});}
  }catch{
   return unavailable();
  }finally{pending--;}
  next();
 };
}

// One indexed bounded batch per minute per running replica. Expired rows are
// also cleaned on startup. No unhandled rejection, no sensitive log contents.
export function startRateLimitRetention(db=pool){
 let running=false;
 const sweep=async()=>{
  if(running)return;
  running=true;
  try{await db.query("SELECT public.purge_api_rate_limits()");}
  catch{process.stderr.write(JSON.stringify({event:"rate_limit_retention_failed"})+"\n");}
  finally{running=false;}
 };
 void sweep();
 const timer=setInterval(sweep,60000);
 timer.unref();
 return ()=>clearInterval(timer);
}

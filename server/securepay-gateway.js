// Staff API gateway: no SecurePay DB credentials, context key, PIN pepper or recovery key.
// Fixed Unix socket only; no client-controlled destination, redirects or raw upstream replies.
import express from "express";
import {customerPortalPage,sendPortalPage} from "./securepay-portal-page.js";
import rateLimit from "express-rate-limit";
import {request} from "node:http";
import {isAbsolute} from "node:path";
const uuid="[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
const allowedPath=new RegExp("^/tenants/"+uuid+"/(?:pin(?:/grant)?|milestones/"+uuid+"/(?:reserve|view))$");
const uuidOnly=new RegExp("^"+uuid+"$");
export const authoritySecrets=["SECUREPAY_DATABASE_URL","SECUREPAY_CONTEXT_HMAC_SECRET","SECUREPAY_PIN_PEPPER","SECUREPAY_RECOVERY_KEY","SECUREPAY_COMMAND_KEY","SECUREPAY_RATE_LIMIT_KEY"];
function forward(socketPath,path,token,body){
 return new Promise((resolve,reject)=>{
  const payload=JSON.stringify(body);
  const req=request({socketPath,path:"/v1/securepay"+path,method:"POST",headers:{
   authorization:token,"content-type":"application/json","content-length":Buffer.byteLength(payload)
  }},res=>{
   let size=0;const chunks=[];
   res.on("data",chunk=>{size+=chunk.length;if(size>8192){res.destroy();req.destroy(Error("Oversize authority response"));return;}chunks.push(chunk);});
   res.on("error",reject);
   res.on("end",()=>{try{resolve({status:res.statusCode,body:JSON.parse(Buffer.concat(chunks).toString("utf8"))});}catch{reject(Error("Invalid authority response"));}});
  });
  const timer=setTimeout(()=>req.destroy(Error("Authority deadline exceeded")),12000);
  req.on("error",e=>{clearTimeout(timer);reject(e);});
  req.on("close",()=>clearTimeout(timer));
  req.end(payload);
 });
}
export function createSecurePayGateway(env=process.env){
 const router=express.Router();
 router.use((req,res,next)=>{res.set("Cache-Control","no-store");next();});
 if(env.SECUREPAY_SANDBOX_ENABLED!=="true"||!["development","test"].includes(env.NODE_ENV)){
  router.use((req,res)=>res.status(404).json({error:"Not found"}));return router;
 }
 if(authoritySecrets.some(k=>env[k]!==undefined))throw Error("SecurePay authority secrets forbidden in gateway");
 const socket=env.SECUREPAY_AUTHORITY_SOCKET;
 if(typeof socket!=="string"||!isAbsolute(socket)||socket.length>100||socket.includes("\0"))throw Error("SecurePay authority socket required");
 router.use(rateLimit({windowMs:60_000,limit:30,standardHeaders:true,legacyHeaders:false}));
 router.get("/portal",(req,res)=>req.originalUrl.includes("?")?res.status(404).json({error:"Not found"}):sendPortalPage(res,customerPortalPage()));
 router.use(express.json({limit:"8kb",strict:true}));
 router.use(async(req,res)=>{
  if(req.method!=="POST"||!allowedPath.test(req.path)||req.originalUrl.includes("?"))return res.status(404).json({error:"Not found"});
  const token=req.headers.authorization;
  if(typeof token!=="string"||token.length>8192||!/^Bearer [^\s]+$/i.test(token))return res.status(401).json({error:"Customer authentication required"});
  if(!req.is("application/json")||!req.body||typeof req.body!=="object"||Array.isArray(req.body))return res.status(400).json({error:"Invalid request"});
  try{
   const {status,body}=await forward(socket,req.path,token,req.body);
   const errors={400:"Invalid request",401:"Customer authentication required",403:"Authorization denied",404:"Not found",409:"Conflicting request",413:"Invalid request",415:"JSON required",429:"Too many requests",503:"SecurePay unavailable"};
   if(Object.hasOwn(errors,status))return res.status(status).json({error:errors[status]});
   if(body?.mode==="sandbox"){
    if(status===200&&req.path.endsWith("/view")&&body.moneyMoved===false&&uuidOnly.test(body.milestoneId)&&req.path.endsWith("/"+body.milestoneId+"/view")&&typeof body.amountCents==="string"&&/^[1-9][0-9]{0,18}$/.test(body.amountCents)&&["planned","submitted","approved","disputed","release_pending","released","settled"].includes(body.status)&&["unfunded","funded","held","released","settled"].includes(body.fundingStatus)&&typeof body.isFinal==="boolean"&&[null,"pending","submitted","confirmed","failed"].includes(body.requestStatus))
     return res.json({mode:"sandbox",moneyMoved:false,milestoneId:body.milestoneId,amountCents:body.amountCents,status:body.status,fundingStatus:body.fundingStatus,isFinal:body.isFinal,requestStatus:body.requestStatus});
    if(status===200&&body.status==="pin_updated"&&req.path.endsWith("/pin"))return res.status(200).json({mode:"sandbox",status:"pin_updated"});
    if(status===201&&body.status==="grant_issued"&&req.path.endsWith("/pin/grant")&&uuidOnly.test(body.grantRef))return res.status(201).json({mode:"sandbox",status:"grant_issued",grantRef:body.grantRef});
    if(status===202&&body.status==="reserved"&&body.moneyMoved===false&&uuidOnly.test(body.releaseRequestId)&&uuidOnly.test(body.milestoneId)&&req.path.includes("/milestones/"+body.milestoneId+"/reserve")&&typeof body.amountCents==="string"&&/^[1-9][0-9]{0,15}$/.test(body.amountCents)&&body.amountCents===String(req.body.expectedAmountCents))
     return res.status(202).json({mode:"sandbox",status:"reserved",releaseRequestId:body.releaseRequestId,milestoneId:body.milestoneId,amountCents:body.amountCents,moneyMoved:false});
   }
  }catch{/* deliberately suppress internal details; no replay or retry */}
  return res.status(503).json({error:"SecurePay unavailable"});
 });
 router.use((err,req,res,next)=>res.status(err.type==="entity.too.large"?413:400).json({error:"Invalid request"}));
 return router;
}

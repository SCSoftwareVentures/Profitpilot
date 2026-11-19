// Staff API gateway: no SecurePay DB credentials, context key, PIN pepper or recovery key.
// Fixed Unix socket only; no client-controlled destination, redirects or raw upstream replies.
import express from "express";
import {customerPortalPage,customerQuotePage,customerContractPage,customerCancellationPage,sendPortalPage} from "./securepay-portal-page.js";
import {projectFundedCancellation} from "./securepay-funded-cancellation-view.js";
import {projectContract} from "./securepay-contract-view.js";
import rateLimit from "express-rate-limit";
import {request} from "node:http";
import {createHash} from "node:crypto";
import {isAbsolute} from "node:path";
const uuid="[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
const allowedPath=new RegExp("^/tenants/"+uuid+"/(?:pin(?:/grant)?|milestones/"+uuid+"/(?:reserve|view|completion|photo|approve|reject|dispute)|plans/"+uuid+"/(?:view|accept|contract|accept-change|funded-cancellation|accept-funded-cancellation|ack-negotiated|appeal-negotiated))$");
const uuidOnly=new RegExp("^"+uuid+"$");
export const authoritySecrets=["SECUREPAY_DATABASE_URL","SECUREPAY_CONTEXT_HMAC_SECRET","SECUREPAY_PIN_PEPPER","SECUREPAY_RECOVERY_KEY","SECUREPAY_COMMAND_KEY","SECUREPAY_RATE_LIMIT_KEY"];
function forward(socketPath,path,token,body){
 return new Promise((resolve,reject)=>{
  const payload=JSON.stringify(body);
  const req=request({socketPath,path:"/v1/securepay"+path,method:"POST",headers:{
   authorization:token,"content-type":"application/json","content-length":Buffer.byteLength(payload)
  }},res=>{
   let size=0;const chunks=[];
   res.on("data",chunk=>{size+=chunk.length;if(size>(path.endsWith("/photo")?2800000:(path.endsWith("/contract")||path.endsWith("/funded-cancellation"))?524288:path.includes("/plans/")?65536:16384)){res.destroy();req.destroy(Error("Oversize authority response"));return;}chunks.push(chunk);});
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
 router.get("/cancellation",(req,res)=>req.originalUrl.includes("?")?res.status(404).json({error:"Not found"}):sendPortalPage(res,customerCancellationPage()));
 router.get("/contract",(req,res)=>req.originalUrl.includes("?")?res.status(404).json({error:"Not found"}):sendPortalPage(res,customerContractPage()));
 router.get("/quote",(req,res)=>req.originalUrl.includes("?")?res.status(404).json({error:"Not found"}):sendPortalPage(res,customerQuotePage()));
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
    if(status===200&&body.moneyMoved===false&&req.path.endsWith("/funded-cancellation"))return res.json({mode:"sandbox",moneyMoved:false,cancellation:projectFundedCancellation(body.cancellation,req.path.split("/")[4])});
    if(status===200&&body.moneyMoved===false&&req.path.endsWith("/accept-funded-cancellation")&&body.status==="negotiation_opened"&&uuidOnly.test(body.caseId))return res.json({mode:"sandbox",moneyMoved:false,status:"negotiation_opened",caseId:body.caseId});
    if(status===200&&body.moneyMoved===false&&((req.path.endsWith("/ack-negotiated")&&body.status==="decision_acknowledged")||(req.path.endsWith("/appeal-negotiated")&&body.status==="decision_appealed")))return res.json({mode:"sandbox",moneyMoved:false,status:body.status});
    if(status===200&&body.moneyMoved===false&&req.path.includes("/plans/")&&req.path.endsWith("/contract"))return res.json({mode:"sandbox",moneyMoved:false,contract:projectContract(body.contract,req.path.split("/")[4])});
    if(status===200&&body.moneyMoved===false&&req.path.includes("/plans/")&&req.path.endsWith("/accept-change")&&body.status==="change_accepted"&&uuidOnly.test(body.changeId)&&body.changeId===req.body.changeId)return res.json({mode:"sandbox",moneyMoved:false,status:"change_accepted",changeId:body.changeId});
    if(status===200&&body.moneyMoved===false&&req.path.includes("/plans/")&&req.path.endsWith("/view")&&uuidOnly.test(body.planId)&&req.path.endsWith("/"+body.planId+"/view")&&uuidOnly.test(body.jobId)&&/^[a-f0-9]{64}$/.test(body.quoteDigest)&&/^[a-f0-9]{64}$/.test(body.planDigest)&&body.currency==="AUD"&&typeof body.totalCents==="string"&&/^[1-9][0-9]{0,15}$/.test(body.totalCents)&&["offered","accepted","withdrawn"].includes(body.status)&&body.quote&&uuidOnly.test(body.quote.quoteId)&&Number.isInteger(body.quote.revision)&&body.quote.revision>=1&&body.quote.revision<=100&&typeof body.quote.description==="string"&&body.quote.description.length<=4000&&body.quote.totalCents===body.totalCents&&Array.isArray(body.items)&&body.items.length>=1&&body.items.length<=20&&body.items.every((p,i)=>uuidOnly.test(p.milestoneId)&&Number.isSafeInteger(p.amountCents)&&p.amountCents>0&&typeof p.description==="string"&&p.description.length<=500&&p.final===(i===body.items.length-1))&&new Set(body.items.map(p=>p.milestoneId)).size===body.items.length&&body.items.reduce((n,p)=>n+BigInt(p.amountCents),0n)===BigInt(body.totalCents))
     return res.json({mode:"sandbox",moneyMoved:false,planId:body.planId,jobId:body.jobId,quoteDigest:body.quoteDigest,planDigest:body.planDigest,currency:"AUD",totalCents:body.totalCents,status:body.status,quote:{quoteId:body.quote.quoteId,revision:body.quote.revision,description:body.quote.description,totalCents:body.quote.totalCents},items:body.items.map(p=>({milestoneId:p.milestoneId,amountCents:p.amountCents,description:p.description,final:p.final}))});
    if(status===200&&body.moneyMoved===false&&req.path.includes("/plans/")&&req.path.endsWith("/accept")&&body.status==="plan_accepted"&&uuidOnly.test(body.planId)&&req.path.endsWith("/"+body.planId+"/accept"))return res.json({mode:"sandbox",moneyMoved:false,status:"plan_accepted",planId:body.planId});
    if(status===200&&body.moneyMoved===false&&req.path.endsWith("/completion")&&uuidOnly.test(body.completionId)&&/^[a-f0-9]{64}$/.test(body.manifestDigest)&&typeof body.comments==="string"&&body.comments.length<=2000&&typeof body.version==="string"&&/^(0|[1-9][0-9]{0,18})$/.test(body.version)&&typeof body.amountCents==="string"&&/^[1-9][0-9]{0,18}$/.test(body.amountCents)&&["submitted","approved","rejected"].includes(body.status)&&Array.isArray(body.photos)&&body.photos.length>=1&&body.photos.length<=12&&body.photos.every(p=>uuidOnly.test(p.photoId)&&/^[a-f0-9]{64}$/.test(p.digest)))
     return res.json({mode:"sandbox",moneyMoved:false,completionId:body.completionId,manifestDigest:body.manifestDigest,comments:body.comments,version:body.version,amountCents:body.amountCents,status:body.status,photos:body.photos.map(p=>({photoId:p.photoId,digest:p.digest}))});
    if(status===200&&body.moneyMoved===false&&req.path.endsWith("/photo")&&uuidOnly.test(body.photoId)&&body.photoId===req.body.photoId&&/^[a-f0-9]{64}$/.test(body.digest)&&typeof body.content==="string"&&body.content.length<=2796204&&/^[A-Za-z0-9+/]+={0,2}$/.test(body.content)){
     const bytes=Buffer.from(body.content,"base64");
     if(bytes.length>=8&&bytes.length<=2097152&&bytes.toString("base64")===body.content&&bytes.subarray(0,8).toString("hex")==="89504e470d0a1a0a"&&createHash("sha256").update(bytes).digest("hex")===body.digest)return res.json({mode:"sandbox",moneyMoved:false,photoId:body.photoId,digest:body.digest,content:body.content});
    }
    if(status===200&&body.moneyMoved===false&&req.path.endsWith("/reject")&&body.status==="work_rejected")return res.json({mode:"sandbox",moneyMoved:false,status:"work_rejected"});
    if(status===200&&body.moneyMoved===false&&req.path.endsWith("/dispute")&&body.status==="dispute_opened"&&uuidOnly.test(body.caseId)&&body.caseId===req.body.caseId)return res.json({mode:"sandbox",moneyMoved:false,status:"dispute_opened",caseId:body.caseId});
    if(status===200&&body.moneyMoved===false&&req.path.endsWith("/approve")&&body.status==="work_approved")return res.json({mode:"sandbox",moneyMoved:false,status:"work_approved"});
    if(status===200&&req.path.endsWith("/view")&&body.moneyMoved===false&&uuidOnly.test(body.milestoneId)&&req.path.endsWith("/"+body.milestoneId+"/view")&&typeof body.amountCents==="string"&&/^[1-9][0-9]{0,18}$/.test(body.amountCents)&&["planned","submitted","approved","disputed","release_pending","released","settled","cancelled"].includes(body.status)&&["unfunded","funded","held","released","settled"].includes(body.fundingStatus)&&typeof body.isFinal==="boolean"&&[null,"pending","submitted","confirmed","failed"].includes(body.requestStatus))
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

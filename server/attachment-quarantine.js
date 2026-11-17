import express from "express";
import {randomUUID} from "node:crypto";
import {requirePermission,requireStepUp} from "./auth.js";
import {withPrivacyStepUp} from "./db.js";
import {MAX_ATTACHMENT_BYTES,attachmentShape,sealAttachment,attachmentWriteAction,independentAttachmentKey} from "../src/attachment-quarantine.js";
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const permitted=["application/pdf","image/png","image/jpeg"];
function syntheticOnly(req,res,next){
 // No production or development upload capability until independent scanner and retention gates.
 if(process.env.NODE_ENV!=="test"||!process.env.TEST_ADMIN_DATABASE_URL||process.env.ENABLE_SYNTHETIC_ATTACHMENT_QUARANTINE!=="true")return res.status(404).json({error:"Resource not found"});
 next();
}
export function registerAttachmentQuarantineRoutes(app,membership){
 const base="/v1/tenants/:tenantId/imports/:batchId/quarantine";
 app.post(base,syntheticOnly,membership,requirePermission("imports.rows.write"),requireStepUp(),(req,res,next)=>{
  if(!uuid.test(req.params.batchId))return res.status(400).json({error:"Invalid batch ID"});
  const type=req.is(permitted);if(!type)return res.status(415).json({error:"Unsupported attachment media"});
  try{independentAttachmentKey(process.env);}catch{return res.status(503).json({error:"Attachment encryption unavailable"});}
  req.attachmentType=type;next();
 },express.raw({type:permitted,limit:MAX_ATTACHMENT_BYTES,inflate:false}),async(req,res,next)=>{try{
  if(!attachmentShape(req.attachmentType,req.body))return res.status(422).json({error:"Invalid attachment signature or size"});
  const {key,keyId}=independentAttachmentKey(process.env);
  const meta={tenantId:req.membership.tenantId.toLowerCase(),batchId:req.params.batchId.toLowerCase(),userId:req.membership.userId.toLowerCase(),id:randomUUID(),type:req.attachmentType,keyId,size:req.body.length};
  const sealed=sealAttachment(req.body,meta,key);
  const result=await withPrivacyStepUp(req.membership,req.identity,meta.batchId,attachmentWriteAction(meta,sealed),async(c,proof)=>{
   const r=await c.query("SELECT private.store_quarantined_attachment($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) AS result",[meta.tenantId,meta.batchId,meta.id,meta.type,meta.keyId,meta.size,sealed.nonce,sealed.tag,sealed.ciphertext,req.identity.authTime,proof]);
   return r.rows[0].result;
  });
  if(result.error)return res.status(result.status).json({error:result.error});
  res.status(201).json(result.item);
 }catch(e){next(e);}finally{if(Buffer.isBuffer(req.body))req.body.fill(0);}});
 app.post(base+"/:attachmentId/discard",syntheticOnly,membership,requirePermission("imports.rows.write"),requireStepUp(),async(req,res,next)=>{try{
  const {batchId,attachmentId}=req.params;
  if(!uuid.test(batchId)||!uuid.test(attachmentId)||req.body?.discardQuarantineOnly!==true)return res.status(400).json({error:"Explicit quarantine discard required"});
  const result=await withPrivacyStepUp(req.membership,req.identity,batchId,"discard_quarantined_attachment:"+attachmentId.toLowerCase(),async(c,proof)=>{
   const r=await c.query("SELECT private.discard_quarantined_attachment($1,$2,$3,$4,$5) AS result",[req.membership.tenantId,batchId,attachmentId,req.identity.authTime,proof]);return r.rows[0].result;
  });
  if(result.error)return res.status(result.status).json({error:result.error});
  res.json(result.item);
 }catch(e){next(e);}});
}

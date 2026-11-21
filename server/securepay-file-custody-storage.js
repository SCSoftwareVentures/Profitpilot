import express from "express";
import {scanSource} from "./malware.js";
import {MAX_CUSTODY_BYTES,validCustodyHeaders,verifyCustodyBytes,sameCustodyReceipt} from "../src/securepay-file-custody.js";
const uuid=s=>typeof s==="string"&&/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(s);
const cols="id,case_id,evidence_id,client_request_id,received_by,sha256,byte_count,media_type,scan_status,origin_verified,source_identity_verified,independent_custody_verified,decision_authority,payment_authority,recorded_at";
const flags={synthetic:true,originalBytesDownloadAvailable:false,
 sourceAuthenticityVerified:false,realPartyIdentityVerified:false,
 independentCustodyVerified:false,decisionAuthority:false,paymentAuthority:false};
export function installSecurepayFileCustodyRoutes(app,{membership,requireRole,withTenant,scannerEnabled=false,scan=scanSource}){
 const path="/v1/tenants/:tenantId/prototype/securepay-cases/:caseId/evidence/:evidenceId/custody-file";
 const guard=[membership,requireRole("owner","admin","reviewer")];
 app.post(path,...guard,(req,res,next)=>{
  if(!uuid(req.params.caseId)||!uuid(req.params.evidenceId))
   return res.status(400).json({error:"Invalid synthetic evidence scope"});
  if(!req.is("application/octet-stream")||(req.get("content-encoding")||"identity").toLowerCase()!=="identity")
   return res.status(415).json({error:"Raw uncompressed application/octet-stream required"});
  if(!validCustodyHeaders({clientRequestId:req.get("x-client-request-id"),
   declaredSha256:req.get("x-evidence-sha256"),mediaType:req.get("x-evidence-media-type"),
   contentEncoding:req.get("content-encoding")}))
   return res.status(400).json({error:"Valid request UUID, SHA-256 and media type required"});
  if(!scannerEnabled)return res.status(503).json({error:"Evidence scanner unavailable; no bytes stored"});
  next();
 },express.raw({type:"application/octet-stream",limit:MAX_CUSTODY_BYTES,inflate:false}),async(req,res,next)=>{try{
  let verified;
  try{verified=verifyCustodyBytes(req.body,req.get("x-evidence-sha256"),req.get("x-evidence-media-type"));}
  catch{return res.status(422).json({error:"Evidence bytes or declared type failed verification"});}
  const verdict=await scan(req.body,{enabled:true});
  if(verdict==="infected")return res.status(422).json({error:"Malware scanner rejected evidence; nothing stored"});
  if(verdict!=="scanner_reported_clean")return res.status(503).json({error:"Clean scanner verdict unavailable; no bytes stored"});
  const tenant=req.membership.tenantId,{caseId,evidenceId}=req.params;
  const clientRequestId=req.get("x-client-request-id");
  const result=await withTenant(tenant,req.identity.subject,async c=>{
   const source=await c.query("SELECT e.id FROM securepay_evidence_rehearsals e JOIN securepay_case_rehearsals k ON k.tenant_id=e.tenant_id AND k.id=e.case_id WHERE e.tenant_id=$1 AND e.case_id=$2 AND e.id=$3 AND k.synthetic=true AND k.funds_moved=false",[tenant,caseId,evidenceId]);
   if(!source.rowCount)return {status:404,error:"Synthetic evidence unavailable"};
   const actor=(await c.query("SELECT private.actor_id()::text AS id")).rows[0]?.id;
   if(!uuid(actor))return {status:403,error:"Signed operator context required"};
   const prior=await c.query("SELECT "+cols+" FROM securepay_evidence_custody_receipts WHERE tenant_id=$1 AND case_id=$2 AND evidence_id=$3",[tenant,caseId,evidenceId]);
   const same=row=>sameCustodyReceipt(row,{clientRequestId,sha256:verified.sha256,mediaType:verified.mediaType},actor);
   if(prior.rowCount)return same(prior.rows[0])?
    {status:200,item:prior.rows[0],idempotent:true}:{status:409,error:"Evidence already sealed with different bytes, request or actor"};
   const added=await c.query("INSERT INTO securepay_evidence_custody_receipts(tenant_id,case_id,evidence_id,client_request_id,received_by,sha256,byte_count,media_type,scan_status,original_bytes) VALUES($1,$2,$3,$4,private.actor_id(),$5,$6,$7,'scanner_reported_clean',$8) ON CONFLICT DO NOTHING RETURNING "+cols,
    [tenant,caseId,evidenceId,clientRequestId,verified.sha256,verified.byteCount,verified.mediaType,req.body]);
   if(added.rowCount)return {status:201,item:added.rows[0],idempotent:false};
   const race=await c.query("SELECT "+cols+" FROM securepay_evidence_custody_receipts WHERE tenant_id=$1 AND case_id=$2 AND evidence_id=$3",[tenant,caseId,evidenceId]);
   return race.rowCount&&same(race.rows[0])?
    {status:200,item:race.rows[0],idempotent:true}:{status:409,error:"Evidence already sealed with different bytes, request or actor"};
  });
  const {status,...rest}=result;
  res.status(status).json({...rest,...flags,originalBytesStored:status===200||status===201,
   receivedByteIntegrityVerified:status===200||status===201,
   scannerReportedClean:status===200||status===201});
 }catch(e){next(e);}});
 app.get(path,...guard,async(req,res,next)=>{try{
  const tenant=req.membership.tenantId,{caseId,evidenceId}=req.params;
  if(!uuid(caseId)||!uuid(evidenceId))return res.status(400).json({error:"Invalid synthetic evidence scope"});
  const result=await withTenant(tenant,req.identity.subject,async c=>{
   const source=await c.query("SELECT id FROM securepay_evidence_rehearsals WHERE tenant_id=$1 AND case_id=$2 AND id=$3",[tenant,caseId,evidenceId]);
   if(!source.rowCount)return {status:404,error:"Synthetic evidence unavailable"};
   const item=await c.query("SELECT "+cols+" FROM securepay_evidence_custody_receipts WHERE tenant_id=$1 AND case_id=$2 AND evidence_id=$3",[tenant,caseId,evidenceId]);
   return {status:200,received:item.rowCount===1,item:item.rows[0]??null};
  },{repeatableRead:true});
  const {status,...rest}=result;res.status(status).json({...rest,...flags,originalBytesStored:rest.received===true,
   receivedByteIntegrityVerified:rest.received===true});
 }catch(e){next(e);}});
}

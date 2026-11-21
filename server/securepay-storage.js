// SP-S2: synthetic-only operator register. Never accepts payment instructions.
import {assessSecurepayDecisionPreflight} from "../src/securepay-readiness.js";
const uuid=s=>typeof s==="string"&&/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(s);
const ref=s=>typeof s==="string"&&/^[A-Za-z0-9][A-Za-z0-9._:-]{2,119}$/.test(s);
const exact=(o,keys)=>o!==null&&typeof o==="object"&&!Array.isArray(o)&&Object.keys(o).length===keys.length&&Object.keys(o).every(k=>keys.includes(k));
const kinds=new Set(["claim_reported","business_response_reported","operator_review_note","rectification_reported","appeal_reported"]);
const caseCols="id,job_reference,claim_reference,status,synthetic,funds_moved,created_at";
const evidenceCols="id,case_id,evidence_type,evidence_reference,externally_verified,recorded_at";
export function installSecurepayStorageRoutes(app,{membership,withTenant,requireRole}){
 const root="/v1/tenants/:tenantId/prototype/securepay-cases";
 const guarded=[membership,requireRole("owner","admin","reviewer")];
 app.post(root,...guarded,async(req,res,next)=>{try{
  const b=req.body;
  if(!exact(b,["synthetic","clientRequestId","jobReference","claimReference"])||b.synthetic!==true||
   !uuid(b.clientRequestId)||!ref(b.jobReference)||!ref(b.claimReference))
   return res.status(400).json({error:"Synthetic case requires request UUID and opaque job/claim references"});
  const tenant=req.membership.tenantId;
  const output=await withTenant(tenant,req.identity.subject,async c=>{
   const p=[tenant,b.clientRequestId,b.jobReference,b.claimReference];
   const created=await c.query("INSERT INTO securepay_case_rehearsals(tenant_id,client_request_id,job_reference,claim_reference,opened_by) VALUES($1,$2,$3,$4,private.actor_id()) ON CONFLICT DO NOTHING RETURNING "+caseCols,p);
   if(created.rowCount)return {status:201,item:created.rows[0]};
   const previous=await c.query("SELECT "+caseCols+" FROM securepay_case_rehearsals WHERE tenant_id=$1 AND client_request_id=$2 AND opened_by=private.actor_id()",p.slice(0,2));
   if(previous.rowCount&&previous.rows[0].job_reference===b.jobReference&&previous.rows[0].claim_reference===b.claimReference)
    return {status:200,item:previous.rows[0]};
   return {status:409,error:"Conflicting case request identifier"};
  });
  const {status,...body}=output;res.status(status).json({...body,paymentAuthority:false,partyIdentityVerified:false});
 }catch(e){next(e);}});
 app.get(root,...guarded,async(req,res,next)=>{try{
  const cursor=req.query.cursor??null;
  if(cursor!==null&&!uuid(cursor))return res.status(400).json({error:"Invalid case cursor ID"});
  const tenant=req.membership.tenantId;
  const output=await withTenant(tenant,req.identity.subject,async c=>{
   if(cursor!==null){
    const anchor=await c.query("SELECT id FROM securepay_case_rehearsals WHERE tenant_id=$1 AND id=$2",[tenant,cursor]);
    if(!anchor.rowCount)return {status:404,error:"Case cursor unavailable"};
   }
   const page=await c.query("SELECT "+caseCols+" FROM securepay_case_rehearsals WHERE tenant_id=$1 AND ($2::uuid IS NULL OR (created_at,id)<(SELECT created_at,id FROM securepay_case_rehearsals WHERE tenant_id=$1 AND id=$2)) ORDER BY created_at DESC,id DESC LIMIT 101",[tenant,cursor]);
   const items=page.rows.slice(0,100);
   return {status:200,items,hasMore:page.rowCount>100,nextCursor:page.rowCount>100?items.at(-1).id:null};
  },{repeatableRead:true});
  const {status,...body}=output;res.status(status).json({...body,synthetic:true,paymentAuthority:false,partyIdentityVerified:false});
 }catch(e){next(e);}});
 app.get(root+"/:caseId",...guarded,async(req,res,next)=>{try{
  if(!uuid(req.params.caseId))return res.status(400).json({error:"Invalid case ID"});
  const tenant=req.membership.tenantId;
  const r=await withTenant(tenant,req.identity.subject,c=>c.query("SELECT "+caseCols+" FROM securepay_case_rehearsals WHERE tenant_id=$1 AND id=$2",[tenant,req.params.caseId]));
  if(!r.rowCount)return res.status(404).json({error:"Synthetic case unavailable"});
  res.json({item:r.rows[0],paymentAuthority:false,partyIdentityVerified:false});
 }catch(e){next(e);}});
 app.get(root+"/:caseId/decision-preflight",...guarded,async(req,res,next)=>{try{
  const caseId=req.params.caseId;
  if(!uuid(caseId))return res.status(400).json({error:"Invalid case ID"});
  const tenant=req.membership.tenantId;
  const output=await withTenant(tenant,req.identity.subject,async c=>{
   const found=await c.query(
    "SELECT id,status,synthetic,funds_moved,claim_reference,(opened_by=private.actor_id()) AS opened_by_requester FROM securepay_case_rehearsals WHERE tenant_id=$1 AND id=$2",
    [tenant,caseId]);
   if(!found.rowCount)return null;
   const summary=await c.query(
    "SELECT count(*)::int AS total,count(*) FILTER(WHERE evidence_type='claim_reported' AND evidence_reference=$3)::int AS claim_reports,count(*) FILTER(WHERE evidence_type='business_response_reported')::int AS business_reports,count(*) FILTER(WHERE evidence_type='operator_review_note')::int AS review_notes,count(*) FILTER(WHERE externally_verified)::int AS externally_verified FROM securepay_evidence_rehearsals WHERE tenant_id=$1 AND case_id=$2",
    [tenant,caseId,found.rows[0].claim_reference]);
   return assessSecurepayDecisionPreflight(found.rows[0],summary.rows[0]);
  },{repeatableRead:true});
  if(output===null)return res.status(404).json({error:"Synthetic case unavailable"});
  res.json(output);
 }catch(e){next(e);}});
 app.post(root+"/:caseId/evidence",...guarded,async(req,res,next)=>{try{
  const b=req.body,caseId=req.params.caseId;
  if(!uuid(caseId)||!exact(b,["clientRequestId","evidenceType","evidenceReference"])||!uuid(b.clientRequestId)||
   !kinds.has(b.evidenceType)||!ref(b.evidenceReference))
   return res.status(400).json({error:"Case, request UUID, evidence category and opaque reference required"});
  const tenant=req.membership.tenantId;
  const output=await withTenant(tenant,req.identity.subject,async c=>{
   const exists=await c.query("SELECT id FROM securepay_case_rehearsals WHERE tenant_id=$1 AND id=$2",[tenant,caseId]);
   if(!exists.rowCount)return {status:404,error:"Synthetic case unavailable"};
   const params=[tenant,caseId,b.clientRequestId,b.evidenceType,b.evidenceReference];
   const created=await c.query("INSERT INTO securepay_evidence_rehearsals(tenant_id,case_id,client_request_id,recorded_by,evidence_type,evidence_reference) VALUES($1,$2,$3,private.actor_id(),$4,$5) ON CONFLICT DO NOTHING RETURNING "+evidenceCols,params);
   if(created.rowCount)return {status:201,item:created.rows[0]};
   const prior=await c.query("SELECT "+evidenceCols+" FROM securepay_evidence_rehearsals WHERE tenant_id=$1 AND case_id=$2 AND client_request_id=$3 AND recorded_by=private.actor_id()",params.slice(0,3));
   if(prior.rowCount&&prior.rows[0].evidence_type===b.evidenceType&&prior.rows[0].evidence_reference===b.evidenceReference)
    return {status:200,item:prior.rows[0]};
   return {status:409,error:"Conflicting evidence request identifier"};
  });
  const {status,...body}=output;res.status(status).json({...body,externalVerification:false});
 }catch(e){next(e);}});
 app.get(root+"/:caseId/evidence",...guarded,async(req,res,next)=>{try{
  const caseId=req.params.caseId,cursor=req.query.cursor??null;
  if(!uuid(caseId)||(cursor!==null&&!uuid(cursor)))return res.status(400).json({error:"Invalid case or cursor ID"});
  const tenant=req.membership.tenantId;
  const output=await withTenant(tenant,req.identity.subject,async c=>{
   const existing=await c.query("SELECT id FROM securepay_case_rehearsals WHERE tenant_id=$1 AND id=$2",[tenant,caseId]);
   if(!existing.rowCount)return {status:404,error:"Synthetic case unavailable"};
   if(cursor!==null){
    const anchor=await c.query("SELECT id FROM securepay_evidence_rehearsals WHERE tenant_id=$1 AND case_id=$2 AND id=$3",[tenant,caseId,cursor]);
    if(!anchor.rowCount)return {status:404,error:"Evidence cursor unavailable"};
   }
   const page=await c.query("SELECT "+evidenceCols+" FROM securepay_evidence_rehearsals WHERE tenant_id=$1 AND case_id=$2 AND ($3::uuid IS NULL OR (recorded_at,id)<(SELECT recorded_at,id FROM securepay_evidence_rehearsals WHERE tenant_id=$1 AND case_id=$2 AND id=$3)) ORDER BY recorded_at DESC,id DESC LIMIT 101",[tenant,caseId,cursor]);
   const items=page.rows.slice(0,100);
   return {status:200,items,hasMore:page.rowCount>100,nextCursor:page.rowCount>100?items.at(-1).id:null};
  });
  const {status,...body}=output;res.status(status).json({...body,externalVerification:false,paymentAuthority:false});
 }catch(e){next(e);}});
}

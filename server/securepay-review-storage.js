import {checkOperatorReviewer,MAX_REVIEW_REPORTS} from "../src/securepay-review.js";
const uuid=x=>typeof x==="string"&&/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(x);
const ref=x=>typeof x==="string"&&/^[A-Za-z0-9][A-Za-z0-9._:-]{2,119}$/.test(x);
const fields="id,case_id,client_request_id,reviewer_id,review_reference,evidence_count,evidence_snapshot_sha256,decision_authority,payment_authority,recorded_at";
const flags={synthetic:true,decisionAuthority:false,paymentAuthority:false,partyIdentityVerified:false,independentReviewerIdentityVerified:false};
export function installSecurepayReviewerRoutes(app,{membership,requireRole,withTenant}){
 const root="/v1/tenants/:tenantId/prototype/securepay-cases/:caseId/reviewer-assessments";
 app.post(root,membership,requireRole("reviewer"),async(req,res,next)=>{try{
  const b=req.body,t=req.membership.tenantId,id=req.params.caseId;
  if(!uuid(id)||!b||typeof b!=="object"||Array.isArray(b)||
    Object.keys(b).length!==2||!Object.hasOwn(b,"clientRequestId")||!Object.hasOwn(b,"reviewReference")||
    !uuid(b.clientRequestId)||!ref(b.reviewReference))
   return res.status(400).json({error:"Valid case, request UUID and opaque review reference required"});
  const result=await withTenant(t,req.identity.subject,async c=>{
   const actor=(await c.query("SELECT private.actor_id()::text AS id")).rows[0]?.id;
   if(!uuid(actor))return {status:403,error:"Verified reviewer unavailable"};
   const r=await c.query("SELECT id,tenant_id,opened_by,claim_reference,synthetic,funds_moved,status FROM securepay_case_rehearsals WHERE tenant_id=$1 AND id=$2",[t,id]);
   if(!r.rowCount)return {status:404,error:"Synthetic case unavailable"};
   const p=[t,id,b.clientRequestId];
   const existing=await c.query("SELECT "+fields+" FROM securepay_reviewer_assessments WHERE tenant_id=$1 AND case_id=$2 AND client_request_id=$3 AND reviewer_id=private.actor_id()",p);
   if(existing.rowCount)return existing.rows[0].review_reference===b.reviewReference?
    {status:200,item:existing.rows[0]}:{status:409,error:"Conflicting review request identifier"};
   const e=await c.query("SELECT id,client_request_id,recorded_by,evidence_type,evidence_reference,externally_verified,recorded_at FROM securepay_evidence_rehearsals WHERE tenant_id=$1 AND case_id=$2 ORDER BY recorded_at,id LIMIT "+(MAX_REVIEW_REPORTS+1),[t,id]);
   if(e.rowCount>MAX_REVIEW_REPORTS)return {status:409,error:"Evidence snapshot limit exceeded"};
   const assessment=checkOperatorReviewer(r.rows[0],e.rows,actor);
   if(!assessment.eligibleForNonbindingOperatorReview)return {status:409,error:"Operator conflict or missing reports",blockingGates:assessment.blockingGates};
   const args=[t,id,b.clientRequestId,b.reviewReference,assessment.evidenceCount,assessment.evidenceSnapshotSha256];
   const created=await c.query("INSERT INTO securepay_reviewer_assessments(tenant_id,case_id,client_request_id,reviewer_id,review_reference,evidence_count,evidence_snapshot_sha256) VALUES($1,$2,$3,private.actor_id(),$4,$5,$6) ON CONFLICT DO NOTHING RETURNING "+fields,args);
   if(created.rowCount)return {status:201,item:created.rows[0]};
   const replay=await c.query("SELECT "+fields+" FROM securepay_reviewer_assessments WHERE tenant_id=$1 AND case_id=$2 AND client_request_id=$3 AND reviewer_id=private.actor_id()",p);
   return replay.rowCount&&replay.rows[0].review_reference===b.reviewReference?
    {status:200,item:replay.rows[0]}:{status:409,error:"Conflicting review request identifier"};
  },{repeatableRead:true});
  const {status,...data}=result;res.status(status).json({...data,...flags});
 }catch(e){next(e);}});
 app.get(root,membership,requireRole("owner","admin","reviewer"),async(req,res,next)=>{try{
  const t=req.membership.tenantId,id=req.params.caseId,cursor=req.query.cursor??null;
  if(!uuid(id)||(cursor!==null&&!uuid(cursor)))return res.status(400).json({error:"Invalid case or review cursor"});
  const result=await withTenant(t,req.identity.subject,async c=>{
   const exists=await c.query("SELECT id FROM securepay_case_rehearsals WHERE tenant_id=$1 AND id=$2",[t,id]);
   if(!exists.rowCount)return {status:404,error:"Synthetic case unavailable"};
   if(cursor!==null){
    const anchor=await c.query("SELECT id FROM securepay_reviewer_assessments WHERE tenant_id=$1 AND case_id=$2 AND id=$3",[t,id,cursor]);
    if(!anchor.rowCount)return {status:404,error:"Review cursor unavailable"};
   }
   const r=await c.query("SELECT "+fields+" FROM securepay_reviewer_assessments WHERE tenant_id=$1 AND case_id=$2 AND ($3::uuid IS NULL OR (recorded_at,id)<(SELECT recorded_at,id FROM securepay_reviewer_assessments WHERE tenant_id=$1 AND case_id=$2 AND id=$3)) ORDER BY recorded_at DESC,id DESC LIMIT 101",[t,id,cursor]);
   const items=r.rows.slice(0,100);
   return {status:200,items,hasMore:r.rowCount>100,nextCursor:r.rowCount>100?items.at(-1).id:null};
  },{repeatableRead:true});
  const {status,...data}=result;res.status(status).json({...data,...flags});
 }catch(e){next(e);}});
}

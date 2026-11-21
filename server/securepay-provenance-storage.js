import {validProvenanceRequest,reportedMetadataDigest,sameReportedMetadata} from "../src/securepay-provenance.js";
const uuid=s=>typeof s==="string"&&/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(s);
const cols="id,case_id,evidence_id,client_request_id,recorded_by,reported_origin,acquisition_method,source_reference,metadata_sha256,origin_verified,job_authority_verified,content_verified,decision_authority,payment_authority,recorded_at";
const flags={synthetic:true,operatorReported:true,sourceIdentityVerified:false,partyToJobVerified:false,
 sourceDocumentVerified:false,independentCustodyVerified:false,decisionAuthority:false,paymentAuthority:false};
export function installSecurepayProvenanceRoutes(app,{membership,requireRole,withTenant}){
 const root="/v1/tenants/:tenantId/prototype/securepay-cases/:caseId";
 const guard=[membership,requireRole("owner","admin","reviewer")];
 app.post(root+"/evidence/:evidenceId/provenance",...guard,async(req,res,next)=>{try{
  const t=req.membership.tenantId,id=req.params.caseId,evidenceId=req.params.evidenceId,b=req.body;
  if(!uuid(id)||!uuid(evidenceId)||!validProvenanceRequest(b))
   return res.status(400).json({error:"Valid case, evidence and exact synthetic provenance fields required"});
  const out=await withTenant(t,req.identity.subject,async c=>{
   const source=await c.query(
    "SELECT e.id,e.evidence_type,e.evidence_reference,k.job_reference FROM securepay_evidence_rehearsals e JOIN securepay_case_rehearsals k ON k.tenant_id=e.tenant_id AND k.id=e.case_id WHERE e.tenant_id=$1 AND e.case_id=$2 AND e.id=$3",
    [t,id,evidenceId]);
   if(!source.rowCount)return {status:404,error:"Synthetic evidence unavailable"};
   const q=[t,id,evidenceId,b.clientRequestId];
   const exists=await c.query("SELECT "+cols+" FROM securepay_evidence_provenance_receipts WHERE tenant_id=$1 AND case_id=$2 AND evidence_id=$3 AND client_request_id=$4 AND recorded_by=private.actor_id()",q);
   if(exists.rowCount)return sameReportedMetadata(exists.rows[0],b)?
    {status:200,item:exists.rows[0]}:{status:409,error:"Conflicting provenance request identifier"};
   const actor=(await c.query("SELECT private.actor_id()::text AS id")).rows[0]?.id;
   const x=source.rows[0];
   const digest=reportedMetadataDigest({tenantId:t,caseId:id,evidenceId,actorId:actor,jobReference:x.job_reference,
    evidenceType:x.evidence_type,evidenceReference:x.evidence_reference,reportedOrigin:b.reportedOrigin,
    acquisitionMethod:b.acquisitionMethod,sourceReference:b.sourceReference});
   const values=[t,id,evidenceId,b.clientRequestId,b.reportedOrigin,b.acquisitionMethod,b.sourceReference,digest];
   const created=await c.query(
    "INSERT INTO securepay_evidence_provenance_receipts(tenant_id,case_id,evidence_id,client_request_id,recorded_by,reported_origin,acquisition_method,source_reference,metadata_sha256) VALUES($1,$2,$3,$4,private.actor_id(),$5,$6,$7,$8) ON CONFLICT DO NOTHING RETURNING "+cols,values);
   if(created.rowCount)return {status:201,item:created.rows[0]};
   const replay=await c.query("SELECT "+cols+" FROM securepay_evidence_provenance_receipts WHERE tenant_id=$1 AND case_id=$2 AND evidence_id=$3 AND client_request_id=$4 AND recorded_by=private.actor_id()",q);
   return replay.rowCount&&sameReportedMetadata(replay.rows[0],b)?
    {status:200,item:replay.rows[0]}:{status:409,error:"Conflicting provenance request identifier"};
  });
  const {status,...body}=out;res.status(status).json({...body,...flags});
 }catch(e){next(e);}});
 app.get(root+"/evidence/:evidenceId/provenance",...guard,async(req,res,next)=>{try{
  const t=req.membership.tenantId,id=req.params.caseId,evidenceId=req.params.evidenceId,cursor=req.query.cursor??null;
  if(!uuid(id)||!uuid(evidenceId)||(cursor!==null&&!uuid(cursor)))
   return res.status(400).json({error:"Invalid case, evidence or provenance cursor"});
  const out=await withTenant(t,req.identity.subject,async c=>{
   const e=await c.query("SELECT id FROM securepay_evidence_rehearsals WHERE tenant_id=$1 AND case_id=$2 AND id=$3",[t,id,evidenceId]);
   if(!e.rowCount)return {status:404,error:"Synthetic evidence unavailable"};
   if(cursor!==null){
    const anchor=await c.query("SELECT id FROM securepay_evidence_provenance_receipts WHERE tenant_id=$1 AND case_id=$2 AND evidence_id=$3 AND id=$4",[t,id,evidenceId,cursor]);
    if(!anchor.rowCount)return {status:404,error:"Provenance cursor unavailable"};
   }
   const page=await c.query("SELECT "+cols+" FROM securepay_evidence_provenance_receipts WHERE tenant_id=$1 AND case_id=$2 AND evidence_id=$3 AND ($4::uuid IS NULL OR (recorded_at,id)<(SELECT recorded_at,id FROM securepay_evidence_provenance_receipts WHERE tenant_id=$1 AND case_id=$2 AND evidence_id=$3 AND id=$4)) ORDER BY recorded_at DESC,id DESC LIMIT 101",[t,id,evidenceId,cursor]);
   const items=page.rows.slice(0,100);
   return {status:200,items,hasMore:page.rowCount>100,nextCursor:page.rowCount>100?items.at(-1).id:null};
  },{repeatableRead:true});
  const {status,...body}=out;res.status(status).json({...body,...flags});
 }catch(e){next(e);}});
 app.get(root+"/provenance-preflight",...guard,async(req,res,next)=>{try{
  const t=req.membership.tenantId,id=req.params.caseId;
  if(!uuid(id))return res.status(400).json({error:"Invalid case ID"});
  const out=await withTenant(t,req.identity.subject,async c=>{
   const found=await c.query("SELECT id FROM securepay_case_rehearsals WHERE tenant_id=$1 AND id=$2",[t,id]);
   if(!found.rowCount)return {status:404,error:"Synthetic case unavailable"};
   const q=await c.query(
    "SELECT count(*)::int AS total_evidence,"+
    "count(*) FILTER(WHERE EXISTS(SELECT 1 FROM securepay_evidence_provenance_receipts p WHERE p.tenant_id=e.tenant_id AND p.case_id=e.case_id AND p.evidence_id=e.id))::int AS metadata_linked,"+
    "count(*) FILTER(WHERE e.evidence_type='claim_reported' AND EXISTS(SELECT 1 FROM securepay_evidence_provenance_receipts p WHERE p.tenant_id=e.tenant_id AND p.case_id=e.case_id AND p.evidence_id=e.id AND p.reported_origin='reported_customer'))::int AS customer_origin_reported,"+
    "count(*) FILTER(WHERE e.evidence_type='business_response_reported' AND EXISTS(SELECT 1 FROM securepay_evidence_provenance_receipts p WHERE p.tenant_id=e.tenant_id AND p.case_id=e.case_id AND p.evidence_id=e.id AND p.reported_origin='reported_business'))::int AS business_origin_reported "+
    "FROM securepay_evidence_rehearsals e WHERE e.tenant_id=$1 AND e.case_id=$2",[t,id]);
   const counts=q.rows[0];
   return {status:200,caseId:id,synthetic:true,decisionReadiness:"blocked",decisionAuthority:false,
    paymentAuthority:false,partyIdentityVerified:false,partyToJobVerified:false,evidenceOriginVerified:false,
    metadata:{evidenceCount:counts.total_evidence,itemsWithReportedProvenance:counts.metadata_linked,
     matchingCustomerOriginReports:counts.customer_origin_reported,matchingBusinessOriginReports:counts.business_origin_reported},
    blockingGates:[
     ...(counts.metadata_linked<counts.total_evidence?["evidence_provenance_metadata_incomplete"]:[]),
     ...(!counts.customer_origin_reported?["customer_origin_report_missing"]:[]),
     ...(!counts.business_origin_reported?["business_origin_report_missing"]:[]),
     "source_identity_unverified","customer_job_authority_unverified","business_job_authority_unverified",
     "evidence_content_unverified","independent_custody_unverified","provider_and_legal_clearance_unverified"
    ]};
  },{repeatableRead:true});
  const {status,...data}=out;res.status(status).json(data);
 }catch(e){next(e);}});
}

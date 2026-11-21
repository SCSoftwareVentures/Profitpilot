import {validClaimRevocation,sameClaimRevocation} from "../src/securepay-claim-revocation.js";
const uuid=s=>typeof s==="string"&&/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{12}$/i.test(s);
const fields="id,case_id,evidence_id,claim_id,client_request_id,revoked_by,reason_code,revocation_reference,recorded_at";
const flags={synthetic:true,revocationOfOperatorRecordedClaim:true,
 identityVerified:false,jobAuthorityVerified:false,decisionAuthority:false,paymentAuthority:false};
export function installSecurepayClaimRevocationRoutes(app,{membership,requireRole,withTenant}){
 const root="/v1/tenants/:tenantId/prototype/securepay-cases/:caseId/evidence/:evidenceId/signed-party-claims/:claimId/revoke";
 const guard=[membership,requireRole("owner","admin","reviewer")];
 app.post(root,...guard,async(req,res,next)=>{try{
  const {caseId,evidenceId,claimId}=req.params,b=req.body,t=req.membership.tenantId;
  if(![caseId,evidenceId,claimId].every(uuid)||!validClaimRevocation(b))
   return res.status(400).json({error:"Exact synthetic revocation request and valid claim scope required"});
  const result=await withTenant(t,req.identity.subject,async c=>{
   const claim=await c.query("SELECT id,recorded_by FROM securepay_signed_party_claims WHERE tenant_id=$1 AND case_id=$2 AND evidence_id=$3 AND id=$4",[t,caseId,evidenceId,claimId]);
   if(!claim.rowCount)return {status:404,error:"Synthetic signed claim unavailable"};
   const actor=(await c.query("SELECT private.actor_id()::text AS id")).rows[0]?.id;
   if(!uuid(actor))return {status:403,error:"Signed tenant actor required"};
   if(req.membership.role==="reviewer"&&claim.rows[0].recorded_by!==actor)
    return {status:403,error:"Only the recording reviewer or tenant administrators can revoke"};
   const args=[t,caseId,evidenceId,claimId];
   const prior=await c.query("SELECT "+fields+" FROM securepay_signed_claim_revocations WHERE tenant_id=$1 AND case_id=$2 AND evidence_id=$3 AND claim_id=$4",args);
   if(prior.rowCount)return sameClaimRevocation(prior.rows[0],b,actor)?
    {status:200,item:prior.rows[0]}:{status:409,error:"Signed claim is already irrevocably revoked"};
   const created=await c.query("INSERT INTO securepay_signed_claim_revocations(tenant_id,case_id,evidence_id,claim_id,client_request_id,revoked_by,reason_code,revocation_reference) VALUES($1,$2,$3,$4,$5,private.actor_id(),$6,$7) ON CONFLICT DO NOTHING RETURNING "+fields,
    [...args,b.clientRequestId,b.reasonCode,b.revocationReference]);
   if(created.rowCount)return {status:201,item:created.rows[0]};
   const replay=await c.query("SELECT "+fields+" FROM securepay_signed_claim_revocations WHERE tenant_id=$1 AND case_id=$2 AND evidence_id=$3 AND claim_id=$4",args);
   return replay.rowCount&&sameClaimRevocation(replay.rows[0],b,actor)?
    {status:200,item:replay.rows[0]}:{status:409,error:"Signed claim is already irrevocably revoked"};
  });
  const {status,...rest}=result;res.status(status).json({...rest,...flags,revoked:status===201||status===200,
   operationallyUsable:false});
 }catch(e){next(e);}});
 app.get(root,...guard,async(req,res,next)=>{try{
  const {caseId,evidenceId,claimId}=req.params,t=req.membership.tenantId;
  if(![caseId,evidenceId,claimId].every(uuid))return res.status(400).json({error:"Invalid claim scope"});
  const result=await withTenant(t,req.identity.subject,async c=>{
   const claim=await c.query("SELECT id FROM securepay_signed_party_claims WHERE tenant_id=$1 AND case_id=$2 AND evidence_id=$3 AND id=$4",[t,caseId,evidenceId,claimId]);
   if(!claim.rowCount)return {status:404,error:"Synthetic signed claim unavailable"};
   const found=await c.query("SELECT "+fields+" FROM securepay_signed_claim_revocations WHERE tenant_id=$1 AND case_id=$2 AND evidence_id=$3 AND claim_id=$4",[t,caseId,evidenceId,claimId]);
   return {status:200,revoked:found.rowCount===1,item:found.rows[0]??null,operationallyUsable:false};
  },{repeatableRead:true});
  const {status,...rest}=result;res.status(status).json({...rest,...flags});
 }catch(e){next(e);}});
 const preflight="/v1/tenants/:tenantId/prototype/securepay-party-job-trust/:caseId";
 app.get(preflight,...guard,async(req,res,next)=>{try{
  const t=req.membership.tenantId,id=req.params.caseId;
  if(!uuid(id))return res.status(400).json({error:"Invalid case ID"});
  const result=await withTenant(t,req.identity.subject,async c=>{
   const found=await c.query("SELECT id FROM securepay_case_rehearsals WHERE tenant_id=$1 AND id=$2",[t,id]);
   if(!found.rowCount)return {status:404,error:"Synthetic case unavailable"};
   const q=await c.query("SELECT count(*)::int AS total_claims,"+
    "count(*) FILTER(WHERE s.claimed_party_role='customer')::int AS customer_claims,"+
    "count(*) FILTER(WHERE s.claimed_party_role='tradesperson')::int AS tradesperson_claims,"+
    "count(*) FILTER(WHERE r.id IS NOT NULL)::int AS revoked_claims "+
    "FROM securepay_signed_party_claims s LEFT JOIN securepay_signed_claim_revocations r"+
    " ON r.tenant_id=s.tenant_id AND r.case_id=s.case_id AND r.evidence_id=s.evidence_id AND r.claim_id=s.id"+
    " WHERE s.tenant_id=$1 AND s.case_id=$2",[t,id]);
   return {status:200,caseId:id,synthetic:true,decisionReadiness:"blocked",operationallyUsable:false,
    partyIdentityVerified:false,jobAuthorityVerified:false,issuerTrusted:false,
    contentBytesVerified:false,paymentAuthority:false,decisionAuthority:false,
    claims:{total:q.rows[0].total_claims,customer:q.rows[0].customer_claims,
     tradesperson:q.rows[0].tradesperson_claims,revoked:q.rows[0].revoked_claims},
    blockingGates:["trusted_identity_issuer_not_configured","customer_job_authority_unverified",
     "tradesperson_job_authority_unverified","content_bytes_unverified",
     "independent_custody_unverified","provider_and_legal_clearance_unverified"]};
  },{repeatableRead:true});
  const {status,...rest}=result;res.status(status).json(rest);
 }catch(e){next(e);}});
}

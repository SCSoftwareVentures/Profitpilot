import {validIssuerRequest,issuerSettings,verifyIssuerAttestation,digest} from "../src/securepay-issuer-attestation.js";
const uuid=x=>typeof x==="string"&&/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(x);
const cols="id,case_id,evidence_id,claim_id,client_request_id,recorded_by,issuer,token_jti,issuer_subject_sha256,token_sha256,issued_at,expires_at,identity_verified,job_authority_verified,content_verified,decision_authority,payment_authority,recorded_at";
const flags={synthetic:true,identityVerified:false,jobAuthorityVerified:false,contentBytesVerified:false,
 decisionAuthority:false,paymentAuthority:false,operationallyUsable:false};
export function installSecurepayIssuerRoutes(app,{membership,requireRole,withTenant}){
 const root="/v1/tenants/:tenantId/prototype/securepay-cases/:caseId/evidence/:evidenceId/signed-party-claims/:claimId/issuer-attestations";
 const guard=[membership,requireRole("owner","admin","reviewer")];
 app.post(root,...guard,async(req,res,next)=>{try{
  const {caseId,evidenceId,claimId}=req.params,b=req.body,t=req.membership.tenantId;
  if(![caseId,evidenceId,claimId].every(uuid)||!validIssuerRequest(b))
   return res.status(400).json({error:"Invalid scoped issuer attestation request"});
  let issuer;try{issuer=issuerSettings();}catch{return res.status(503).json({error:"Independent authority issuer not configured; fail closed"});}
  const hash=digest(b.attestationJwt);
  const result=await withTenant(t,req.identity.subject,async c=>{
   const source=await c.query("SELECT s.id,s.claimed_party_role,s.key_spki_sha256,k.job_reference"+
    " FROM securepay_signed_party_claims s JOIN securepay_case_rehearsals k ON k.tenant_id=s.tenant_id AND k.id=s.case_id"+
    " WHERE s.tenant_id=$1 AND s.case_id=$2 AND s.evidence_id=$3 AND s.id=$4 AND k.synthetic=true AND k.funds_moved=false",[t,caseId,evidenceId,claimId]);
   if(!source.rowCount)return {httpStatus:404,error:"Synthetic signed claim unavailable"};
   const rev=await c.query("SELECT id FROM securepay_signed_claim_revocations WHERE tenant_id=$1 AND case_id=$2 AND evidence_id=$3 AND claim_id=$4",[t,caseId,evidenceId,claimId]);
   if(rev.rowCount)return {httpStatus:409,error:"Underlying signed claim revoked"};
   const args=[t,caseId,evidenceId,claimId,b.clientRequestId];
   const previous=await c.query("SELECT "+cols+" FROM securepay_job_issuer_attestations WHERE tenant_id=$1 AND case_id=$2 AND evidence_id=$3 AND claim_id=$4 AND client_request_id=$5 AND recorded_by=private.actor_id()",args);
   if(previous.rowCount)return previous.rows[0].token_sha256===hash?
    {httpStatus:200,item:previous.rows[0],signatureReverifiedOnReplay:false}:
    {httpStatus:409,error:"Conflicting issuer attestation request identifier"};
   let result;
   try{result=await verifyIssuerAttestation(b.attestationJwt,issuer,{tenantId:t,caseId,evidenceId,claimId,
    jobReference:source.rows[0].job_reference,claimedPartyRole:source.rows[0].claimed_party_role,
    keySpkiSha256:source.rows[0].key_spki_sha256});}
   catch{return {httpStatus:422,error:"Issuer JWT signature, expiry or exact job scope invalid"};}
   const vals=[...args,result.issuer,result.jti,result.subjectHash,result.tokenHash,result.issuedAt,result.expiresAt];
   const inserted=await c.query("INSERT INTO securepay_job_issuer_attestations(tenant_id,case_id,evidence_id,claim_id,client_request_id,recorded_by,issuer,token_jti,issuer_subject_sha256,token_sha256,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,private.actor_id(),$6,$7,$8,$9,$10,$11) ON CONFLICT DO NOTHING RETURNING "+cols,vals);
   if(inserted.rowCount)return {httpStatus:201,item:inserted.rows[0],issuerSignatureVerifiedAtRequest:true};
   const raced=await c.query("SELECT "+cols+" FROM securepay_job_issuer_attestations WHERE tenant_id=$1 AND case_id=$2 AND evidence_id=$3 AND claim_id=$4 AND client_request_id=$5 AND recorded_by=private.actor_id()",args);
   return raced.rowCount&&raced.rows[0].token_sha256===hash?
    {httpStatus:200,item:raced.rows[0],signatureReverifiedOnReplay:false}:
    {httpStatus:409,error:"Issuer JWT or request identifier already used"};
  },{repeatableRead:true});
  const {httpStatus,...body}=result;res.status(httpStatus).json({...body,...flags});
 }catch(e){next(e);}});
 app.get(root,...guard,async(req,res,next)=>{try{
  const {caseId,evidenceId,claimId}=req.params,t=req.membership.tenantId;
  if(![caseId,evidenceId,claimId].every(uuid))return res.status(400).json({error:"Invalid issuer claim scope"});
  const data=await withTenant(t,req.identity.subject,async c=>{
   const c1=await c.query("SELECT id FROM securepay_signed_party_claims WHERE tenant_id=$1 AND case_id=$2 AND evidence_id=$3 AND id=$4",[t,caseId,evidenceId,claimId]);
   if(!c1.rowCount)return {httpStatus:404,error:"Synthetic signed claim unavailable"};
   const revoked=await c.query("SELECT id FROM securepay_signed_claim_revocations WHERE tenant_id=$1 AND case_id=$2 AND evidence_id=$3 AND claim_id=$4",[t,caseId,evidenceId,claimId]);
   const r=await c.query("SELECT "+cols+" FROM securepay_job_issuer_attestations WHERE tenant_id=$1 AND case_id=$2 AND evidence_id=$3 AND claim_id=$4 ORDER BY recorded_at DESC,id DESC LIMIT 101",[t,caseId,evidenceId,claimId]);
   return {httpStatus:200,items:r.rows.slice(0,100).map(x=>({...x,expired:new Date(x.expires_at).getTime()<=Date.now(),
    underlyingClaimRevoked:revoked.rowCount>0,usableForJobAuthorization:false})),
    truncated:r.rowCount>100,signatureReverifiedAtRead:false};
  },{repeatableRead:true});
  const {httpStatus,...body}=data;res.status(httpStatus).json({...body,...flags});
 }catch(e){next(e);}});
}

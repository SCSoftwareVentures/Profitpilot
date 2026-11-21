import {validSignedPartyClaim,signedPartyStatement,checkSignedPartyClaim,sameSignedClaim} from "../src/securepay-signed-party.js";
import {claimTrustStatus} from "../src/securepay-claim-revocation.js";
const uuid=s=>typeof s==="string"&&/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(s);
const cols="id,case_id,evidence_id,provenance_receipt_id,client_request_id,recorded_by,claimed_party_role,key_spki,claim_nonce,claimed_content_sha256,signature,statement_sha256,key_spki_sha256,issuer_trusted,party_identity_verified,job_authority_verified,content_verified,decision_authority,payment_authority,recorded_at";
const flags={synthetic:true,cryptographicProofOnly:true,trustedIssuerVerified:false,
 partyIdentityVerified:false,partyToJobVerified:false,contentBytesVerified:false,
 independentCustodyVerified:false,decisionAuthority:false,paymentAuthority:false};
function statementFromDb(t,id,eid,b,scope){
 return {tenantId:t,caseId:id,evidenceId:eid,provenanceReceiptId:b.provenanceReceiptId,
  provenanceMetadataSha256:scope.metadata_sha256,jobReference:scope.job_reference,
  evidenceType:scope.evidence_type,evidenceReference:scope.evidence_reference,
  claimedPartyRole:b.claimedPartyRole,claimedContentSha256:b.claimedContentSha256,
  nonce:b.nonce};
}
export function installSecurepaySignedPartyRoutes(app,{membership,requireRole,withTenant}){
 const root="/v1/tenants/:tenantId/prototype/securepay-cases/:caseId/evidence/:evidenceId/signed-party-claims";
 const guarded=[membership,requireRole("owner","admin","reviewer")];
 const scopeQuery="SELECT p.id,p.metadata_sha256,p.reported_origin,k.job_reference,e.evidence_type,e.evidence_reference"+
 " FROM securepay_evidence_provenance_receipts p"+
 " JOIN securepay_evidence_rehearsals e ON e.tenant_id=p.tenant_id AND e.case_id=p.case_id AND e.id=p.evidence_id"+
 " JOIN securepay_case_rehearsals k ON k.tenant_id=p.tenant_id AND k.id=p.case_id"+
 " WHERE p.tenant_id=$1 AND p.case_id=$2 AND p.evidence_id=$3 AND p.id=$4";
 app.post(root,...guarded,async(req,res,next)=>{try{
  const t=req.membership.tenantId,id=req.params.caseId,eid=req.params.evidenceId,b=req.body;
  if(!uuid(id)||!uuid(eid)||!validSignedPartyClaim(b))
   return res.status(400).json({error:"Valid synthetic signed-claim inputs required"});
  const output=await withTenant(t,req.identity.subject,async c=>{
   const source=await c.query(scopeQuery,[t,id,eid,b.provenanceReceiptId]);
   if(!source.rowCount)return {status:404,error:"Synthetic evidence provenance unavailable"};
   const row=source.rows[0];
   if((b.claimedPartyRole==="customer"&&(row.reported_origin!=="reported_customer"||row.evidence_type!=="claim_reported"))||
      (b.claimedPartyRole==="tradesperson"&&(row.reported_origin!=="reported_business"||row.evidence_type!=="business_response_reported")))
    return {status:409,error:"Claimed party role does not match recorded evidence origin and type"};
   const params=[t,id,eid,b.clientRequestId];
   const prior=await c.query("SELECT "+cols+" FROM securepay_signed_party_claims WHERE tenant_id=$1 AND case_id=$2 AND evidence_id=$3 AND client_request_id=$4 AND recorded_by=private.actor_id()",params);
   if(prior.rowCount)return sameSignedClaim(prior.rows[0],b)?
    {status:200,item:prior.rows[0]}:{status:409,error:"Conflicting signed-claim request identifier"};
   let proof;
   try{proof=checkSignedPartyClaim(statementFromDb(t,id,eid,b,row),b.keySpki,b.signature);}
   catch{return {status:422,error:"Invalid Ed25519 public key or signature encoding"};}
   if(!proof.signatureValid)return {status:422,error:"Invalid or mismatched synthetic signature"};
   const vals=[t,id,eid,b.provenanceReceiptId,b.clientRequestId,b.claimedPartyRole,b.keySpki,b.nonce,b.claimedContentSha256,b.signature,proof.statementSha256,proof.keySpkiSha256];
   const created=await c.query(
    "INSERT INTO securepay_signed_party_claims(tenant_id,case_id,evidence_id,provenance_receipt_id,client_request_id,recorded_by,claimed_party_role,key_spki,claim_nonce,claimed_content_sha256,signature,statement_sha256,key_spki_sha256)"+
    " VALUES($1,$2,$3,$4,$5,private.actor_id(),$6,$7,$8,$9,$10,$11,$12) ON CONFLICT DO NOTHING RETURNING "+cols,vals);
   if(created.rowCount)return {status:201,item:created.rows[0],signatureValid:true};
   const race=await c.query("SELECT "+cols+" FROM securepay_signed_party_claims WHERE tenant_id=$1 AND case_id=$2 AND evidence_id=$3 AND client_request_id=$4 AND recorded_by=private.actor_id()",params);
   return race.rowCount&&sameSignedClaim(race.rows[0],b)?
    {status:200,item:race.rows[0]}:{status:409,error:"Conflicting signed-claim request identifier"};
  },{repeatableRead:true});
  const {status,...data}=output;res.status(status).json({...data,...flags});
 }catch(e){next(e);}});
 app.get(root,...guarded,async(req,res,next)=>{try{
  const t=req.membership.tenantId,id=req.params.caseId,eid=req.params.evidenceId,cursor=req.query.cursor??null;
  if(!uuid(id)||!uuid(eid)||(cursor!==null&&!uuid(cursor)))
   return res.status(400).json({error:"Invalid case, evidence or claim cursor"});
  const output=await withTenant(t,req.identity.subject,async c=>{
   const e=await c.query("SELECT id FROM securepay_evidence_rehearsals WHERE tenant_id=$1 AND case_id=$2 AND id=$3",[t,id,eid]);
   if(!e.rowCount)return {status:404,error:"Synthetic evidence unavailable"};
   if(cursor!==null){
    const a=await c.query("SELECT id FROM securepay_signed_party_claims WHERE tenant_id=$1 AND case_id=$2 AND evidence_id=$3 AND id=$4",[t,id,eid,cursor]);
    if(!a.rowCount)return {status:404,error:"Signed-claim cursor unavailable"};
   }
   const r=await c.query("SELECT "+cols+" FROM securepay_signed_party_claims WHERE tenant_id=$1 AND case_id=$2 AND evidence_id=$3 AND ($4::uuid IS NULL OR (recorded_at,id)<(SELECT recorded_at,id FROM securepay_signed_party_claims WHERE tenant_id=$1 AND case_id=$2 AND evidence_id=$3 AND id=$4)) ORDER BY recorded_at DESC,id DESC LIMIT 101",[t,id,eid,cursor]);
   const items=r.rows.slice(0,100);
   const revokeIds=items.map(x=>x.id);
   const revoked=revokeIds.length?(await c.query("SELECT claim_id FROM securepay_signed_claim_revocations WHERE tenant_id=$1 AND case_id=$2 AND evidence_id=$3 AND claim_id=ANY($4::uuid[])",[t,id,eid,revokeIds])).rows:[];
   const revokedSet=new Set(revoked.map(x=>x.claim_id));
   return {status:200,items:items.map(x=>({...x,revoked:revokedSet.has(x.id),operationallyUsable:false})),
    hasMore:r.rowCount>100,nextCursor:r.rowCount>100?items.at(-1).id:null};
  },{repeatableRead:true});
  const {status,...data}=output;res.status(status).json({...data,...flags,signaturesNotReverifiedInList:true});
 }catch(e){next(e);}});
 app.get(root+"/:claimId/verify-signature",...guarded,async(req,res,next)=>{try{
  const t=req.membership.tenantId,id=req.params.caseId,eid=req.params.evidenceId,claimId=req.params.claimId;
  if(!uuid(id)||!uuid(eid)||!uuid(claimId))return res.status(400).json({error:"Invalid case, evidence or claim ID"});
  const output=await withTenant(t,req.identity.subject,async c=>{
   const r=await c.query("SELECT "+cols+" FROM securepay_signed_party_claims WHERE tenant_id=$1 AND case_id=$2 AND evidence_id=$3 AND id=$4",[t,id,eid,claimId]);
   if(!r.rowCount)return {status:404,error:"Synthetic signed claim unavailable"};
   const claim=r.rows[0];
   const scope=await c.query(scopeQuery,[t,id,eid,claim.provenance_receipt_id]);
   if(!scope.rowCount)return {status:409,error:"Signed claim source record missing"};
   const input={provenanceReceiptId:claim.provenance_receipt_id,claimedPartyRole:claim.claimed_party_role,
    claimedContentSha256:claim.claimed_content_sha256,nonce:claim.claim_nonce};
   let proof;
   try{proof=checkSignedPartyClaim(statementFromDb(t,id,eid,input,scope.rows[0]),claim.key_spki,claim.signature);}
   catch{return {status:409,error:"Stored signature cannot be verified"};}
   const match=proof.signatureValid&&proof.statementSha256===claim.statement_sha256&&proof.keySpkiSha256===claim.key_spki_sha256;
   const revocation=await c.query("SELECT id,recorded_at FROM securepay_signed_claim_revocations WHERE tenant_id=$1 AND case_id=$2 AND evidence_id=$3 AND claim_id=$4",[t,id,eid,claimId]);
   const state=claimTrustStatus({revoked:revocation.rowCount>0,signatureValid:match});
   return {status:200,claimId,...state,revokedAt:revocation.rows[0]?.recorded_at??null,
    trustVerified:false,trustBlockingGates:state.blockingGates};
  },{repeatableRead:true});
  const {status,...data}=output;res.status(status).json({...data,...flags});
 }catch(e){next(e);}});
}

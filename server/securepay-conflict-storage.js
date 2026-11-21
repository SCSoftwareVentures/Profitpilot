import {validConflictDeclaration,sameConflictDeclaration} from "../src/securepay-conflicts.js";
const uuid=x=>typeof x==="string"&&/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(x);
const fields="id,case_id,client_request_id,reviewer_id,declaration_status,conflict_code,disclosure_reference,independently_screened,identity_verified,decision_authority,payment_authority,recorded_at";
const flags={synthetic:true,selfReportedOnly:true,conflictIndependentlyScreened:false,identityVerified:false,decisionAuthority:false,paymentAuthority:false};
export function installSecurepayConflictDeclarationRoutes(app,{membership,requireRole,withTenant}){
 const root="/v1/tenants/:tenantId/prototype/securepay-cases/:caseId/reviewer-declarations";
 app.post(root,membership,requireRole("reviewer"),async(req,res,next)=>{try{
  const caseId=req.params.caseId,t=req.membership.tenantId,b=req.body;
  if(!uuid(caseId)||!validConflictDeclaration(b))
   return res.status(400).json({error:"Valid case and exact bounded self-declaration required"});
  const output=await withTenant(t,req.identity.subject,async c=>{
   const existingCase=await c.query("SELECT id FROM securepay_case_rehearsals WHERE tenant_id=$1 AND id=$2",[t,caseId]);
   if(!existingCase.rowCount)return {status:404,error:"Synthetic case unavailable"};
   const p=[t,caseId,b.clientRequestId];
   const previous=await c.query("SELECT "+fields+" FROM securepay_reviewer_declarations WHERE tenant_id=$1 AND case_id=$2 AND client_request_id=$3 AND reviewer_id=private.actor_id()",p);
   if(previous.rowCount)return sameConflictDeclaration(previous.rows[0],b)?
    {status:200,item:previous.rows[0]}:{status:409,error:"Conflicting declaration request identifier"};
   const values=[t,caseId,b.clientRequestId,b.declarationStatus,b.conflictCode,b.disclosureReference];
   const inserted=await c.query("INSERT INTO securepay_reviewer_declarations(tenant_id,case_id,client_request_id,reviewer_id,declaration_status,conflict_code,disclosure_reference) VALUES($1,$2,$3,private.actor_id(),$4,$5,$6) ON CONFLICT DO NOTHING RETURNING "+fields,values);
   if(inserted.rowCount)return {status:201,item:inserted.rows[0]};
   const raced=await c.query("SELECT "+fields+" FROM securepay_reviewer_declarations WHERE tenant_id=$1 AND case_id=$2 AND client_request_id=$3 AND reviewer_id=private.actor_id()",p);
   return raced.rowCount&&sameConflictDeclaration(raced.rows[0],b)?
    {status:200,item:raced.rows[0]}:{status:409,error:"Conflicting declaration request identifier"};
  });
  const {status,...payload}=output;res.status(status).json({...payload,...flags});
 }catch(e){next(e);}});
 app.get(root,membership,requireRole("owner","admin","reviewer"),async(req,res,next)=>{try{
  const t=req.membership.tenantId,caseId=req.params.caseId,cursor=req.query.cursor??null;
  if(!uuid(caseId)||(cursor!==null&&!uuid(cursor)))return res.status(400).json({error:"Invalid case or declaration cursor"});
  const output=await withTenant(t,req.identity.subject,async c=>{
   const found=await c.query("SELECT id FROM securepay_case_rehearsals WHERE tenant_id=$1 AND id=$2",[t,caseId]);
   if(!found.rowCount)return {status:404,error:"Synthetic case unavailable"};
   if(cursor!==null){
    const anchor=await c.query("SELECT id FROM securepay_reviewer_declarations WHERE tenant_id=$1 AND case_id=$2 AND id=$3",[t,caseId,cursor]);
    if(!anchor.rowCount)return {status:404,error:"Declaration cursor unavailable"};
   }
   const page=await c.query("SELECT "+fields+" FROM securepay_reviewer_declarations WHERE tenant_id=$1 AND case_id=$2 AND ($3::uuid IS NULL OR (recorded_at,id)<(SELECT recorded_at,id FROM securepay_reviewer_declarations WHERE tenant_id=$1 AND case_id=$2 AND id=$3)) ORDER BY recorded_at DESC,id DESC LIMIT 101",[t,caseId,cursor]);
   const items=page.rows.slice(0,100);
   return {status:200,items,hasMore:page.rowCount>100,nextCursor:page.rowCount>100?items.at(-1).id:null};
  },{repeatableRead:true});
  const {status,...payload}=output;res.status(status).json({...payload,...flags});
 }catch(e){next(e);}});
}

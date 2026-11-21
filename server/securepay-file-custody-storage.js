import express from "express";
import {scanSource} from "./malware.js";
import {MAX_CUSTODY_BYTES,validCustodyHeaders,verifyCustodyBytes,sameCustodyReceipt} from "../src/securepay-file-custody.js";
import {custodyKeyringSettings,resolveCustodyReceiptKey,sealCustodyBytes,verifyScanMac} from "../src/securepay-encrypted-custody.js";
const uuid=x=>typeof x==="string"&&/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(x);
const cols="id,tenant_id,case_id,evidence_id,client_request_id,received_by,sha256,byte_count,media_type,scan_status,scan_observed_at,scanner_attestation_mac,encryption_algorithm,key_id,aad_sha256,ciphertext_sha256,origin_verified,source_identity_verified,independent_scanner_verified,independent_custody_verified,retention_policy_enforced,decision_authority,payment_authority,recorded_at";
const oldCols="id,tenant_id,case_id,evidence_id,client_request_id,received_by,sha256,byte_count,media_type,scan_status,origin_verified,source_identity_verified,independent_custody_verified,decision_authority,payment_authority,recorded_at";
const flags={synthetic:true,originalBytesDownloadAvailable:false,sourceAuthenticityVerified:false,
 realPartyIdentityVerified:false,independentScannerVerified:false,independentCustodyVerified:false,
 retentionPolicyEnforced:false,decisionAuthority:false,paymentAuthority:false};
const noMac=x=>{const {scanner_attestation_mac,...safe}=x;return safe;};
export function installSecurepayFileCustodyRoutes(app,{membership,requireRole,withTenant,scannerEnabled=false,scan=scanSource}){
 const path="/v1/tenants/:tenantId/prototype/securepay-cases/:caseId/evidence/:evidenceId/custody-file";
 const guard=[membership,requireRole("owner","admin","reviewer")];
 app.post(path,...guard,(req,res,next)=>{
  if(!uuid(req.params.caseId)||!uuid(req.params.evidenceId))return res.status(400).json({error:"Invalid evidence scope"});
  if(!req.is("application/octet-stream")||(req.get("content-encoding")||"identity").toLowerCase()!=="identity")
   return res.status(415).json({error:"Raw uncompressed application/octet-stream required"});
  if(!validCustodyHeaders({clientRequestId:req.get("x-client-request-id"),declaredSha256:req.get("x-evidence-sha256"),
   mediaType:req.get("x-evidence-media-type"),contentEncoding:req.get("content-encoding")}))
   return res.status(400).json({error:"Valid custody request UUID, SHA-256 and media type required"});
  if(!scannerEnabled)return res.status(503).json({error:"Evidence scanner unavailable; no bytes stored"});
  try{custodyKeyringSettings();}catch{return res.status(503).json({error:"Encrypted custody keys unavailable; no bytes stored"});}
  next();
 },express.raw({type:"application/octet-stream",limit:MAX_CUSTODY_BYTES,inflate:false}),async(req,res,next)=>{try{
  let valid;
  try{valid=verifyCustodyBytes(req.body,req.get("x-evidence-sha256"),req.get("x-evidence-media-type"));}
  catch{return res.status(422).json({error:"Evidence byte integrity or media signature invalid"});}
  const verdict=await scan(req.body,{enabled:true});
  if(verdict==="infected")return res.status(422).json({error:"Malware scanner reported infected bytes; no storage"});
  if(verdict!=="scanner_reported_clean")return res.status(503).json({error:"Clean scanner verdict unavailable; no storage"});
  let ring;try{ring=custodyKeyringSettings();}catch{return res.status(503).json({error:"Encrypted custody keys unavailable; no bytes stored"});}
  const tenant=req.membership.tenantId,{caseId,evidenceId}=req.params,clientRequestId=req.get("x-client-request-id");
  const result=await withTenant(tenant,req.identity.subject,async c=>{
   const source=await c.query("SELECT e.id FROM securepay_evidence_rehearsals e JOIN securepay_case_rehearsals k ON k.tenant_id=e.tenant_id AND k.id=e.case_id WHERE e.tenant_id=$1 AND e.case_id=$2 AND e.id=$3 AND k.synthetic=true AND k.funds_moved=false",[tenant,caseId,evidenceId]);
   if(!source.rowCount)return {httpStatus:404,error:"Synthetic evidence unavailable"};
   const actor=(await c.query("SELECT private.actor_id()::text AS id")).rows[0]?.id;
   if(!uuid(actor))return {httpStatus:403,error:"Signed tenant operator context required"};
   const args=[tenant,caseId,evidenceId];
   const old=await c.query("SELECT id FROM securepay_evidence_custody_receipts WHERE tenant_id=$1 AND case_id=$2 AND evidence_id=$3",args);
   if(old.rowCount)return {httpStatus:409,error:"Legacy plaintext custody requires separate migration and review"};
   const prev=await c.query("SELECT "+cols+" FROM securepay_encrypted_custody_receipts WHERE tenant_id=$1 AND case_id=$2 AND evidence_id=$3",args);
   const request={clientRequestId,sha256:valid.sha256,mediaType:valid.mediaType};
   if(prev.rowCount){
    const same=sameCustodyReceipt(prev.rows[0],request,actor);
    const macOk=verifyScanMac(prev.rows[0],resolveCustodyReceiptKey(ring,prev.rows[0].key_id));
    return same&&macOk?{httpStatus:200,item:prev.rows[0],idempotent:true,macOk:true}:
     {httpStatus:409,error:"Encrypted receipt already exists or signing key changed; manual review required"};
   }
   const scope={tenantId:tenant,caseId,evidenceId,clientRequestId,actorId:actor,sha256:valid.sha256,
    byteCount:valid.byteCount,mediaType:valid.mediaType,keyId:ring.active.keyId};
   const sealed=sealCustodyBytes(req.body,scope,ring.active);
   const created=await c.query("INSERT INTO securepay_encrypted_custody_receipts(tenant_id,case_id,evidence_id,client_request_id,received_by,sha256,byte_count,media_type,scan_observed_at,scanner_attestation_mac,encryption_algorithm,key_id,aad_sha256,ciphertext_sha256,nonce,auth_tag,ciphertext) VALUES($1,$2,$3,$4,private.actor_id(),$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) ON CONFLICT DO NOTHING RETURNING "+cols,
    [tenant,caseId,evidenceId,clientRequestId,valid.sha256,valid.byteCount,valid.mediaType,
     sealed.observedAt,sealed.attestationMac,sealed.algorithm,sealed.keyId,sealed.aadSha256,
     sealed.ciphertextSha256,sealed.nonce,sealed.tag,sealed.ciphertext]);
   if(created.rowCount)return {httpStatus:201,item:created.rows[0],idempotent:false,macOk:true};
   const raced=await c.query("SELECT "+cols+" FROM securepay_encrypted_custody_receipts WHERE tenant_id=$1 AND case_id=$2 AND evidence_id=$3",args);
   return raced.rowCount&&sameCustodyReceipt(raced.rows[0],request,actor)&&verifyScanMac(raced.rows[0],resolveCustodyReceiptKey(ring,raced.rows[0].key_id))?
    {httpStatus:200,item:raced.rows[0],idempotent:true,macOk:true}:
    {httpStatus:409,error:"Encrypted custody receipt already sealed; conflicting request"};
  });
  const {httpStatus,item,macOk,...rest}=result;
  const saved=httpStatus===200||httpStatus===201;
  res.status(httpStatus).json({...rest,...(item?{item:noMac(item)}:{}),...flags,
   originalBytesStored:saved,encryptedAtApplicationLayer:saved,
   receivedByteIntegrityVerified:saved,scanRecordMacVerified:saved&&macOk===true,
   externallySignedScannerVerdict:false});
 }catch(e){next(e);}});
 app.get(path,...guard,async(req,res,next)=>{try{
  const tenant=req.membership.tenantId,{caseId,evidenceId}=req.params;
  if(!uuid(caseId)||!uuid(evidenceId))return res.status(400).json({error:"Invalid evidence scope"});
  let settings;try{settings=custodyKeyringSettings();}catch{settings=null;}
  const result=await withTenant(tenant,req.identity.subject,async c=>{
   const args=[tenant,caseId,evidenceId];
   const source=await c.query("SELECT id FROM securepay_evidence_rehearsals WHERE tenant_id=$1 AND case_id=$2 AND id=$3",args);
   if(!source.rowCount)return {httpStatus:404,error:"Synthetic evidence unavailable"};
   const current=await c.query("SELECT "+cols+" FROM securepay_encrypted_custody_receipts WHERE tenant_id=$1 AND case_id=$2 AND evidence_id=$3",args);
   if(current.rowCount)return {httpStatus:200,received:true,legacy:false,item:current.rows[0]};
   const legacy=await c.query("SELECT "+oldCols+" FROM securepay_evidence_custody_receipts WHERE tenant_id=$1 AND case_id=$2 AND evidence_id=$3",args);
   return {httpStatus:200,received:legacy.rowCount===1,legacy:legacy.rowCount===1,item:legacy.rows[0]??null};
  },{repeatableRead:true});
  const {httpStatus,received,legacy,item,error}=result;
  if(httpStatus!==200)return res.status(httpStatus).json({error,...flags,received:false});
  let macOk=false;if(item&&!legacy&&settings){try{macOk=verifyScanMac(item,resolveCustodyReceiptKey(settings,item.key_id));}catch{macOk=false;}}
  res.status(200).json({received,item:item?legacy?item:noMac(item):null,...flags,
   storageClass:legacy?"legacy_plaintext_requires_review":received?"application_aead_encrypted":"none",
   originalBytesStored:received,encryptedAtApplicationLayer:received&&!legacy,
   receivedByteIntegrityVerified:received&&!legacy,scanRecordMacVerified:macOk,
   scanRecordReverifiedAtRead:macOk,legacyMigrationRequired:legacy,
   keyRecoveryRequired:received&&!legacy&&!resolveCustodyReceiptKey(settings,item?.key_id),
   operationallyUsable:false});
 }catch(e){next(e);}});
}

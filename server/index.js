import "dotenv/config";
import express from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import {randomUUID} from "node:crypto";
import {withTenant,health} from "./db.js";
import {parseSourceFile,MAX_SOURCE_BYTES} from "./source-file.js";
import {allowedImportRows} from "./privacy.js";
import {deploymentProfile,readSecret} from "./deployment.js";
import {scanSource,SCANNER_PATH} from "./malware.js";
import {accessSync,constants as fsConstants} from "node:fs";
import {authRequired,requireRole} from "./auth.js";
import {installSecurepayStorageRoutes} from "./securepay-storage.js";
import {installSecurepayReviewerRoutes} from "./securepay-review-storage.js";
import {installSecurepayConflictDeclarationRoutes} from "./securepay-conflict-storage.js";
import {installSecurepayProvenanceRoutes} from "./securepay-provenance-storage.js";
import {installSecurepaySignedPartyRoutes} from "./securepay-signed-party-storage.js";
import {installSecurepayClaimRevocationRoutes} from "./securepay-claim-revocation-storage.js";
import {validateInvoiceRows,validatePayrollRows,reconcilePayroll,isIsoDate} from "../src/engine.js";

import {classifyInvoiceIdentity} from "../src/invoice-identity.js";
import {FORMULA_VERSION,MAX_EVIDENCE_LINES,contributionTotals,snapshotDigest,invoiceCostBridge,unifiedRehearsalContribution} from "../src/financial-calculation.js";

const MAX_IMPORT_ROWS=2000;
const isUuid=value=>typeof value==="string"&&/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);

const profile=deploymentProfile();
if(profile.protectedMode&&!/^(?:[a-f0-9]{2}){32,}$/i.test(readSecret("TENANT_CONTEXT_HMAC_SECRET")))throw new Error("Invalid mounted signing key");
if(profile.protectedMode)accessSync(SCANNER_PATH,fsConstants.X_OK);
const app=express();
app.disable("x-powered-by");
app.use(helmet());
app.use(cors({origin:(process.env.CORS_ORIGIN||"").split(",").map(x=>x.trim()).filter(Boolean),credentials:false,methods:["GET","POST"]}));
app.use("/v1",(_req,res,next)=>{res.set("Cache-Control","no-store");res.set("Pragma","no-cache");next();});
export const requestLimiter=rateLimit({windowMs:60_000,limit:100,standardHeaders:true,legacyHeaders:false});
app.use(requestLimiter);
app.get("/health",async(req,res)=>{try{await health();res.json({status:"ok",database:"connected"});}catch{res.status(503).json({status:"unavailable"});}});
app.use("/v1",authRequired());
app.use("/v1",express.json({limit:"100kb",inflate:false}));
app.use("/v1/tenants/:tenantId/prototype",(_req,res,next)=>{if(profile.protectedMode)return res.status(403).json({error:"Synthetic rehearsal unavailable in protected profile"});next();});

async function membership(req,res,next){
 const tenantId=req.params.tenantId;
 if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(tenantId))return res.status(400).json({error:"Invalid tenant ID"});
 try{
  const r=await withTenant(tenantId,req.identity.subject,client=>client.query("SELECT role FROM tenant_memberships tm JOIN users u ON u.id=tm.user_id JOIN tenants t ON t.id=tm.tenant_id WHERE tm.tenant_id=$1 AND u.auth_subject=$2 AND tm.status='active' AND u.status='active' AND t.status='active'",[tenantId,req.identity.subject]));
  if(!r.rowCount)return res.status(403).json({error:"No active membership for this tenant"});
  req.membership={tenantId,role:r.rows[0].role};next();
 }catch(e){next(e);}
}
// Synthetic-only preview: caller-supplied identifiers are not authenticated issuer evidence.
app.post("/v1/tenants/:tenantId/prototype/invoice-identity-preview",membership,requireRole("owner","admin","analyst","reviewer"),(req,res)=>{
 const {synthetic,rows}=req.body||{};
 if(synthetic!==true||!Array.isArray(rows)||rows.length<1||rows.length>200||rows.some(r=>!r||typeof r!=="object"||Array.isArray(r)||Object.keys(r).some(k=>!["direction","issuerKey","invoiceReference"].includes(k))||Object.values(r).some(v=>typeof v!=="string"||v.length>200)))return res.status(400).json({error:"Explicit synthetic mode and 1–200 bounded invoice identity rows required"});
 const items=classifyInvoiceIdentity(rows).map((r,i)=>({rowNumber:i+1,...r}));
 res.set("Cache-Control","no-store");
 res.json({synthetic:true,issuerAuthenticated:false,automaticallyAccepted:0,items});
});

const privacyColumns="id,requester_id,request_type,status,created_at,reviewed_at,review_reference";
app.get("/v1/tenants/:tenantId/privacy-requests",membership,async(req,res,next)=>{try{
 const cursor=req.query.cursor??null;
 if(cursor!==null&&!isUuid(cursor))return res.status(400).json({error:"Invalid privacy cursor"});
 const result=await withTenant(req.membership.tenantId,req.identity.subject,async c=>{
  if(cursor!==null){
   const anchor=await c.query("SELECT id FROM privacy_requests WHERE tenant_id=$1 AND id=$2",[req.membership.tenantId,cursor]);
   if(!anchor.rowCount)return {invalidCursor:true};
  }
  const cases=await c.query("SELECT "+privacyColumns+" FROM privacy_requests WHERE tenant_id=$1 AND ($2::uuid IS NULL OR (created_at,id)<(SELECT created_at,id FROM privacy_requests WHERE tenant_id=$1 AND id=$2)) ORDER BY created_at DESC,id DESC LIMIT 201",[req.membership.tenantId,cursor]);
  const page=cases.rows.slice(0,200);
  return {items:page,limit:200,additionalRequests:cases.rowCount>200,nextCursor:cases.rowCount>200?page.at(-1).id:null,scope:"Own requests or authorised tenant administration; case tracking only"};
 },{repeatableRead:true});
 if(result.invalidCursor)return res.status(404).json({error:"Privacy cursor unavailable"});
 res.json(result);
}catch(e){next(e);}});
app.post("/v1/tenants/:tenantId/privacy-requests",membership,async(req,res,next)=>{try{
 const body=req.body||{}, {clientRequestId,requestType}=body;
 if(Object.keys(body).some(k=>!["clientRequestId","requestType"].includes(k))||!isUuid(clientRequestId)||!["access","correction","erasure","restriction"].includes(requestType))return res.status(400).json({error:"Request type and client request UUID required; do not submit personal details"});
 const result=await withTenant(req.membership.tenantId,req.identity.subject,async c=>{
  const args=[req.membership.tenantId,clientRequestId,requestType];
  const inserted=await c.query("INSERT INTO privacy_requests(tenant_id,requester_id,client_request_id,request_type) VALUES($1,private.actor_id(),$2,$3) ON CONFLICT DO NOTHING RETURNING "+privacyColumns,args);
  if(inserted.rowCount)return {status:201,item:inserted.rows[0]};
  const existing=await c.query("SELECT "+privacyColumns+" FROM privacy_requests WHERE tenant_id=$1 AND requester_id=private.actor_id() AND client_request_id=$2 AND request_type=$3",args);
  return existing.rowCount?{status:200,item:existing.rows[0]}:{status:409,error:"Conflicting privacy request identifier"};
 });
 const {status,...bodyOut}=result;res.status(status).json({...bodyOut,automatedErasure:false});
}catch(e){next(e);}});
app.post("/v1/tenants/:tenantId/privacy-requests/:requestId/review",membership,requireRole("owner","admin"),async(req,res,next)=>{try{
 const body=req.body||{}, {status:decision,reviewReference}=body;
 if(!isUuid(req.params.requestId)||Object.keys(body).some(k=>!["status","reviewReference"].includes(k))||!["reviewing","closed_attested","declined"].includes(decision)||typeof reviewReference!=="string"||!/^[A-Za-z0-9][A-Za-z0-9._:-]{2,119}$/.test(reviewReference))return res.status(400).json({error:"Valid review status and opaque case reference required"});
 const result=await withTenant(req.membership.tenantId,req.identity.subject,c=>c.query("UPDATE privacy_requests SET status=$1,reviewed_by=private.actor_id(),reviewed_at=now(),review_reference=$2 WHERE tenant_id=$3 AND id=$4 AND requester_id<>private.actor_id() AND ((status='requested' AND $1='reviewing') OR (status='reviewing' AND $1 IN ('closed_attested','declined'))) RETURNING "+privacyColumns,[decision,reviewReference,req.membership.tenantId,req.params.requestId]));
 if(!result.rowCount)return res.status(409).json({error:"Request unavailable, self-review prohibited or invalid transition"});
 res.json({item:result.rows[0],automatedErasure:false,externalFulfilmentVerified:false});
}catch(e){
 if(e.code==="23514")return res.status(409).json({error:"Independent privacy review required or decision conflicts with current case"});
 next(e);
}});


app.get("/v1/tenants/:tenantId/privacy-requests/:requestId/evidence",membership,async(req,res,next)=>{try{
 if(!isUuid(req.params.requestId))return res.status(400).json({error:"Invalid privacy request identifier"});
 const result=await withTenant(req.membership.tenantId,req.identity.subject,async c=>{
  const caseRow=await c.query("SELECT id FROM privacy_requests WHERE tenant_id=$1 AND id=$2",[req.membership.tenantId,req.params.requestId]);
  if(!caseRow.rowCount)return null;
  return (await c.query("SELECT scope,outcome,evidence_reference,recorded_at FROM private.privacy_case_evidence WHERE tenant_id=$1 AND case_id=$2 ORDER BY scope",[req.membership.tenantId,req.params.requestId])).rows;
 });
 if(result===null)return res.status(404).json({error:"Privacy request unavailable"});
 res.json({items:result,externalFulfilmentVerified:false,automatedErasure:false,scope:"Opaque operator attestations only, not verified downstream execution"});
}catch(e){next(e);}});

app.get("/v1/tenants/:tenantId/privacy/self-access",membership,async(req,res,next)=>{try{
 const cursor=req.query.cursor??null;
 if(cursor!==null&&!isUuid(cursor))return res.status(400).json({error:"Invalid privacy cursor"});
 const result=await withTenant(req.membership.tenantId,req.identity.subject,async c=>{
  if(cursor!==null){const anchor=await c.query("SELECT id FROM privacy_requests WHERE tenant_id=$1 AND requester_id=private.actor_id() AND id=$2",[req.membership.tenantId,cursor]);if(!anchor.rowCount)return {invalidCursor:true};}
  const identity=await c.query("SELECT u.id,u.email,u.status,u.created_at,m.role,m.status AS membership_status,m.granted_at FROM users u JOIN tenant_memberships m ON m.user_id=u.id WHERE m.tenant_id=$1 AND u.id=private.actor_id()",[req.membership.tenantId]);
  const cases=await c.query("SELECT "+privacyColumns+" FROM privacy_requests WHERE tenant_id=$1 AND requester_id=private.actor_id() AND ($2::uuid IS NULL OR (created_at,id)<(SELECT created_at,id FROM privacy_requests WHERE tenant_id=$1 AND requester_id=private.actor_id() AND id=$2)) ORDER BY created_at DESC,id DESC LIMIT 201",[req.membership.tenantId,cursor]);
  const page=cases.rows.slice(0,200);return {identity:identity.rows[0],privacyRequests:page,additionalRequests:cases.rowCount>200,nextCursor:cases.rowCount>200?page.at(-1).id:null};
 },{repeatableRead:true});
 if(result.invalidCursor)return res.status(404).json({error:"Privacy cursor unavailable"});
 if(!result.identity)return res.status(403).json({error:"Active identity required"});
 res.set("Content-Disposition",'attachment; filename="profitpilot-self-access.json"');
 res.json({scope:"Own stored identity, current tenant membership and own privacy case metadata only",completeDataSubjectExport:false,...result});
}catch(e){next(e);}});

app.get("/v1/me",async(req,res)=>{res.json({subject:req.identity.subject,email:req.identity.email,membershipsEndpoint:"Membership discovery is not exposed until a separately reviewed security-definer function is installed."});});
app.get("/v1/tenants/:tenantId/contracts",membership,async(req,res,next)=>{try{const rows=await withTenant(req.membership.tenantId,req.identity.subject,async c=>(await c.query("SELECT id,customer_name,status FROM contracts WHERE tenant_id=$1 ORDER BY customer_name",[req.membership.tenantId])).rows);res.json({items:rows});}catch(e){next(e);}});
app.post("/v1/tenants/:tenantId/imports",membership,requireRole("owner","admin","analyst"),async(req,res,next)=>{
 try{
  const {sourceType,fileName,sha256,permissionReference,periodStart,periodEnd}=req.body||{};
  if(!["payroll","customer_invoice","supplier_invoice"].includes(sourceType)||typeof fileName!=="string"||!fileName.trim()||fileName.length>255||typeof sha256!=="string"||!/^[a-f0-9]{64}$/i.test(sha256)||typeof permissionReference!=="string"||!permissionReference.trim()||permissionReference.length>2000||!isIsoDate(periodStart)||!isIsoDate(periodEnd)||periodEnd<periodStart)return res.status(400).json({error:"Invalid import metadata"});
  const result=await withTenant(req.membership.tenantId,req.identity.subject,async c=>{
   const args=[req.membership.tenantId,sourceType,periodStart,periodEnd,permissionReference.trim(),sha256.toLowerCase(),fileName.trim(),req.identity.subject];
   const inserted=await c.query("INSERT INTO import_batches(tenant_id,source_type,source_period_start,source_period_end,permission_ref,status,file_sha256,file_name,created_by) SELECT $1,$2,$3,$4,$5,'uploaded',$6,$7,u.id FROM users u WHERE u.auth_subject=$8 ON CONFLICT(tenant_id,file_sha256) DO NOTHING RETURNING id,status",args);
   if(inserted.rowCount)return {status:201,batch:inserted.rows[0]};
   const old=await c.query("SELECT id,status,(source_type=$2 AND source_period_start=$3::date AND source_period_end=$4::date AND permission_ref=$5 AND file_name=$7) AS identical FROM import_batches WHERE tenant_id=$1 AND file_sha256=$6",args.slice(0,7));
   if(!old.rowCount)throw Object.assign(new Error("Import identity or membership is unavailable"),{status:403});
   if(!old.rows[0].identical)return {status:409,error:"Source hash already exists with different import metadata"};
   return {status:200,batch:{id:old.rows[0].id,status:old.rows[0].status},idempotent:true};
  });
  const {status,...body}=result;res.status(status).json(body);
 }catch(e){next(e);}
});


app.post("/v1/tenants/:tenantId/imports/:batchId/file",membership,requireRole("owner","admin","analyst"),
 (req,res,next)=>{
  if(!isUuid(req.params.batchId))return res.status(400).json({error:"Invalid batch ID"});
  if(!req.is("text/csv")||(req.get("content-encoding")||"identity").toLowerCase()!=="identity")return res.status(415).json({error:"Only uncompressed text/csv is supported"});
  next();
 },express.raw({type:"text/csv",limit:MAX_SOURCE_BYTES,inflate:false}),async(req,res,next)=>{try{
 const bytes=req.body;
 if(!(bytes instanceof Buffer)||!Buffer.isBuffer(bytes))return res.status(422).json({error:"CSV body required"});
 const byteCount=bytes.byteLength;
 if(byteCount<1||byteCount>MAX_SOURCE_BYTES)return res.status(422).json({error:"CSV body outside supported bounds"});
 const scanStatus=await scanSource(bytes,{enabled:profile.scannerEnabled});
 if(scanStatus==="infected")return res.status(422).json({error:"File rejected by malware scanner"});
 if(scanStatus==="unavailable"||(profile.protectedMode&&scanStatus!=="scanner_reported_clean"))return res.status(503).json({error:"Malware scan unavailable; file not stored"});
 const result=await withTenant(req.membership.tenantId,req.identity.subject,async c=>{
  const tenant=req.membership.tenantId,batchId=req.params.batchId;
  const batch=await c.query("SELECT id,status,source_type,file_sha256,file_name FROM import_batches WHERE tenant_id=$1 AND id=$2 FOR UPDATE",[tenant,batchId]);
  if(!batch.rowCount)return {status:404,error:"Import batch not found"};
  const b=batch.rows[0];
  if(!b.file_name.toLowerCase().endsWith(".csv")||b.file_name.includes("/")||b.file_name.includes(String.fromCharCode(92))||Array.from(b.file_name).some(ch=>ch.charCodeAt(0)<32||ch.charCodeAt(0)===127))return {status:422,error:"Source filename must be a plain CSV filename"};
  let parsed;
  try{parsed=parseSourceFile(bytes,b.source_type);}catch(e){return {status:422,error:e.message};}
  if(!allowedImportRows(parsed.rows,b.source_type))return {status:422,error:"CSV source fields contain unsupported values"};
  if(parsed.sha256!==b.file_sha256)return {status:422,error:"Uploaded bytes do not match the declared SHA-256"};
  const prior=await c.query("SELECT sha256,byte_count,row_count,parser_version,scan_status FROM import_source_receipts WHERE tenant_id=$1 AND batch_id=$2",[tenant,batchId]);
  if(prior.rowCount){if(profile.protectedMode&&prior.rows[0].scan_status!=="scanner_reported_clean")return {status:409,error:"Legacy unscanned receipt requires controlled review"};return {status:200,receipt:prior.rows[0],sourceIntegrity:"byte_verified",idempotent:true};}
  if(b.status!=="uploaded")return {status:409,error:"Batch is not open for original-file ingestion"};
  const existing=await c.query("SELECT 1 FROM raw_import_rows WHERE tenant_id=$1 AND batch_id=$2 LIMIT 1",[tenant,batchId]);
  if(existing.rowCount)return {status:409,error:"Client-ingested rows cannot be retroactively labelled byte-verified"};
  const actor=await c.query("SELECT u.id FROM users u JOIN tenant_memberships m ON m.user_id=u.id WHERE u.auth_subject=$1 AND m.tenant_id=$2 AND m.status='active' AND m.role IN ('owner','admin','analyst')",[req.identity.subject,tenant]);
  if(!actor.rowCount)throw Object.assign(new Error("Active ingestion membership required"),{status:403});
  const userId=actor.rows[0].id;
  await c.query("INSERT INTO raw_import_rows(tenant_id,batch_id,row_number,payload) SELECT $1,$2,p.ordinality::int,p.value FROM jsonb_array_elements($3::jsonb) WITH ORDINALITY AS p(value,ordinality)",[tenant,batchId,JSON.stringify(parsed.rows)]);
  const receipt=await c.query("INSERT INTO import_source_receipts(tenant_id,batch_id,sha256,byte_count,row_count,parser_version,original_bytes,received_by,scan_status) VALUES($1,$2,$3,$4,$5,'strict-csv-0.1.0',$6,$7,$8) RETURNING sha256,byte_count,row_count,parser_version,scan_status",[tenant,batchId,parsed.sha256,byteCount,parsed.rows.length,bytes,userId,scanStatus]);
  await c.query("INSERT INTO audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata) VALUES($1,$2,'source_file_verified','import_batch',$3,'Original CSV checksum matched',$4)",[tenant,userId,batchId,JSON.stringify(receipt.rows[0])]);
  return {status:201,sourceIntegrity:"byte_verified",receipt:receipt.rows[0]};
 });
 const {status,...body}=result;res.status(status).json(body);
 }catch(e){next(e);}});

app.get("/v1/tenants/:tenantId/imports/:batchId/source",membership,async(req,res,next)=>{try{
 if(!isUuid(req.params.batchId))return res.status(400).json({error:"Invalid batch ID"});
 const r=await withTenant(req.membership.tenantId,req.identity.subject,c=>c.query("SELECT b.id,b.file_sha256,r.sha256,r.byte_count,r.row_count,r.parser_version,r.scan_status,r.received_at FROM import_batches b LEFT JOIN import_source_receipts r ON r.tenant_id=b.tenant_id AND r.batch_id=b.id WHERE b.tenant_id=$1 AND b.id=$2",[req.membership.tenantId,req.params.batchId]));
 if(!r.rowCount)return res.status(404).json({error:"Import batch not found"});
 const row=r.rows[0];
 res.json({batchId:row.id,declaredSha256:row.file_sha256,sourceIntegrity:row.sha256?"byte_verified":"client_declared",receipt:row.sha256?{sha256:row.sha256,byte_count:row.byte_count,row_count:row.row_count,parser_version:row.parser_version,scan_status:row.scan_status,received_at:row.received_at}:null,issuerAuthenticated:false});
 }catch(e){next(e);}});

app.post("/v1/tenants/:tenantId/imports/:batchId/rows",membership,requireRole("owner","admin","analyst"),async(req,res,next)=>{try{
 if(profile.protectedMode)return res.status(403).json({error:"Protected ingestion requires original-file scanning"});
 const {rows,startRow=1}=req.body||{};
 if(!isUuid(req.params.batchId)||!Array.isArray(rows)||rows.length<1||rows.length>200||rows.some(x=>!x||typeof x!=="object"||Array.isArray(x))||!Number.isSafeInteger(startRow)||startRow<1||startRow+rows.length-1>MAX_IMPORT_ROWS)return res.status(400).json({error:"Provide 1–200 row objects and a valid one-based startRow (maximum 2000 rows per batch)"});
 const result=await withTenant(req.membership.tenantId,req.identity.subject,async client=>{
  const tenant=req.membership.tenantId,batchId=req.params.batchId,payload=JSON.stringify(rows);
  // Serialise all ingestion and validation operations for the same batch.
  const batch=await client.query("SELECT id,status,source_type FROM import_batches WHERE id=$1 AND tenant_id=$2 FOR UPDATE",[batchId,tenant]);
  if(!batch.rowCount)return {status:404,error:"Import batch not found"};
  if(!allowedImportRows(rows,batch.rows[0].source_type))return {status:422,error:"Rows must contain only allowed scalar source fields; remove unnecessary personal information"};
  const verified=await client.query("SELECT 1 FROM import_source_receipts WHERE tenant_id=$1 AND batch_id=$2",[tenant,batchId]);
  if(verified.rowCount)return {status:409,error:"Byte-verified rows cannot be replaced or extended through JSON ingestion"};
  const state=await client.query("SELECT COUNT(*)::int AS n,COALESCE(MAX(row_number),0)::int AS last FROM raw_import_rows WHERE batch_id=$1 AND tenant_id=$2",[batchId,tenant]);
  const {n,last}=state.rows[0];
  if(n!==last)return {status:409,error:"Source row numbering is inconsistent; administrator review required"};
  if(startRow>last+1)return {status:409,error:"Row chunk would create a gap"};
  const overlap=await client.query("SELECT COUNT(*)::int AS n,COUNT(*) FILTER(WHERE r.payload IS DISTINCT FROM p.value)::int AS conflicts FROM jsonb_array_elements($3::jsonb) WITH ORDINALITY AS p(value,ordinality) JOIN raw_import_rows r ON r.batch_id=$1 AND r.tenant_id=$2 AND r.row_number=$4::int+p.ordinality-1",[batchId,tenant,payload,startRow]);
  if(overlap.rows[0].conflicts)return {status:409,error:"Existing row number has different source content; no rows written"};
  if(overlap.rows[0].n===rows.length)return {status:200,inserted:0,received:rows.length,duplicates:rows.length};
  if(!["uploaded","review"].includes(batch.rows[0].status))return {status:409,error:"Import batch is not open for row ingestion"};
  const reviewed=await client.query("SELECT 1 FROM mapping_decisions m JOIN raw_import_rows r ON r.id=m.raw_row_id AND r.tenant_id=m.tenant_id WHERE r.batch_id=$1 AND r.tenant_id=$2 LIMIT 1",[batchId,tenant]);
  if(reviewed.rowCount)return {status:409,error:"Validation has started; source rows are sealed"};
  const inserted=await client.query("INSERT INTO raw_import_rows(tenant_id,batch_id,row_number,payload) SELECT $2,$1,($4::int+p.ordinality-1)::int,p.value FROM jsonb_array_elements($3::jsonb) WITH ORDINALITY AS p(value,ordinality) WHERE $4::int+p.ordinality-1>$5::int",[batchId,tenant,payload,startRow,last]);
  return {status:201,inserted:inserted.rowCount,received:rows.length,duplicates:overlap.rows[0].n};
 });
 if(result.error)return res.status(result.status).json({error:result.error});
 res.status(result.status).json({batchId:req.params.batchId,inserted:result.inserted,received:result.received,duplicates:result.duplicates});
 }catch(e){next(e);}});

app.post("/v1/tenants/:tenantId/imports/:batchId/validate",membership,requireRole("owner","admin","analyst","reviewer"),async(req,res,next)=>{try{
 if(!isUuid(req.params.batchId))return res.status(400).json({error:"Invalid batch ID"});
 const result=await withTenant(req.membership.tenantId,req.identity.subject,async client=>{
  const batch=await client.query("SELECT id,status,source_type,source_period_start::text AS period_start,source_period_end::text AS period_end FROM import_batches WHERE id=$1 AND tenant_id=$2 FOR UPDATE",[req.params.batchId,req.membership.tenantId]);
  if(!batch.rowCount)return {status:404,error:"Import batch not found"};
  if(!["uploaded","review"].includes(batch.rows[0].status))return {status:409,error:"Import batch is not open for validation"};
  if(!["customer_invoice","supplier_invoice","payroll"].includes(batch.rows[0].source_type))return {status:422,error:"Unsupported source type"};
  const raw=await client.query("SELECT id,row_number,payload FROM raw_import_rows WHERE batch_id=$1 AND tenant_id=$2 ORDER BY row_number LIMIT $3",[req.params.batchId,req.membership.tenantId,MAX_IMPORT_ROWS+1]);
  if(!raw.rowCount)return {status:422,error:"No persisted import rows found. Ingest rows before validation."};
  if(raw.rowCount>MAX_IMPORT_ROWS||raw.rows.some((r,i)=>r.row_number!==i+1))return {status:409,error:"Source row numbering or batch size requires administrator review"};
  const items=raw.rows.map(r=>({...r.payload,__rowNumber:String(r.row_number)}));
  const payroll=batch.rows[0].source_type==="payroll";
  const checked=payroll?validatePayrollRows(items,{periodStart:batch.rows[0].period_start,periodEnd:batch.rows[0].period_end}):validateInvoiceRows(items);
  const records=checked.map((item,i)=>({id:raw.rows[i].id,decision:item.errors.length?"held":"candidate",reason:item.errors.join("; ")||"Structural validation passed; requires mapping and human review"}));
  const held=records.filter(r=>r.decision==="held").length;
  // A repeat validation must never overwrite a human review or its recorded reason.
  await client.query("INSERT INTO mapping_decisions(tenant_id,raw_row_id,target_type,target_id,decision,confidence,method_version,reason) SELECT $1,p.id,$3,NULL,p.decision,'LOW',$4,p.reason FROM jsonb_to_recordset($2::jsonb) AS p(id uuid,decision text,reason text) ON CONFLICT(tenant_id,raw_row_id,method_version) DO NOTHING",[req.membership.tenantId,JSON.stringify(records),payroll?"payroll_row":"invoice_row",payroll?"payroll-validator-0.1.0":"invoice-validator-0.1.0"]);
  await client.query("UPDATE import_batches SET status='review' WHERE id=$1 AND tenant_id=$2",[req.params.batchId,req.membership.tenantId]);
  const receipt=await client.query("SELECT 1 FROM import_source_receipts WHERE tenant_id=$1 AND batch_id=$2",[req.membership.tenantId,req.params.batchId]);
  return {status:200,batchId:req.params.batchId,sourceIntegrity:receipt.rowCount?"byte_verified":"client_declared",total:raw.rowCount,validCandidateRows:raw.rowCount-held,heldRows:held,automaticallyAccepted:0};
 });
 if(result.error)return res.status(result.status).json({error:result.error});
 const {status,...body}=result;res.status(status).json(body);
 }catch(e){next(e);}});



// Review-only identity registry: reservations do not confirm matches or authorise financial inclusion.
app.get("/v1/tenants/:tenantId/imports/:batchId/invoice-identities",membership,requireRole("owner","admin","analyst","reviewer"),async(req,res,next)=>{try{
 if(!isUuid(req.params.batchId))return res.status(400).json({error:"Invalid batch ID"});
 const result=await withTenant(req.membership.tenantId,req.identity.subject,async c=>{
  const args=[req.membership.tenantId,req.params.batchId];
  const b=await c.query("SELECT source_type FROM import_batches WHERE tenant_id=$1 AND id=$2",args);
  if(!b.rowCount)return {status:404,error:"Import batch not found"};
  if(!["customer_invoice","supplier_invoice"].includes(b.rows[0].source_type))return {status:422,error:"Invoice batch required"};
  const rows=await c.query(`SELECT r.id AS raw_row_id,r.row_number,CASE WHEN jsonb_typeof(r.payload->'invoice_id')='string' THEN r.payload->>'invoice_id' END AS reference,
   m.decision AS structural_decision,ic.id AS claim_id,ic.issuer_key,ic.source_integrity,
   (SELECT count(DISTINCT other.batch_id)::int FROM raw_import_rows other JOIN import_batches ob ON ob.tenant_id=other.tenant_id AND ob.id=other.batch_id
    WHERE other.tenant_id=r.tenant_id AND other.batch_id<>r.batch_id AND ob.source_type=$3
    AND jsonb_typeof(other.payload->'invoice_id')='string' AND jsonb_typeof(r.payload->'invoice_id')='string'
    AND md5(private.invoice_review_alias(other.payload->>'invoice_id'))=md5(private.invoice_review_alias(r.payload->>'invoice_id')) AND private.invoice_review_alias(other.payload->>'invoice_id')=private.invoice_review_alias(r.payload->>'invoice_id')) AS other_batch_count
   FROM raw_import_rows r LEFT JOIN mapping_decisions m ON m.tenant_id=r.tenant_id AND m.raw_row_id=r.id AND m.method_version='invoice-validator-0.1.0'
   LEFT JOIN invoice_identity_claims ic ON ic.tenant_id=r.tenant_id AND ic.raw_row_id=r.id
   WHERE r.tenant_id=$1 AND r.batch_id=$2 ORDER BY r.row_number LIMIT 2001`,[...args,b.rows[0].source_type]);
  if(rows.rowCount>MAX_IMPORT_ROWS)return {status:409,error:"Batch exceeds review limit"};
  return {status:200,items:rows.rows,issuerAuthenticated:false,financialInclusionAuthorized:false};
 });
 res.set("Cache-Control","no-store");
 const {status,...body}=result;res.status(status).json(body);
 }catch(e){next(e);}});
app.post("/v1/tenants/:tenantId/imports/:batchId/invoice-identities",membership,requireRole("owner","admin","reviewer"),async(req,res,next)=>{try{
 const {rowNumber,issuerKey,evidenceReference,reason}=req.body||{};
 if(!isUuid(req.params.batchId)||!Number.isSafeInteger(rowNumber)||rowNumber<1||rowNumber>MAX_IMPORT_ROWS||
 typeof issuerKey!=="string"||!/^[a-z0-9][a-z0-9._:-]{0,199}$/.test(issuerKey)||
 typeof evidenceReference!=="string"||evidenceReference.trim().length<3||evidenceReference.length>500||
 typeof reason!=="string"||reason.trim().length<3||reason.length>2000)return res.status(400).json({error:"Valid row, stable issuer key, evidence reference and review reason required"});
 const result=await withTenant(req.membership.tenantId,req.identity.subject,async c=>{
  const tenant=req.membership.tenantId,batchId=req.params.batchId;
  const batch=await c.query("SELECT source_type,status FROM import_batches WHERE tenant_id=$1 AND id=$2 FOR UPDATE",[tenant,batchId]);
  if(!batch.rowCount)return {status:404,error:"Import batch not found"};
  const b=batch.rows[0];
  if(!["customer_invoice","supplier_invoice"].includes(b.source_type)||b.status!=="review")return {status:422,error:"Reviewed invoice batch required"};
  const row=await c.query("SELECT r.id,btrim(r.payload->>'invoice_id') AS ref,m.decision,CASE WHEN s.id IS NULL THEN 'client_declared' ELSE 'byte_verified' END AS integrity FROM raw_import_rows r JOIN mapping_decisions m ON m.tenant_id=r.tenant_id AND m.raw_row_id=r.id AND m.method_version='invoice-validator-0.1.0' LEFT JOIN import_source_receipts s ON s.tenant_id=r.tenant_id AND s.batch_id=r.batch_id WHERE r.tenant_id=$1 AND r.batch_id=$2 AND r.row_number=$3 AND jsonb_typeof(r.payload->'invoice_id')='string'",[tenant,batchId,rowNumber]);
  if(!row.rowCount||row.rows[0].decision!=="candidate"||!row.rows[0].ref||row.rows[0].ref.length>200)return {status:422,error:"Structurally valid invoice candidate required"};
  const r=row.rows[0],actor=await c.query("SELECT private.payroll_reviewer_id() AS id");
  if(!actor.rows[0].id)return {status:403,error:"Reviewer membership required"};
  const args=[tenant,r.id,b.source_type==="customer_invoice"?"customer":"supplier",issuerKey,r.ref,r.integrity,actor.rows[0].id,evidenceReference.trim(),reason.trim()];
  const inserted=await c.query("INSERT INTO invoice_identity_claims(tenant_id,raw_row_id,direction,issuer_key,invoice_reference,source_integrity,reviewer_id,evidence_reference,reason) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING RETURNING id,source_integrity",[...args]);
  if(!inserted.rowCount){
   const prior=await c.query("SELECT id,source_integrity FROM invoice_identity_claims WHERE tenant_id=$1 AND raw_row_id=$2 AND direction=$3 AND issuer_key=$4 AND invoice_reference=$5 AND source_integrity=$6 AND reviewer_id=$7 AND evidence_reference=$8 AND reason=$9",args);
   if(prior.rowCount)return {status:200,claim:prior.rows[0],idempotent:true,issuerAuthenticated:false,financialInclusionAuthorized:false};
   return {status:409,error:"Invoice identity or potential alias already reserved; review conflicting source evidence"};
  }
  const claim=inserted.rows[0];
  await c.query("INSERT INTO audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata) VALUES($1,$2,'invoice_identity_reserved','invoice_identity_claim',$3,$4,$5)",[tenant,args[6],claim.id,args[8],JSON.stringify({rawRowId:r.id,sourceIntegrity:r.integrity,issuerAuthenticated:false})]);
  return {status:201,claim,issuerAuthenticated:false,financialInclusionAuthorized:false};
 });
 res.set("Cache-Control","no-store");
 const {status,...body}=result;res.status(status).json(body);
 }catch(e){if(e.code==="23514")return res.status(422).json({error:"Invoice source integrity or review state does not support reservation"});next(e);}});

app.post("/v1/tenants/:tenantId/imports/:batchId/reconcile-payroll",membership,requireRole("owner","admin","reviewer"),async(req,res,next)=>{try{
 if(!isUuid(req.params.batchId))return res.status(400).json({error:"Invalid batch ID"});
 const {controlTotal,currency,controlReference,reason,assignments=[]}=req.body||{};
 if(!Array.isArray(assignments)||assignments.length>MAX_IMPORT_ROWS||typeof controlReference!=="string"||!controlReference.trim()||controlReference.length>200||typeof reason!=="string"||reason.trim().length<3||reason.length>2000)return res.status(400).json({error:"Control reference, reviewer reason and bounded allocation plan required"});
 const result=await withTenant(req.membership.tenantId,req.identity.subject,async c=>{
  const tenant=req.membership.tenantId,batchId=req.params.batchId;
  const batch=await c.query("SELECT status,source_type,source_period_start::text AS period_start,source_period_end::text AS period_end FROM import_batches WHERE id=$1 AND tenant_id=$2 FOR UPDATE",[batchId,tenant]);
  if(!batch.rowCount)return {status:404,error:"Import batch not found"};
  const b=batch.rows[0];
  if(b.source_type!=="payroll"||b.status!=="review")return {status:409,error:"Only validated payroll awaiting review can be reconciled"};
  const existing=await c.query("SELECT id FROM payroll_pools WHERE tenant_id=$1 AND batch_id=$2 LIMIT 1",[tenant,batchId]);
  if(existing.rowCount)return {status:409,error:"A payroll pool already exists for this batch"};
  const rows=await c.query("SELECT r.id,r.row_number,r.payload,m.decision FROM raw_import_rows r LEFT JOIN mapping_decisions m ON m.tenant_id=r.tenant_id AND m.raw_row_id=r.id AND m.method_version='payroll-validator-0.1.0' WHERE r.tenant_id=$1 AND r.batch_id=$2 ORDER BY r.row_number LIMIT $3",[tenant,batchId,MAX_IMPORT_ROWS+1]);
  if(!rows.rowCount||rows.rowCount>MAX_IMPORT_ROWS||rows.rows.some((r,i)=>r.row_number!==i+1||r.decision!=="candidate"))return {status:422,error:"All source rows must be validated candidates"};
  let plan;
  try{plan=reconcilePayroll(validatePayrollRows(rows.rows.map(r=>r.payload),{periodStart:b.period_start,periodEnd:b.period_end}),assignments,controlTotal,currency);}
  catch(e){return {status:422,error:e.message};}
  const sites=[...new Set(plan.lines.filter(l=>l.siteId).map(l=>l.siteId))];
  if(sites.some(id=>!isUuid(id)))return {status:400,error:"Invalid site ID"};
  if(sites.length){
   const allowed=await c.query("SELECT id FROM sites WHERE tenant_id=$1 AND id=ANY($2::uuid[]) AND status='active'",[tenant,sites]);
   if(allowed.rowCount!==sites.length)return {status:422,error:"Allocation site is unavailable in this tenant"};
  }
  const actor=await c.query("SELECT u.id FROM users u JOIN tenant_memberships m ON m.user_id=u.id WHERE u.auth_subject=$1 AND m.tenant_id=$2 AND m.status='active' AND m.role IN ('owner','admin','reviewer')",[req.identity.subject,tenant]);
  if(!actor.rowCount)throw Object.assign(new Error("Active reviewer membership required"),{status:403});
  const userId=actor.rows[0].id,k=plan.buckets;
  const source=await c.query("SELECT 1 FROM import_source_receipts WHERE tenant_id=$1 AND batch_id=$2",[tenant,batchId]);
  const sourceIntegrity=source.rowCount?"byte_verified":"client_declared";
  const pool=await c.query("INSERT INTO payroll_pools(tenant_id,batch_id,period_start,period_end,total_amount,currency,source_ref) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id",[tenant,batchId,b.period_start,b.period_end,plan.total,currency,"reconciled:"+controlReference.trim()]);
  const poolId=pool.rows[0].id;
  const run=await c.query("INSERT INTO allocation_runs(tenant_id,payroll_pool_id,method_version,status,direct_amount,allocated_amount,non_site_amount,excluded_amount,residual_amount,reviewer_id) VALUES($1,$2,'payroll-source-row-0.2.0','draft',$3,$4,$5,$6,$7,$8) RETURNING id",[tenant,poolId,k.direct,k.approved_allocated,k.non_site,k.excluded,k.unallocated,userId]);
  const runId=run.rows[0].id;
  const entries=plan.lines.map(l=>({...l,rawRowId:rows.rows[l.rowNumber-1].id}));
  const sourceRows=rows.rows.map(r=>({raw_row_id:r.id,source_ref:r.payload.source_ref,amount:r.payload.amount}));
  const sourceRecords=await c.query("INSERT INTO payroll_source_records(tenant_id,raw_row_id,payroll_pool_id,source_ref,amount) SELECT $1,x.raw_row_id,$2,x.source_ref,x.amount FROM jsonb_to_recordset($3::jsonb) AS x(raw_row_id uuid,source_ref text,amount numeric) RETURNING id,raw_row_id",[tenant,poolId,JSON.stringify(sourceRows)]);
  const sourceIds=new Map(sourceRecords.rows.map(r=>[r.raw_row_id,r.id]));
  await c.query("INSERT INTO allocation_lines(tenant_id,allocation_run_id,site_id,bucket_type,amount,source_ref,source_record_id) SELECT $1,$2,x.site_id,x.bucket,x.amount,x.source_ref,x.source_record_id FROM jsonb_to_recordset($3::jsonb) AS x(site_id uuid,bucket text,amount numeric,source_ref text,source_record_id uuid)",[tenant,runId,JSON.stringify(entries.map(e=>({site_id:e.siteId,bucket:e.bucket,amount:e.amount,source_ref:e.sourceRef,source_record_id:sourceIds.get(e.rawRowId)})))]);
  const confirmed=await c.query("UPDATE allocation_runs SET status='confirmed' WHERE tenant_id=$1 AND id=$2 AND status='draft' RETURNING id",[tenant,runId]);
  if(confirmed.rowCount!==1)throw new Error("Payroll confirmation failed");
  await c.query("INSERT INTO audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata) VALUES($1,$2,'payroll_reconciled','allocation_run',$3,$4,$5)",[tenant,userId,runId,reason.trim(),JSON.stringify({batchId,poolId,controlReference:controlReference.trim(),sourceIntegrity,currency,total:plan.total,buckets:k,assignments:entries.map(e=>({rowNumber:e.rowNumber,bucket:e.bucket,siteId:e.siteId,amount:e.amount,reason:e.reason}))})]);
  await c.query("UPDATE import_batches SET status='accepted' WHERE tenant_id=$1 AND id=$2",[tenant,batchId]);
  return {status:201,poolId,runId,total:plan.total,currency,sourceIntegrity,buckets:k,sourceRows:rows.rowCount,allocationLines:entries.length};
 });
 const {status,...body}=result;res.status(status).json(body);
 }catch(e){next(e);}});

app.post("/v1/tenants/:tenantId/matches/:matchId/decision",membership,requireRole("owner","admin","reviewer"),async(req,res,next)=>{try{
 const {decision,reason}=req.body||{};
 if(!isUuid(req.params.matchId))return res.status(400).json({error:"Invalid match ID"});
 if(!["confirmed","rejected","held"].includes(decision)||typeof reason!=="string"||reason.trim().length<3||reason.length>2000)return res.status(400).json({error:"Decision and reason are required"});
 const result=await withTenant(req.membership.tenantId,req.identity.subject,async client=>{
  const user=await client.query("SELECT id FROM users WHERE auth_subject=$1",[req.identity.subject]);
  if(!user.rowCount)throw Object.assign(new Error("User identity is not provisioned in this tenant database"),{status:403});
  const updated=await client.query("UPDATE match_reviews SET decision=$1,reviewer_id=$2,reviewed_at=now() WHERE id=$3 AND tenant_id=$4 AND decision IN ('candidate','held') RETURNING id,decision,reviewed_at",[decision,user.rows[0].id,req.params.matchId,req.membership.tenantId]);
  if(!updated.rowCount)return null;
  await client.query("INSERT INTO audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata) VALUES($1,$2,'invoice_match_decision','match_review',$3,$4,$5)",[req.membership.tenantId,user.rows[0].id,req.params.matchId,reason.trim(),JSON.stringify({decision})]);
  return updated.rows[0];
 });
 if(!result)return res.status(404).json({error:"Review candidate not found or already finalised"});
 res.status(201).json({decision:result});
 }catch(e){next(e);}});


const rehearsalColumns="id,claim_id,contract_id,site_id,contract_version_no,reviewer_id,service_start::text,service_end::text,currency,tax_basis,cost_kind,direction,issuer_key,invoice_reference,source_integrity,raw_row_id,source_sha256,invoice_date::text,amount::text";
app.post("/v1/tenants/:tenantId/prototype/invoice-confirmations",membership,requireRole("owner","admin","reviewer"),async(req,res,next)=>{try{
 const body=req.body||{}, {synthetic,claimId,contractId,siteId,serviceStart,serviceEnd,currency,taxBasis,costKind,evidenceReference}=body;
 if(profile.mode!=="prototype")return res.status(403).json({error:"Synthetic rehearsal unavailable in protected profile"});
 if(synthetic!==true||Object.keys(body).some(k=>!["synthetic","claimId","contractId","siteId","serviceStart","serviceEnd","currency","taxBasis","costKind","evidenceReference"].includes(k))||![claimId,contractId,siteId].every(isUuid)||!isIsoDate(serviceStart)||!isIsoDate(serviceEnd)||serviceStart>serviceEnd||currency!=="AUD"||!["gst_inclusive","gst_exclusive","no_gst"].includes(taxBasis)||!["revenue","supplier","subcontractor"].includes(costKind)||typeof evidenceReference!=="string"||!/^[A-Za-z0-9][A-Za-z0-9._:-]{2,119}$/.test(evidenceReference))return res.status(400).json({error:"Explicit synthetic confirmation and reviewed scope, AUD, tax basis and evidence reference required"});
 const result=await withTenant(req.membership.tenantId,req.identity.subject,async c=>{
  const tenant=req.membership.tenantId;
  const allowed=await c.query("SELECT id FROM tenants WHERE id=$1 AND invoice_rehearsal_enabled",[tenant]);
  if(!allowed.rowCount)return {status:403,error:"Synthetic rehearsal tenant not provisioned"};
  const args=[tenant,claimId,contractId,siteId,serviceStart,serviceEnd,currency,taxBasis,costKind,evidenceReference];
  const inserted=await c.query("INSERT INTO invoice_confirmation_rehearsals(tenant_id,claim_id,contract_id,site_id,reviewer_id,service_start,service_end,currency,tax_basis,cost_kind,evidence_reference) VALUES($1,$2,$3,$4,private.payroll_reviewer_id(),$5,$6,$7,$8,$9,$10) ON CONFLICT DO NOTHING RETURNING "+rehearsalColumns,args);
  if(inserted.rowCount)return {status:201,item:inserted.rows[0]};
  const replay=await c.query("SELECT "+rehearsalColumns+" FROM invoice_confirmation_rehearsals WHERE tenant_id=$1 AND claim_id=$2 AND contract_id=$3 AND site_id=$4 AND reviewer_id=private.payroll_reviewer_id() AND service_start=$5 AND service_end=$6 AND currency=$7 AND tax_basis=$8 AND cost_kind=$9 AND evidence_reference=$10",args);
  return replay.rowCount?{status:200,item:replay.rows[0]}:{status:409,error:"Confirmation conflicts with an existing rehearsal"};
 });
 const {status,...out}=result;res.status(status).json({...out,synthetic:true,issuerAuthenticated:false,financialInclusionAuthorized:false});
}catch(e){if(["23514","22007","22008","22003","23503"].includes(e.code))return res.status(422).json({error:"Rehearsal source, identity or contract evidence invalid"});next(e);}});
app.post("/v1/tenants/:tenantId/prototype/invoice-cost-bridge",membership,requireRole("owner","admin","analyst","reviewer"),async(req,res,next)=>{try{
 const body=req.body||{}, {synthetic,contractId,siteId,periodStart,periodEnd}=body;
 if(profile.mode!=="prototype")return res.status(403).json({error:"Synthetic rehearsal unavailable in protected profile"});
 if(synthetic!==true||Object.keys(body).some(k=>!["synthetic","contractId","siteId","periodStart","periodEnd"].includes(k))||!isUuid(contractId)||!isUuid(siteId)||!isIsoDate(periodStart)||!isIsoDate(periodEnd)||periodStart>periodEnd)return res.status(400).json({error:"Explicit synthetic scope and valid dates required"});
 const result=await withTenant(req.membership.tenantId,req.identity.subject,async c=>{
  const tenant=req.membership.tenantId;
  const allowed=await c.query("SELECT id FROM tenants WHERE id=$1 AND invoice_rehearsal_enabled",[tenant]);
  if(!allowed.rowCount)return {status:403,error:"Synthetic rehearsal tenant not provisioned"};
  const rows=await c.query("SELECT "+rehearsalColumns+" FROM invoice_confirmation_rehearsals WHERE tenant_id=$1 AND contract_id=$2 AND site_id=$3 AND service_start<=$5::date AND service_end>=$4::date ORDER BY id LIMIT $6",[tenant,contractId,siteId,periodStart,periodEnd,MAX_EVIDENCE_LINES+1]);
  if(rows.rows.some(r=>r.service_start<periodStart||r.service_end>periodEnd)||new Set(rows.rows.map(r=>r.contract_version_no)).size!==1)return {status:422,error:"Rehearsal period or contract version ambiguous"};
  let bridge;try{bridge=invoiceCostBridge(rows.rows);}catch(e){if(e instanceof RangeError)return {status:422,error:e.message};throw e;}
  const snapshot={contractId,siteId,periodStart,periodEnd,rows:rows.rows,method:"synthetic-invoice-bridge-0.1.0"};
  return {status:200,bridge,evidenceSha256:snapshotDigest(snapshot),evidence:snapshot};
 },{repeatableRead:true});
 const {status,...out}=result;res.status(status).json({...out,synthetic:true,issuerAuthenticated:false,financialInclusionAuthorized:false});
}catch(e){next(e);}});


const payrollRehearsalColumns="id,allocation_line_id,contract_id,contract_version_no,site_id,reviewer_id,evidence_reference,allocation_run_id,payroll_pool_id,source_record_id,raw_row_id,batch_id,source_sha256,service_start::text,service_end::text,currency,bucket_type,amount::text";
app.post("/v1/tenants/:tenantId/prototype/payroll-attributions",membership,requireRole("owner","admin","reviewer"),async(req,res,next)=>{try{
 const body=req.body||{}, {synthetic,allocationLineId,contractId,evidenceReference}=body;
 if(profile.mode!=="prototype")return res.status(403).json({error:"Synthetic rehearsal unavailable in protected profile"});
 if(synthetic!==true||Object.keys(body).some(k=>!["synthetic","allocationLineId","contractId","evidenceReference"].includes(k))||!isUuid(allocationLineId)||!isUuid(contractId)||typeof evidenceReference!=="string"||!/^[A-Za-z0-9][A-Za-z0-9._:-]{2,119}$/.test(evidenceReference))return res.status(400).json({error:"Explicit synthetic whole-line attribution and evidence reference required"});
 const result=await withTenant(req.membership.tenantId,req.identity.subject,async c=>{
  const tenant=req.membership.tenantId;
  const enabled=await c.query("SELECT id FROM tenants WHERE id=$1 AND invoice_rehearsal_enabled",[tenant]);
  if(!enabled.rowCount)return {status:403,error:"Synthetic rehearsal tenant not provisioned"};
  const args=[tenant,allocationLineId,contractId,evidenceReference];
  const inserted=await c.query("INSERT INTO payroll_contract_rehearsals(tenant_id,allocation_line_id,contract_id,reviewer_id,evidence_reference) VALUES($1,$2,$3,private.payroll_reviewer_id(),$4) ON CONFLICT DO NOTHING RETURNING "+payrollRehearsalColumns,args);
  if(inserted.rowCount)return {status:201,item:inserted.rows[0]};
  const prior=await c.query("SELECT "+payrollRehearsalColumns+" FROM payroll_contract_rehearsals WHERE tenant_id=$1 AND allocation_line_id=$2 AND contract_id=$3 AND evidence_reference=$4 AND reviewer_id=private.payroll_reviewer_id()",args);
  return prior.rowCount?{status:200,item:prior.rows[0]}:{status:409,error:"Allocation line already attributed in another rehearsal"};
 });
 const {status,...out}=result;res.status(status).json({...out,synthetic:true,financialInclusionAuthorized:false});
}catch(e){if(["23514","23503"].includes(e.code))return res.status(422).json({error:"Confirmed source-linked payroll and approved contract/site required"});next(e);}});
async function computeUnifiedSnapshot(c,tenant,contractId,siteId,periodStart,periodEnd){
  const args=[tenant,contractId,siteId,periodStart,periodEnd];
  const enabled=await c.query("SELECT id FROM tenants WHERE id=$1 AND invoice_rehearsal_enabled",[tenant]);
  if(!enabled.rowCount)return {status:403,error:"Synthetic rehearsal tenant not provisioned"};
  const versions=await c.query("SELECT cv.id,cv.version_no,cv.currency,cv.effective_from::text AS effective_from,cv.effective_to::text AS effective_to,cv.price::text AS price,cv.billing_basis,cv.approved_by FROM contract_versions cv JOIN contracts ct ON ct.tenant_id=cv.tenant_id AND ct.id=cv.contract_id JOIN sites s ON s.tenant_id=ct.tenant_id AND s.business_id=ct.business_id AND s.id=$3 WHERE cv.tenant_id=$1 AND cv.contract_id=$2 AND ct.status='active' AND s.status='active' AND cv.approved_at IS NOT NULL AND cv.approved_by IS NOT NULL AND cv.effective_from<=$5::date AND (cv.effective_to IS NULL OR cv.effective_to>=$4::date) LIMIT 2",args);
  const v=versions.rows[0];if(versions.rowCount!==1||v.currency!=="AUD"||v.effective_from>periodStart||(v.effective_to!==null&&v.effective_to<periodEnd))return {status:422,error:"Unique approved covering AUD contract version required"};
  const invoices=await c.query("SELECT "+rehearsalColumns+" FROM invoice_confirmation_rehearsals WHERE tenant_id=$1 AND contract_id=$2 AND site_id=$3 AND service_start<=$5::date AND service_end>=$4::date ORDER BY id LIMIT $6",[...args,MAX_EVIDENCE_LINES+1]);
  const payroll=await c.query("SELECT "+payrollRehearsalColumns+" FROM payroll_contract_rehearsals WHERE tenant_id=$1 AND contract_id=$2 AND site_id=$3 AND service_start<=$5::date AND service_end>=$4::date ORDER BY id LIMIT $6",[...args,MAX_EVIDENCE_LINES+1]);
  if([...invoices.rows,...payroll.rows].some(r=>r.service_start<periodStart||r.service_end>periodEnd||r.contract_version_no!==v.version_no))return {status:422,error:"Evidence crosses requested period or contract version"};
  // Unknown contract allocation is not a zero cost. Hold all overlapping unattributed v2 site lines.
  const unmatched=await c.query("SELECT al.id FROM allocation_lines al JOIN allocation_runs ar ON ar.tenant_id=al.tenant_id AND ar.id=al.allocation_run_id JOIN payroll_pools pp ON pp.tenant_id=ar.tenant_id AND pp.id=ar.payroll_pool_id LEFT JOIN payroll_contract_rehearsals pr ON pr.tenant_id=al.tenant_id AND pr.allocation_line_id=al.id WHERE al.tenant_id=$1 AND al.site_id=$2 AND al.bucket_type IN ('direct','approved_allocated') AND ar.status='confirmed' AND ar.method_version='payroll-source-row-0.2.0' AND pp.period_start<=$4::date AND pp.period_end>=$3::date AND pr.id IS NULL LIMIT 1",[tenant,siteId,periodStart,periodEnd]);
  if(unmatched.rowCount)return {status:422,error:"Unattributed confirmed site payroll remains; review contract attribution first"};
  const legacy=await c.query("SELECT al.id,al.amount::text AS amount,pp.currency,pp.period_start::text AS period_start,pp.period_end::text AS period_end FROM allocation_lines al JOIN allocation_runs ar ON ar.tenant_id=al.tenant_id AND ar.id=al.allocation_run_id JOIN payroll_pools pp ON pp.tenant_id=ar.tenant_id AND pp.id=ar.payroll_pool_id WHERE al.tenant_id=$1 AND al.site_id=$2 AND al.bucket_type IN ('direct','approved_allocated') AND ar.status='confirmed' AND ar.method_version<>'payroll-source-row-0.2.0' AND pp.period_start<=$4::date AND pp.period_end>=$3::date ORDER BY al.id LIMIT $5",[tenant,siteId,periodStart,periodEnd,MAX_EVIDENCE_LINES+1]);
  if(legacy.rowCount>MAX_EVIDENCE_LINES)return {status:422,error:"Legacy evidence exceeds review limit"};
  let contribution;try{contribution=unifiedRehearsalContribution(invoices.rows,payroll.rows);}catch(e){if(e instanceof RangeError)return {status:422,error:e.message};throw e;}
  const evidence={method:"unified-rehearsal-0.1.0",tenantId:tenant,contractId,siteId,periodStart,periodEnd,contractVersion:v,invoiceLines:invoices.rows,payrollLines:payroll.rows,excludedLegacyPayroll:legacy.rows,limitations:["Incomplete synthetic contribution, not audited profit.","No automatic invoice or payroll promotion. No shared allocation line splitting or cross-period proration.","Legacy payroll and non-site, excluded or unallocated amounts are not included. Other contract attributions are excluded.","Invoice tax basis is reviewer-attested; actual GST treatment and source authenticity remain unverified.","No evidence of complete supplier coverage or absence of economic overlap between invoice and payroll sources."]};
  return {status:200,contribution,evidence,evidenceSha256:snapshotDigest(evidence)};
}
app.post("/v1/tenants/:tenantId/prototype/unified-contribution",membership,requireRole("owner","admin","analyst","reviewer"),async(req,res,next)=>{try{
 const body=req.body||{},{synthetic,contractId,siteId,periodStart,periodEnd}=body;
 if(profile.mode!=="prototype")return res.status(403).json({error:"Synthetic rehearsal unavailable in protected profile"});
 if(synthetic!==true||Object.keys(body).some(k=>!["synthetic","contractId","siteId","periodStart","periodEnd"].includes(k))||![contractId,siteId].every(isUuid)||!isIsoDate(periodStart)||!isIsoDate(periodEnd)||periodStart>periodEnd)return res.status(400).json({error:"Explicit synthetic scope and valid dates required"});
 const result=await withTenant(req.membership.tenantId,req.identity.subject,c=>computeUnifiedSnapshot(c,req.membership.tenantId,contractId,siteId,periodStart,periodEnd),{repeatableRead:true});
 const {status,...out}=result;res.status(status).json({...out,synthetic:true,financialInclusionAuthorized:false,issuerAuthenticated:false,persisted:false});
}catch(e){next(e);}});

// F5: immutable synthetic unified report, derived and written within one
// repeatable-read tenant transaction. The API accepts no client amounts or hashes.
const unifiedReportColumns="id,client_request_id,contract_id,site_id,period_start::text,period_end::text,created_by,evidence_sha256,contribution,evidence,created_at";
app.post("/v1/tenants/:tenantId/prototype/unified-reports",membership,requireRole("owner","admin","reviewer"),async(req,res,next)=>{try{
 const body=req.body||{},{synthetic,clientRequestId,contractId,siteId,periodStart,periodEnd}=body;
 if(profile.mode!=="prototype")return res.status(403).json({error:"Synthetic reporting disabled in protected profile"});
 if(synthetic!==true||Object.keys(body).some(k=>!["synthetic","clientRequestId","contractId","siteId","periodStart","periodEnd"].includes(k))
 ||![clientRequestId,contractId,siteId].every(isUuid)||!isIsoDate(periodStart)||!isIsoDate(periodEnd)||periodStart>periodEnd)
 return res.status(400).json({error:"Valid synthetic request ID and financial scope required"});
 const result=await withTenant(req.membership.tenantId,req.identity.subject,async c=>{
  const tenant=req.membership.tenantId;
  const proposed=await computeUnifiedSnapshot(c,tenant,contractId,siteId,periodStart,periodEnd);
  if(proposed.status!==200)return {status:proposed.status,error:proposed.error};
  const {contribution,evidence,evidenceSha256}=proposed;
  const args=[tenant,clientRequestId,contractId,siteId,periodStart,periodEnd,JSON.stringify(contribution),JSON.stringify(evidence),evidenceSha256];
  const inserted=await c.query("INSERT INTO unified_report_snapshots(tenant_id,client_request_id,contract_id,site_id,period_start,period_end,created_by,contribution,evidence,evidence_sha256) VALUES($1,$2,$3,$4,$5,$6,private.actor_id(),$7::jsonb,$8::jsonb,$9) ON CONFLICT DO NOTHING RETURNING "+unifiedReportColumns,args);
  if(inserted.rowCount)return {status:201,item:inserted.rows[0]};
  const replay=await c.query("SELECT "+unifiedReportColumns+" FROM unified_report_snapshots WHERE tenant_id=$1 AND client_request_id=$2 AND contract_id=$3 AND site_id=$4 AND period_start=$5 AND period_end=$6 AND created_by=private.actor_id() AND evidence_sha256=$7",[tenant,clientRequestId,contractId,siteId,periodStart,periodEnd,evidenceSha256]);
  return replay.rowCount?{status:200,item:replay.rows[0]}:{status:409,error:"A different request or evidence snapshot already exists"};
 },{repeatableRead:true});
 const {status,...out}=result;
 res.status(status).json({...out,synthetic:true,completeness:"incomplete",issuerAuthenticated:false,financialInclusionAuthorized:false,externalVerification:false});
}catch(e){if(["23514","23503","22P02","22003"].includes(e.code))return res.status(422).json({error:"Invalid source-linked synthetic report"});next(e);}});
app.get("/v1/tenants/:tenantId/prototype/unified-reports/:reportId",membership,requireRole("owner","admin","analyst","reviewer"),async(req,res,next)=>{try{
 if(!isUuid(req.params.reportId))return res.status(400).json({error:"Invalid unified report ID"});
 const data=await withTenant(req.membership.tenantId,req.identity.subject,c=>c.query("SELECT "+unifiedReportColumns+" FROM unified_report_snapshots WHERE tenant_id=$1 AND id=$2",[req.membership.tenantId,req.params.reportId]));
 if(!data.rowCount)return res.status(404).json({error:"Unified report not found"});
 const item=data.rows[0];
 if(snapshotDigest(item.evidence)!==item.evidence_sha256)return res.status(409).json({error:"Stored financial evidence integrity mismatch"});
 res.json({item,synthetic:true,completeness:"incomplete",issuerAuthenticated:false,financialInclusionAuthorized:false,externalVerification:false});
}catch(e){next(e);}});

// F4: durable, review-controlled link between existing immutable calculations.
// No financial source values are accepted from the HTTP caller.
const restatementColumns="id,prior_run_id,next_run_id,reviewed_by,reason_code,evidence_reference,prior_evidence_sha256,next_evidence_sha256,created_at";
app.post("/v1/tenants/:tenantId/prototype/calculation-restatements",membership,requireRole("owner","admin","reviewer"),async(req,res,next)=>{try{
 const body=req.body||{},{synthetic,priorRunId,nextRunId,reasonCode,evidenceReference}=body;
 if(profile.mode!=="prototype")return res.status(403).json({error:"Protected profile cannot activate synthetic restatements"});
 if(synthetic!==true||Object.keys(body).some(k=>!["synthetic","priorRunId","nextRunId","reasonCode","evidenceReference"].includes(k))
 ||!isUuid(priorRunId)||!isUuid(nextRunId)||priorRunId===nextRunId
 ||typeof reasonCode!=="string"||!/^[A-Za-z0-9][A-Za-z0-9._:-]{2,119}$/.test(reasonCode)
 ||typeof evidenceReference!=="string"||!/^[A-Za-z0-9][A-Za-z0-9._:-]{2,119}$/.test(evidenceReference))
 return res.status(400).json({error:"Reviewed synthetic restatement identifiers and evidence references required"});
 const result=await withTenant(req.membership.tenantId,req.identity.subject,async c=>{
  const tenant=req.membership.tenantId;
  const active=await c.query("SELECT id FROM tenants WHERE id=$1 AND invoice_rehearsal_enabled",[tenant]);
  if(!active.rowCount)return {status:403,error:"Synthetic reporting tenant not provisioned"};
  const insert=await c.query("INSERT INTO calculation_restatements(tenant_id,prior_run_id,next_run_id,reviewed_by,reason_code,evidence_reference) VALUES($1,$2,$3,private.actor_id(),$4,$5) ON CONFLICT DO NOTHING RETURNING "+restatementColumns,[tenant,priorRunId,nextRunId,reasonCode,evidenceReference]);
  if(insert.rowCount)return {status:201,item:insert.rows[0]};
  const old=await c.query("SELECT "+restatementColumns+" FROM calculation_restatements WHERE tenant_id=$1 AND next_run_id=$2 AND prior_run_id=$3 AND reviewed_by=private.actor_id() AND reason_code=$4 AND evidence_reference=$5",[tenant,nextRunId,priorRunId,reasonCode,evidenceReference]);
  return old.rowCount?{status:200,item:old.rows[0]}:{status:409,error:"A calculation is already linked by an incompatible restatement"};
 });
 const {status,...payload}=result;
 res.status(status).json({...payload,synthetic:true,financialInclusionAuthorized:false,externalVerification:false});
}catch(e){
 if(["23514","23503"].includes(e.code))return res.status(422).json({error:"Calculation restatement scope, evidence or independent review invalid"});
 if(e.code==="23505"||e.code==="40001")return res.status(409).json({error:"Restatement conflict; refresh immutable calculation history"});
 next(e);
}});
app.get("/v1/tenants/:tenantId/prototype/calculation-restatements/:restatementId",membership,requireRole("owner","admin","analyst","reviewer"),async(req,res,next)=>{try{
 if(!isUuid(req.params.restatementId))return res.status(400).json({error:"Invalid restatement identifier"});
 const result=await withTenant(req.membership.tenantId,req.identity.subject,c=>c.query(
 "SELECT "+restatementColumns+" FROM calculation_restatements WHERE tenant_id=$1 AND id=$2",[req.membership.tenantId,req.params.restatementId]));
 if(!result.rowCount)return res.status(404).json({error:"Restatement unavailable"});
 res.json({item:result.rows[0],synthetic:true,financialInclusionAuthorized:false,externalVerification:false});
}catch(e){next(e);}});

app.post("/v1/tenants/:tenantId/calculations",membership,requireRole("owner","admin","analyst","reviewer"),async(req,res,next)=>{try{
 const {contractId,siteId,periodStart,periodEnd}=req.body||{};
 if(!isUuid(contractId)||!isUuid(siteId)||!isIsoDate(periodStart)||!isIsoDate(periodEnd)||periodEnd<periodStart)return res.status(400).json({error:"Valid contract, site and period are required"});
 const result=await withTenant(req.membership.tenantId,req.identity.subject,async client=>{
  const base=await client.query("SELECT c.id,cv.id AS version_id,cv.version_no,cv.currency,cv.effective_from::text AS effective_from,cv.effective_to::text AS effective_to,cv.price::text AS price,cv.billing_basis,cv.approved_by,(cv.effective_from <= $4::date AND (cv.effective_to IS NULL OR cv.effective_to >= $5::date)) AS covers_period FROM contracts c JOIN contract_versions cv ON cv.contract_id=c.id AND cv.tenant_id=c.tenant_id JOIN sites s ON s.id=$2 AND s.tenant_id=c.tenant_id AND s.business_id=c.business_id WHERE c.id=$1 AND c.tenant_id=$3 AND cv.approved_at IS NOT NULL AND cv.approved_by IS NOT NULL AND cv.effective_from <= $5::date AND (cv.effective_to IS NULL OR cv.effective_to >= $4::date)",[contractId,siteId,req.membership.tenantId,periodStart,periodEnd]);
  if(!base.rowCount)return {error:"No matching contract/site and effective contract version for this period"};
  if(base.rowCount!==1)return {error:"Overlapping contract versions make this period ambiguous. Correct the contract baseline before calculating."};
  if(!base.rows[0].covers_period)return {error:"The approved contract version does not cover the entire requested period"};
  // Fail closed on ambiguous duplicate confirmations; never sum the same invoice line twice.
  const duplicates=await client.query("SELECT mr.invoice_line_id FROM match_reviews mr JOIN invoice_lines il ON il.id=mr.invoice_line_id AND il.tenant_id=mr.tenant_id JOIN invoices i ON i.id=il.invoice_id AND i.tenant_id=il.tenant_id WHERE mr.tenant_id=$1 AND mr.decision='confirmed' AND i.direction='customer' AND i.invoice_date BETWEEN $4::date AND $5::date GROUP BY mr.invoice_line_id HAVING COUNT(*)>1 AND BOOL_OR(mr.contract_id=$2 AND mr.site_id=$3) LIMIT 1",[req.membership.tenantId,contractId,siteId,periodStart,periodEnd]);
  if(duplicates.rowCount)return {error:"Multiple confirmed matches for an invoice line; resolve conflicting review decisions before calculating"};
  const revenue=await client.query(
   "SELECT mr.id AS match_id,il.id AS invoice_line_id,i.id AS invoice_id,il.source_row_id,il.amount::text AS amount,i.currency,i.tax_basis,i.invoice_date::text AS invoice_date,mr.service_period_start::text AS service_period_start,mr.service_period_end::text AS service_period_end,mr.reviewer_id,mr.confidence,(i.invoice_date BETWEEN $4::date AND $5::date AND mr.service_period_start >= $4::date AND mr.service_period_end <= $5::date AND mr.service_period_start <= mr.service_period_end) AS aligned,rr.batch_id,receipt.sha256 AS source_sha256 FROM match_reviews mr JOIN invoice_lines il ON il.id=mr.invoice_line_id AND il.tenant_id=mr.tenant_id JOIN invoices i ON i.id=il.invoice_id AND i.tenant_id=il.tenant_id LEFT JOIN raw_import_rows rr ON rr.tenant_id=il.tenant_id AND rr.id=il.source_row_id LEFT JOIN import_source_receipts receipt ON receipt.tenant_id=rr.tenant_id AND receipt.batch_id=rr.batch_id WHERE mr.tenant_id=$1 AND mr.contract_id=$2 AND mr.site_id=$3 AND mr.decision='confirmed' AND i.direction='customer' AND (i.invoice_date BETWEEN $4::date AND $5::date OR (mr.service_period_start <= $5::date AND mr.service_period_end >= $4::date)) ORDER BY mr.id LIMIT $6",
   [req.membership.tenantId,contractId,siteId,periodStart,periodEnd,MAX_EVIDENCE_LINES+1]);
  if(revenue.rows.some(r=>r.aligned!==true||!r.reviewer_id))return {error:"Invoice date or reviewed service period is ambiguous; align both before calculating"};
  const partialPeriods=await client.query("SELECT 1 FROM allocation_runs ar JOIN payroll_pools pp ON pp.id=ar.payroll_pool_id AND pp.tenant_id=ar.tenant_id JOIN allocation_lines al ON al.allocation_run_id=ar.id AND al.tenant_id=ar.tenant_id WHERE ar.tenant_id=$1 AND al.site_id=$4 AND ar.status='confirmed' AND pp.period_start <= $3::date AND pp.period_end >= $2::date AND NOT (pp.period_start >= $2::date AND pp.period_end <= $3::date) LIMIT 1",[req.membership.tenantId,periodStart,periodEnd,siteId]);
  if(partialPeriods.rowCount)return {error:"A confirmed payroll period overlaps only part of the requested service period. Align periods before calculating; no pro-rata estimate is applied."};
  const costs=await client.query(
   "SELECT al.id AS allocation_line_id,ar.id AS allocation_run_id,pp.id AS payroll_pool_id,pp.batch_id,al.source_record_id,ps.raw_row_id,al.amount::text AS amount,al.bucket_type,ar.method_version,ar.reviewer_id,pp.currency,pp.period_start::text AS period_start,pp.period_end::text AS period_end,receipt.sha256 AS source_sha256 FROM allocation_lines al JOIN allocation_runs ar ON ar.id=al.allocation_run_id AND ar.tenant_id=al.tenant_id JOIN payroll_pools pp ON pp.id=ar.payroll_pool_id AND pp.tenant_id=ar.tenant_id LEFT JOIN payroll_source_records ps ON ps.id=al.source_record_id AND ps.tenant_id=al.tenant_id LEFT JOIN import_source_receipts receipt ON receipt.tenant_id=pp.tenant_id AND receipt.batch_id=pp.batch_id WHERE al.tenant_id=$1 AND al.site_id=$2 AND al.bucket_type IN ('direct','approved_allocated') AND ar.status='confirmed' AND pp.period_start >= $3::date AND pp.period_end <= $4::date ORDER BY al.id LIMIT $5",
   [req.membership.tenantId,siteId,periodStart,periodEnd,MAX_EVIDENCE_LINES+1]);
  if(!revenue.rowCount||!costs.rowCount)return {error:"Insufficient evidence: confirmed invoice lines and confirmed site allocation lines are both required"};
  if(revenue.rowCount>MAX_EVIDENCE_LINES||costs.rowCount>MAX_EVIDENCE_LINES)return {error:"Calculation evidence exceeds the supported line limit; use a shorter aligned period"};
  const basis=base.rows[0],taxBasis=revenue.rows[0].tax_basis;
  if(taxBasis==="unknown"||revenue.rows.some(r=>r.tax_basis!==taxBasis||r.currency!==basis.currency))return {error:"Mixed, unknown or mismatched invoice tax/currency basis. Resolve source basis before calculating."};
  if(costs.rows.some(r=>r.currency!==basis.currency))return {error:"Payroll currency does not match the contract currency"};
  let totals;try{totals=contributionTotals(revenue.rows.map(r=>r.amount),costs.rows.map(r=>r.amount));}catch(e){if(e instanceof RangeError)return {error:"Financial amounts exceed supported exact precision or contain invalid values"};throw e;}
  const snapshot={formulaVersion:FORMULA_VERSION,contractId,siteId,periodStart,periodEnd,contractVersion:{id:basis.version_id,number:basis.version_no,currency:basis.currency,effectiveFrom:basis.effective_from,effectiveTo:basis.effective_to,price:basis.price,billingBasis:basis.billing_basis,approvedBy:basis.approved_by},invoiceLines:revenue.rows.map(({aligned,...r})=>r),allocationLines:costs.rows,periodPolicy:"invoice date and reviewed service period must both align; no pro-rata calculation",roundingPolicy:"integer cents; percentage rounded half away from zero",completeness:"incomplete"};
  const evidenceSha256=snapshotDigest(snapshot);
  const outputs={...totals,currency:basis.currency,taxBasis:"consistent source invoice basis; no tax conversion applied",invoiceTaxBasis:taxBasis,invoiceLineCount:revenue.rowCount,allocationLineCount:costs.rowCount,taxBasisCount:1,formulaVersion:FORMULA_VERSION,evidenceSha256,limitations:["Management contribution only; not statutory or audited profit.","Only confirmed invoice matches and confirmed direct/approved site allocation lines are included.","Site payroll is not independently apportioned among multiple contracts sharing the site.","Other delivery costs, non-site costs and unallocated payroll are excluded.","Legacy source rows may lack original-file or reviewer lineage. Invoice issuer authenticity is not established.","Exact decimal strings are authoritative; numeric fields are compatibility projections. Margin is provisional and null when revenue is nonpositive or the numeric projection would exceed supported precision."]};
  const user=await client.query("SELECT id FROM users WHERE auth_subject=$1",[req.identity.subject]);if(!user.rowCount)throw Object.assign(new Error("User identity is not provisioned in this tenant database"),{status:403});
  const saved=await client.query("INSERT INTO calculation_runs(tenant_id,contract_id,site_id,period_start,period_end,formula_version,inputs,outputs,completeness,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'incomplete',$9) RETURNING id,created_at",[req.membership.tenantId,contractId,siteId,periodStart,periodEnd,FORMULA_VERSION,JSON.stringify({contractVersion:basis.version_no,invoiceLineCount:outputs.invoiceLineCount,allocationLineCount:outputs.allocationLineCount,snapshot,evidenceSha256}),JSON.stringify(outputs),user.rows[0].id]);
  await client.query("INSERT INTO audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata) VALUES($1,$2,'calculation_created','calculation_run',$3,'Versioned management contribution calculation',$4)",[req.membership.tenantId,user.rows[0].id,saved.rows[0].id,JSON.stringify({formulaVersion:FORMULA_VERSION,periodStart,periodEnd,evidenceSha256})]);
  return {id:saved.rows[0].id,createdAt:saved.rows[0].created_at,outputs};
 },{repeatableRead:true});
 if(result.error)return res.status(422).json({error:result.error});
 res.status(201).json(result);
 }catch(e){next(e);}});
 
app.get("/v1/tenants/:tenantId/calculations/:runId",membership,async(req,res,next)=>{try{
 if(!isUuid(req.params.runId))return res.status(400).json({error:"Invalid calculation ID"});
 const result=await withTenant(req.membership.tenantId,req.identity.subject,client=>client.query("SELECT id,contract_id,site_id,period_start,period_end,formula_version,inputs,outputs,completeness,created_at FROM calculation_runs WHERE id=$1 AND tenant_id=$2",[req.params.runId,req.membership.tenantId]));
 if(!result.rowCount)return res.status(404).json({error:"Calculation run not found"});
 res.json(result.rows[0]);
 }catch(e){next(e);}});
 

installSecurepayStorageRoutes(app,{membership,withTenant,requireRole});
installSecurepayReviewerRoutes(app,{membership,withTenant,requireRole});
installSecurepayConflictDeclarationRoutes(app,{membership,withTenant,requireRole});
installSecurepayProvenanceRoutes(app,{membership,withTenant,requireRole});
installSecurepaySignedPartyRoutes(app,{membership,withTenant,requireRole});
installSecurepayClaimRevocationRoutes(app,{membership,withTenant,requireRole});

app.use((err,req,res,next)=>{const id=randomUUID();process.stderr.write(JSON.stringify({event:"request_error",id,code:typeof err.code==="string"&&/^[A-Z0-9_]{1,30}$/.test(err.code)?err.code:"REQUEST_ERROR"})+"\n");const status=["23505","40001","40P01"].includes(err.code)?409:(Number.isInteger(err.status)&&err.status>=400&&err.status<500?err.status:500);res.status(status).json({error:status===409?"Conflicting record; refresh and review the current state":status===413?"Request body exceeds size limit":status===415?"Unsupported request encoding or media type":status<500?"Request rejected":"Internal server error",reference:id});});
const port=Number(process.env.PORT||8080);
if(process.env.NODE_ENV!=="test")app.listen(port,()=>process.stdout.write("ProfitPilot API listening on "+port+"\n"));
export default app;

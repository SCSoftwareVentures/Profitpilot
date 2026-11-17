import "dotenv/config";
import express from "express";
import {fileURLToPath} from "node:url";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import {randomUUID,createHash} from "node:crypto";
import {withTenant,health,listAuthSessions,revokeAuthSession,withPrivacyStepUp,appendAudit} from "./db.js";
import {authRequired,requirePermission,requireStepUp} from "./auth.js";
import {parseCsv,validateInvoiceRows,validatePayrollRows,isIsoDate} from "../src/engine.js";
import {registerPayrollRoutes} from "./payroll.js";
import {registerContributionRoutes} from "./contribution.js";
import {reconcileSharedOverhead} from "../src/shared-overhead.js";
import {registerInvoiceRoutes} from "./invoices.js";
import {registerSourceReconciliationRoutes} from "./source-reconciliation.js";
import {importPayloadAllowed} from "../src/import-privacy.js";
import {parseFinancialCsv} from "../src/secure-csv.js";
import {accountRateLimit} from "./request-guard.js";
import {registerAttachmentQuarantineRoutes} from "./attachment-quarantine.js";

const app=express();
app.disable("x-powered-by");
app.use(helmet());
// Apply even to parser errors, authentication failures and preflight responses.
app.use((req,res,next)=>{res.set("Cache-Control","no-store");next();});
app.use(cors({origin:(process.env.CORS_ORIGIN||"").split(",").map(x=>x.trim()).filter(Boolean),credentials:false,methods:["GET","POST","DELETE"]}));
// Only the dedicated synthetic PostgreSQL integration harness gets an expanded test window.
// Production, CI container smoke tests, and non-integration environments retain 100/min.
const globalRpmLimit=(process.env.NODE_ENV==="test"&&Boolean(process.env.TEST_ADMIN_DATABASE_URL))?500:100;
app.use(rateLimit({windowMs:60_000,limit:globalRpmLimit,standardHeaders:true,legacyHeaders:false}));
app.use(express.json({limit:"100kb",inflate:false}));
app.get("/health",async(req,res)=>{try{await health();res.json({status:"ok",database:"connected"});}catch{res.status(503).json({status:"unavailable"});}});
// Opt-in synthetic workspace only; never served in production.
if(process.env.NODE_ENV!=="production"&&process.env.ENABLE_SYNTHETIC_PAYROLL_UI==="true"){
 for(const [route,file] of Object.entries({"/dev/payroll":"../app/payroll.html","/dev/payroll.js":"../app/payroll.js","/dev/payroll.css":"../app/payroll.css","/dev/payroll-client.js":"../src/payroll-client.js"})){
  app.get(route,(req,res)=>{res.set("Cache-Control","no-store");res.sendFile(fileURLToPath(new URL(file,import.meta.url)));});
 }
}
app.use("/v1",(req,res,next)=>{res.set("Cache-Control","no-store");next();});
app.use("/v1",authRequired());
app.use("/v1",accountRateLimit({limit:globalRpmLimit===500?500:60}));

async function membership(req,res,next){
 const tenantId=req.params.tenantId;
 if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(tenantId))return res.status(400).json({error:"Invalid tenant ID"});
 try{
  const r=await withTenant(tenantId,req.identity.subject,client=>client.query("SELECT tm.role,u.id AS user_id FROM tenant_memberships tm JOIN users u ON u.id=tm.user_id JOIN tenants t ON t.id=tm.tenant_id WHERE tm.tenant_id=$1 AND u.auth_subject=$2 AND tm.status='active' AND u.status='active' AND t.status='active'",[tenantId,req.identity.subject]));
  if(!r.rowCount)return res.status(403).json({error:"No active membership for this tenant"});
  req.membership={tenantId,role:r.rows[0].role,userId:r.rows[0].user_id};next();
 }catch(e){next(e);}
}
app.get("/v1/me",async(req,res)=>{res.json({subject:req.identity.subject,email:req.identity.email,membershipsEndpoint:"Membership discovery is not exposed until a separately reviewed security-definer function is installed."});});
app.get("/v1/me/security",async(req,res)=>{res.set("Cache-Control","no-store");res.json({
 authentication:{issuerConfigured:Boolean(process.env.AUTH_ISSUER),audienceConfigured:Boolean(process.env.AUTH_AUDIENCE),stepUpConfigured:Boolean(process.env.AUTH_STEP_UP_ACR),stepUpMaxAgeSeconds:Number(process.env.AUTH_STEP_UP_MAX_AGE_SECONDS||300)},
 currentSession:{sessionId:req.identity.jti,authenticatedAt:req.identity.authTime,assuranceClass:req.identity.acr}
});});
app.get("/v1/tenants/:tenantId/security/permissions",membership,requirePermission("security.permissions.read"),requireStepUp(),async(req,res,next)=>{try{
 const result=await withTenant(req.membership.tenantId,req.identity.subject,async client=>{
  const catalogue=await client.query("SELECT pc.permission_key,pc.description,pc.sensitive,rp.role,(rp.permission_key IS NOT NULL) AS granted_by_role FROM permission_catalog pc LEFT JOIN role_permissions rp ON rp.permission_key=pc.permission_key ORDER BY pc.permission_key,rp.role");
  const overrides=await client.query("SELECT user_id,permission_key,effect,reason,granted_by,created_at FROM tenant_membership_permission_overrides WHERE tenant_id=$1 ORDER BY user_id,permission_key",[req.membership.tenantId]);
  return {catalogue:catalogue.rows,overrides:overrides.rows};
 });
 res.json(result);
}catch(e){next(e);}});
app.post("/v1/tenants/:tenantId/security/permissions/overrides",membership,requirePermission("security.permissions.manage"),requireStepUp(),async(req,res,next)=>{try{
 const {userId,permissionKey,effect,reason}=req.body||{};
 if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(userId||"")||
    typeof permissionKey!=="string"||permissionKey.length>128||permissionKey.startsWith("security.")||permissionKey.startsWith("privacy.")||
    !["grant","deny"].includes(effect)||typeof reason!=="string"||reason.trim().length<3||reason.length>1000)
  return res.status(400).json({error:"Valid member, non-security permission, effect and reason are required"});
 const result=await withTenant(req.membership.tenantId,req.identity.subject,async client=>{
  const target=await client.query("SELECT 1 FROM tenant_memberships WHERE tenant_id=$1 AND user_id=$2 AND status='active'",[req.membership.tenantId,userId]);
  if(!target.rowCount)return {status:404,error:"Active tenant member not found"};
  const permission=await client.query("SELECT 1 FROM permission_catalog WHERE permission_key=$1",[permissionKey]);
  if(!permission.rowCount)return {status:400,error:"Unknown permission"};
  await client.query("SELECT private.set_member_permission_override($1,$2,$3,$4,$5,$6)",[req.membership.tenantId,req.membership.userId,userId,permissionKey,effect,reason.trim()]);
  await appendAudit(client,req.membership,"member_permission_override_set","tenant_membership_permission_override",userId,reason.trim(),{permissionKey,effect});
  return {status:201,override:{userId,permissionKey,effect,reason:reason.trim()}};
 });
 if(result.error)return res.status(result.status).json({error:result.error});
 res.status(result.status).json(result.override);
}catch(e){next(e);}});
app.delete("/v1/tenants/:tenantId/security/permissions/overrides/:userId/:permissionKey",membership,requirePermission("security.permissions.manage"),requireStepUp(),async(req,res,next)=>{try{
 const {userId,permissionKey}=req.params;
 const {reason}=req.body||{};
 if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(userId||"")||
    typeof permissionKey!=="string"||permissionKey.startsWith("security.")||permissionKey.startsWith("privacy.")||
    typeof reason!=="string"||reason.trim().length<3||reason.length>1000)
  return res.status(400).json({error:"Valid member, permission and removal reason are required"});
 const result=await withTenant(req.membership.tenantId,req.identity.subject,async client=>{
  const removed=await client.query("SELECT private.remove_member_permission_override($1,$2,$3,$4) AS removed",[req.membership.tenantId,req.membership.userId,userId,permissionKey]);
  if(!removed.rows[0].removed)return {status:404,error:"Permission override not found"};
  await appendAudit(client,req.membership,"member_permission_override_removed","tenant_membership_permission_override",userId,reason.trim(),{permissionKey});
  return {status:200};
 });
 if(result.error)return res.status(result.status).json({error:result.error});
 res.status(result.status).json({removed:true,userId,permissionKey});
}catch(e){next(e);}});
app.get("/v1/tenants/:tenantId/security/audit",membership,requirePermission("security.audit.read"),requireStepUp(),async(req,res,next)=>{try{
 const limitRaw=Number(req.query.limit||50);
 if(!Number.isInteger(limitRaw)||limitRaw<1||limitRaw>100)return res.status(400).json({error:"Audit page limit must be an integer from 1 to 100"});
 const tenant=req.membership.tenantId;
 const result=await withPrivacyStepUp(req.membership,req.identity,tenant,"read_audit_summary:"+limitRaw,async(client,proof)=>{
  const r=await client.query("SELECT private.read_audit_summary($1,$2,$3,$4) AS result",[tenant,limitRaw,req.identity.authTime,proof]);
  return r.rows[0].result;
 });
 res.json(result);
}catch(e){next(e);}});

app.get("/v1/me/sessions",async(req,res,next)=>{try{
 const sessions=await listAuthSessions(req.identity.subject);
 res.json({items:sessions.map(s=>({sessionId:s.jti,issuedAt:s.issued_at,expiresAt:s.expires_at,lastSeenAt:s.last_seen_at,revokedAt:s.revoked_at}))});
}catch(e){next(e);}});
app.delete("/v1/me/sessions/:jti",async(req,res,next)=>{try{
 const jti=req.params.jti;
 if(typeof jti!=="string"||jti.length<16||jti.length>128||!/^[A-Za-z0-9._~-]+$/.test(jti))return res.status(400).json({error:"Invalid session identifier"});
 const revoked=await revokeAuthSession(jti,req.identity.subject);
 if(!revoked)return res.status(404).json({error:"Active session not found"});
 res.status(200).json({sessionId:jti,revoked:true});
}catch(e){next(e);}});
app.post("/v1/tenants/:tenantId/privacy/requests",membership,requirePermission("privacy.requests.submit"),async(req,res,next)=>{try{
 const {requestType,details}=req.body||{};
 if(!["access","correction","export","deletion","restriction","account_closure"].includes(requestType)||typeof details!=="string"||details.trim().length<3||details.length>2000)
  return res.status(400).json({error:"A supported request type and concise description are required"});
 const result=await withTenant(req.membership.tenantId,req.identity.subject,async client=>{
  const created=await client.query("INSERT INTO privacy_requests(tenant_id,subject_user_id,submitted_by,request_type,details) VALUES($1,$2,$2,$3,$4) RETURNING id,request_type,status,created_at",[req.membership.tenantId,req.membership.userId,requestType,details.trim()]);
  const item=created.rows[0];
  await appendAudit(client,req.membership,"privacy_request_submitted","privacy_request",item.id,'Member submitted a privacy request',{requestType});
  return item;
 });
 res.status(201).json(result);
}catch(e){next(e);}});
app.get("/v1/tenants/:tenantId/privacy/requests",membership,requirePermission("privacy.requests.read"),async(req,res,next)=>{try{
 const result=await withTenant(req.membership.tenantId,req.identity.subject,async client=>{
  const rows=await client.query("SELECT id,request_type,status,details,created_at,updated_at,resolved_at,resolution_summary,legal_hold_reason,account_confirmed_at,details_redacted_at FROM privacy_requests WHERE tenant_id=$1 AND subject_user_id=$2 ORDER BY created_at DESC LIMIT 100",[req.membership.tenantId,req.membership.userId]);
  return {items:rows.rows};
 });
 res.json(result);
}catch(e){next(e);}});
app.get("/v1/tenants/:tenantId/privacy/requests/manage",membership,requirePermission("privacy.requests.manage"),requireStepUp(),async(req,res,next)=>{try{
 const tenant=req.membership.tenantId;
 const result=await withPrivacyStepUp(req.membership,req.identity,tenant,"read_privacy_queue",async(client,proof)=>{
  const r=await client.query("SELECT private.read_privacy_queue($1,$2,$3) AS result",[tenant,req.identity.authTime,proof]);
  return r.rows[0].result;
 });
 res.json(result);
}catch(e){next(e);}});
app.post("/v1/tenants/:tenantId/privacy/requests/:requestId/read-details",membership,requirePermission("privacy.requests.manage"),requireStepUp(),async(req,res,next)=>{try{
 const id=req.params.requestId,reason=req.body?.reason;
 if(!privacyRequestIdValid(id)||typeof reason!=="string"||reason.trim().length<3||reason.length>500||/[\x00-\x1f\x7f]/.test(reason))return res.status(400).json({error:"Valid request ID and access purpose required"});
 const purpose=reason.trim();
 // Bind to the exact purpose without exposing it in the proof domain.
 const action="read_privacy_details:"+createHash("sha256").update(purpose).digest("hex");
 const result=await withPrivacyStepUp(req.membership,req.identity,id,action,async(client,proof)=>{
  const r=await client.query("SELECT private.read_privacy_details($1,$2,$3,$4,$5) AS result",[req.membership.tenantId,id,purpose,req.identity.authTime,proof]);
  return r.rows[0].result;
 });
 if(result.error)return res.status(result.status).json({error:result.error});
 res.json(result.item);
}catch(e){next(e);}});
// Scope-limited account correction, never a provider credential or identity change.
app.post("/v1/tenants/:tenantId/privacy/requests/:requestId/correct-local-email",membership,requirePermission("privacy.requests.submit"),requireStepUp(),async(req,res,next)=>{try{
 const id=req.params.requestId;
 if(!privacyRequestIdValid(id)||req.body?.localProfileOnly!==true)return res.status(400).json({error:"Explicit local-profile-only correction required"});
 const {email,emailVerified,issuer,issuedAt}=req.identity;
 if(!emailVerified||typeof email!=="string"||email.length>254||!/^[^\s@\x00-\x1f\x7f]+@[^\s@\x00-\x1f\x7f]+\.[^\s@\x00-\x1f\x7f]+$/.test(email))return res.status(403).json({error:"Fresh provider-verified email claim required"});
 const evidence=JSON.stringify({email,issuer,issuedAt});
 const action="correct_local_email:"+createHash("sha256").update(evidence).digest("hex");
 const result=await withPrivacyStepUp(req.membership,req.identity,id,action,async(client,proof)=>{
  const r=await client.query("SELECT private.correct_local_email($1,$2,$3,$4,$5) AS result",[req.membership.tenantId,id,evidence,req.identity.authTime,proof]);
  return r.rows[0].result;
 });
 if(result.error)return res.status(result.status).json({error:result.error});
 res.status(200).json(result.item);
}catch(e){next(e);}});
const privacyRequestIdValid=id=>typeof id==="string"&&/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id);
app.post("/v1/tenants/:tenantId/privacy/requests/:requestId/source-ingestion-restriction",membership,requirePermission("privacy.requests.submit"),requireStepUp(),async(req,res,next)=>{try{
 const id=req.params.requestId,{mode,acknowledgeLimitedScope}=req.body||{};
 if(!privacyRequestIdValid(id)||!["activate","release"].includes(mode)||acknowledgeLimitedScope!==true)return res.status(400).json({error:"Explicit limited source ingestion restriction action required"});
 const result=await withPrivacyStepUp(req.membership,req.identity,id,"source_ingestion_restriction:"+mode,async(c,proof)=>{
  const r=await c.query("SELECT private.apply_source_ingestion_restriction($1,$2,$3,$4,$5) AS result",[req.membership.tenantId,id,mode,req.identity.authTime,proof]);return r.rows[0].result;
 });
 if(result.error)return res.status(result.status).json({error:result.error});
 res.json(result.item);
}catch(e){next(e);}});
app.post("/v1/tenants/:tenantId/privacy/requests/:requestId/confirm-account",membership,requirePermission("privacy.requests.submit"),requireStepUp(),async(req,res,next)=>{try{
 const id=req.params.requestId;
 if(!privacyRequestIdValid(id))return res.status(400).json({error:"Invalid request ID"});
 const result=await withPrivacyStepUp(req.membership,req.identity,id,"confirm_account",async(client,proof)=>{
  const r=await client.query("SELECT private.confirm_privacy_account($1,$2,$3,$4) AS result",[req.membership.tenantId,id,req.identity.authTime,proof]);
  return r.rows[0].result;
 });
 if(result.error)return res.status(result.status).json({error:result.error});
 res.status(result.status).json(result.item);
}catch(e){next(e);}});
app.post("/v1/tenants/:tenantId/privacy/requests/:requestId/decision",membership,requirePermission("privacy.requests.manage"),requireStepUp(),async(req,res,next)=>{try{
 const {action,reason,resolutionSummary}=req.body||{};
 if(!privacyRequestIdValid(req.params.requestId))return res.status(400).json({error:"Invalid request ID"});
 if(action==="fulfil")return res.status(409).json({error:"Privacy request fulfilment is not implemented. Complete and verify the requested action before recording fulfilment."});
 if(!["verify_identity","begin_review","place_legal_hold","release_legal_hold","reject"].includes(action)||typeof reason!=="string"||reason.trim().length<3||reason.length>1000)
  return res.status(400).json({error:"A supported review action and reason are required"});
 if(action==="reject"&&(typeof resolutionSummary!=="string"||resolutionSummary.trim().length<3||resolutionSummary.length>2000))
  return res.status(400).json({error:"A resolution summary is required for a completed decision"});
 const result=await withPrivacyStepUp(req.membership,req.identity,req.params.requestId,"decision:"+action,async(client,proof)=>{
  const r=await client.query("SELECT private.decide_privacy_request($1,$2,$3,$4,$5,$6,$7) AS result",[req.membership.tenantId,req.params.requestId,action,reason.trim(),action==="reject"?resolutionSummary.trim():null,req.identity.authTime,proof]);
  return r.rows[0].result;
 });
 if(result.error)return res.status(result.status).json({error:result.error});
 res.status(result.status).json(result.item);
}catch(e){next(e);}});
// Both operations require independent, request-bound step-up evidence at the database.
app.post("/v1/tenants/:tenantId/privacy/requests/:requestId/approve-export",membership,requirePermission("privacy.requests.manage"),requireStepUp(),async(req,res,next)=>{try{
 const id=req.params.requestId;
 if(!privacyRequestIdValid(id))return res.status(400).json({error:"Invalid request ID"});
 const result=await withPrivacyStepUp(req.membership,req.identity,id,"approve_account_export",async(client,proof)=>{
  const r=await client.query("SELECT private.approve_account_export($1,$2,$3,$4) AS result",[req.membership.tenantId,id,req.identity.authTime,proof]);
  return r.rows[0].result;
 });
 if(result.error)return res.status(result.status).json({error:result.error});
 res.status(result.status).json(result.item);
}catch(e){next(e);}});
app.post("/v1/tenants/:tenantId/privacy/requests/:requestId/export",membership,requirePermission("privacy.requests.read"),requireStepUp(),async(req,res,next)=>{try{
 const id=req.params.requestId;
 if(!privacyRequestIdValid(id))return res.status(400).json({error:"Invalid request ID"});
 const result=await withPrivacyStepUp(req.membership,req.identity,id,"release_account_export",async(client,proof)=>{
  const r=await client.query("SELECT private.release_account_export($1,$2,$3,$4) AS result",[req.membership.tenantId,id,req.identity.authTime,proof]);
  return r.rows[0].result;
 });
 if(result.error)return res.status(result.status).json({error:result.error});
 res.set({"Cache-Control":"no-store, private","Pragma":"no-cache","Content-Disposition":"attachment; filename=\"profitpilot-account-export.json\"","X-Content-Type-Options":"nosniff"});
 // No persisted file, public URL, email attachment, or server-side copy.
 res.status(200).type("application/json").send(JSON.stringify(result.item));
}catch(e){next(e);}});
for(const [route,permission,fn] of [
 ["approve-redaction","privacy.requests.manage","approve_request_redaction"],
 ["execute-redaction","privacy.requests.submit","execute_request_redaction"]
]){
 app.post("/v1/tenants/:tenantId/privacy/requests/:requestId/"+route,membership,requirePermission(permission),requireStepUp(),async(req,res,next)=>{try{
  const id=req.params.requestId,target=req.body?.targetRequestId;
  if(!privacyRequestIdValid(id)||!privacyRequestIdValid(target))return res.status(400).json({error:"Valid request and target IDs required"});
  const result=await withPrivacyStepUp(req.membership,req.identity,id,fn+":"+target.toLowerCase(),async(client,proof)=>{
   // fn is from a fixed server-side allowlist, never user input.
   const r=await client.query("SELECT private."+fn+"($1,$2,$3,$4,$5) AS result",[req.membership.tenantId,id,target,req.identity.authTime,proof]);
   return r.rows[0].result;
  });
  if(result.error)return res.status(result.status).json({error:result.error});
  res.status(result.status).json(result.item);
 }catch(e){next(e);}});
}
for(const [route,permission,fn] of [
 ["approve-closure","privacy.requests.manage","approve_account_closure"],
 ["execute-closure","privacy.requests.submit","execute_account_closure"]
]){
 app.post("/v1/tenants/:tenantId/privacy/requests/:requestId/"+route,membership,requirePermission(permission),requireStepUp(),async(req,res,next)=>{try{
  const id=req.params.requestId,erase=req.body?.eraseEmail;
  if(!privacyRequestIdValid(id)||typeof erase!=="boolean")return res.status(400).json({error:"Valid request ID and explicit eraseEmail choice required"});
  const result=await withPrivacyStepUp(req.membership,req.identity,id,fn+":"+String(erase),async(client,proof)=>{
   const r=await client.query("SELECT private."+fn+"($1,$2,$3,$4,$5) AS result",[req.membership.tenantId,id,erase,req.identity.authTime,proof]);
   return r.rows[0].result;
  });
  if(result.error)return res.status(result.status).json({error:result.error});
  res.status(result.status).json(result.item);
 }catch(e){next(e);}});
}
app.post("/v1/tenants/:tenantId/privacy/requests/:requestId/withdraw",membership,requirePermission("privacy.requests.submit"),async(req,res,next)=>{try{
 const {reason}=req.body||{};
 if(!privacyRequestIdValid(req.params.requestId))return res.status(400).json({error:"Invalid request ID"});
 if(typeof reason!=="string"||reason.trim().length<3||reason.length>1000)return res.status(400).json({error:"A withdrawal reason is required"});
 const result=await withTenant(req.membership.tenantId,req.identity.subject,async client=>{
  const updated=await client.query("SELECT request_id AS id,request_status AS status,request_updated_at AS updated_at FROM private.withdraw_privacy_request($1,$2,$3)",[req.membership.tenantId,req.params.requestId,reason.trim()]);
  if(!updated.rowCount)return {status:404,error:"Withdrawable privacy request not found"};
  return {status:200,item:updated.rows[0]};
 });
 if(result.error)return res.status(result.status).json({error:result.error});
 res.status(result.status).json(result.item);
}catch(e){next(e);}});
app.get("/v1/tenants/:tenantId/contracts",membership,requirePermission("contracts.read"),async(req,res,next)=>{try{const rows=await withTenant(req.membership.tenantId,req.identity.subject,async c=>(await c.query("SELECT id,customer_name,status FROM contracts WHERE tenant_id=$1 ORDER BY customer_name",[req.membership.tenantId])).rows);res.json({items:rows});}catch(e){next(e);}});
app.post("/v1/tenants/:tenantId/imports",membership,requirePermission("imports.create"),async(req,res,next)=>{
 try{
  const {sourceType,fileName,sha256,permissionReference,periodStart,periodEnd}=req.body||{};
  if(!["payroll","customer_invoice","supplier_invoice"].includes(sourceType)||typeof fileName!=="string"||!fileName.trim()||fileName.length>255||/[\x00-\x1f\x7f]/.test(fileName)||typeof sha256!=="string"||!/^[a-f0-9]{64}$/i.test(sha256)||typeof permissionReference!=="string"||!permissionReference.trim()||permissionReference.length>1000||/[\x00-\x1f\x7f]/.test(permissionReference)||!isIsoDate(periodStart)||!isIsoDate(periodEnd)||periodEnd<periodStart)return res.status(400).json({error:"Invalid import metadata"});
  const id=randomUUID();
  const result=await withTenant(req.membership.tenantId,req.identity.subject,async c=>c.query("INSERT INTO import_batches(id,tenant_id,source_type,source_period_start,source_period_end,permission_ref,status,file_sha256,file_name,created_by) SELECT $1,$2,$3,$4,$5,$6,'uploaded',$7,$8,u.id FROM users u WHERE u.auth_subject=$9 ON CONFLICT(tenant_id,file_sha256) DO NOTHING RETURNING id,status",[id,req.membership.tenantId,sourceType,periodStart,periodEnd,permissionReference.trim(),sha256.toLowerCase(),fileName,req.identity.subject]));
  if(!result.rowCount){
   const old=await withTenant(req.membership.tenantId,req.identity.subject,async c=>c.query("SELECT id,status,created_by,source_type,file_name,permission_ref,source_period_start::text AS start,source_period_end::text AS end FROM import_batches WHERE tenant_id=$1 AND file_sha256=$2",[req.membership.tenantId,sha256.toLowerCase()]));
   const b=old.rows[0];
   if(!b||b.created_by!==req.membership.userId||b.source_type!==sourceType||b.file_name!==fileName||b.permission_ref!==permissionReference.trim()||b.start!==periodStart||b.end!==periodEnd)return res.status(409).json({error:"Source checksum already registered with different ownership or metadata"});
   return res.status(200).json({batch:{id:b.id,status:b.status},idempotent:true});
  }
  res.status(201).json({batch:result.rows[0]});
 }catch(e){next(e);}
});
async function stageFinancialRows(req,res,next,{csv=false}={}){try{
 let rows=csv?null:req.body?.rows;
 if(!privacyRequestIdValid(req.params.batchId))return res.status(400).json({error:"Invalid batch ID"});
 if(!csv&&(!Array.isArray(rows)||rows.length<1||rows.length>200||rows.some(x=>!x||typeof x!=="object"||Array.isArray(x))))return res.status(400).json({error:"Provide 1–200 row objects"});
 const result=await withTenant(req.membership.tenantId,req.identity.subject,async client=>{
  const batch=await client.query("SELECT id,status,source_type,created_by,file_sha256,file_name FROM import_batches WHERE id=$1 AND tenant_id=$2 FOR UPDATE",[req.params.batchId,req.membership.tenantId]);
  if(!batch.rowCount)return {status:404,error:"Import batch not found"};
  if(!["uploaded","review","validating"].includes(batch.rows[0].status))return {status:409,error:"Import batch is not open for row ingestion"};
  // All financial batches are complete single submissions; the declared importer must upload them.
  {
   if(batch.rows[0].created_by!==req.membership.userId)return {status:403,error:"Only the original batch importer may submit its source rows"};
   if(csv){
    if(!/^[^\/\\\x00-\x1f\x7f]{1,250}\.csv$/i.test(batch.rows[0].file_name))return {status:422,error:"Registered source filename must be a CSV basename"};
    const checked=parseFinancialCsv(req.body,batch.rows[0].source_type);
    if(checked.error)return {status:422,error:checked.error};
    if(checked.sha256!==batch.rows[0].file_sha256)return {status:409,error:"CSV checksum differs from the registered source"};
    rows=checked.rows;
   }
   if(!importPayloadAllowed(batch.rows[0].source_type,rows))return {status:422,error:"Source rows contain unsupported fields, nested values or excessive lengths; remove unnecessary personal data before submitting"};
   const prior=(await client.query("SELECT count(*)::int AS n, COALESCE(jsonb_agg(payload ORDER BY row_number)=$3::jsonb,false) AS identical FROM raw_import_rows WHERE batch_id=$1 AND tenant_id=$2",[req.params.batchId,req.membership.tenantId,JSON.stringify(rows)])).rows[0];
   if(prior.n>0){
    if(!prior.identical)return {status:409,error:"Source batch already contains different rows; create a new batch and reconcile independently"};
    if(csv)return {status:409,error:"Batch already staged; file submission cannot replace or certify a previous upload"};
    return {status:201,inserted:0,received:rows.length,duplicates:rows.length};
   }
  }
  let inserted=0;
  for(let i=0;i<rows.length;i++){
   const row=await client.query("INSERT INTO raw_import_rows(tenant_id,batch_id,row_number,payload) VALUES($1,$2,$3,$4) ON CONFLICT(batch_id,row_number) DO NOTHING RETURNING id",[req.membership.tenantId,req.params.batchId,i+1,JSON.stringify(rows[i])]);
   inserted+=row.rowCount;
  }
  await client.query("UPDATE import_batches SET status='review' WHERE id=$1 AND tenant_id=$2",[req.params.batchId,req.membership.tenantId]);
  if(csv)await appendAudit(client,req.membership,"import_csv_staged","import_batch",req.params.batchId,"CSV bytes matched declared source checksum",{sha256:batch.rows[0].file_sha256,rowCount:rows.length,rawFilePersisted:false});
  return {status:201,inserted,received:rows.length,duplicates:rows.length-inserted};
 });
 if(result.error)return res.status(result.status).json({error:result.error});
 res.status(result.status).json({batchId:req.params.batchId,inserted:result.inserted,received:result.received,duplicates:result.duplicates,...(csv?{checksumVerified:true,rawFilePersisted:false}:{})});
 }catch(e){next(e);}finally{if(csv&&Buffer.isBuffer(req.body))req.body.fill(0);}}
app.post("/v1/tenants/:tenantId/imports/:batchId/rows",membership,requirePermission("imports.rows.write"),(req,res,next)=>stageFinancialRows(req,res,next));
app.post("/v1/tenants/:tenantId/imports/:batchId/rows/csv",membership,requirePermission("imports.rows.write"),requireStepUp(),(req,res,next)=>{
 if(!req.is("text/csv"))return res.status(415).json({error:"Only text/csv is supported"});next();
},express.raw({type:"text/csv",limit:"100kb",inflate:false}),(req,res,next)=>stageFinancialRows(req,res,next,{csv:true}));

// Decision-only import review: never return raw payroll, financial or personal source payloads.
app.get("/v1/tenants/:tenantId/imports/:batchId/review",membership,requirePermission("imports.validate"),async(req,res,next)=>{
 try{
  if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(req.params.batchId))return res.status(400).json({error:"Invalid batch ID"});
  const offsetArg=req.query.offset===undefined?"0":req.query.offset;
  const limitArg=req.query.limit===undefined?"100":req.query.limit;
  if(typeof offsetArg!=="string"||!/^(0|[1-9]\d{0,6})$/.test(offsetArg)||typeof limitArg!=="string"||!/^[1-9]\d{0,2}$/.test(limitArg)||Number(limitArg)>100){
   return res.status(400).json({error:"Invalid review pagination"});
  }
  const offset=Number(offsetArg),limit=Number(limitArg);
  const result=await withTenant(req.membership.tenantId,req.identity.subject,async client=>{
   const batch=await client.query("SELECT id,status,source_type FROM import_batches WHERE id=$1 AND tenant_id=$2",[req.params.batchId,req.membership.tenantId]);
   if(!batch.rowCount)return null;
   const methodVersion=batch.rows[0].source_type==="payroll"?"payroll-validator-0.1.0":batch.rows[0].status==="accepted"?"canonical-invoice-0.1.0":"invoice-validator-0.1.0";
   const args=[req.params.batchId,req.membership.tenantId,methodVersion];
   const from=" FROM raw_import_rows r LEFT JOIN mapping_decisions d ON d.tenant_id=r.tenant_id AND d.raw_row_id=r.id AND d.method_version=$3 WHERE r.batch_id=$1 AND r.tenant_id=$2";
   const counts=await client.query(
    "SELECT COUNT(*)::int AS total,"+
    "COUNT(*) FILTER(WHERE d.decision='candidate')::int AS candidate,"+
    "COUNT(*) FILTER(WHERE d.decision='held')::int AS held,"+
    "COUNT(*) FILTER(WHERE d.decision='accepted')::int AS accepted,"+
    "COUNT(*) FILTER(WHERE d.decision='rejected')::int AS rejected,"+
    "COUNT(*) FILTER(WHERE d.id IS NULL)::int AS unvalidated"+from,args);
   const page=await client.query(
    "SELECT r.row_number AS \"rowNumber\",COALESCE(d.decision,'unvalidated') AS decision,"+
    "CASE WHEN d.decision IN ('held','rejected') THEN d.reason ELSE NULL END AS reason"+from+
    " ORDER BY r.row_number LIMIT $4 OFFSET $5",[...args,limit,offset]);
   return {batchId:req.params.batchId,sourceType:batch.rows[0].source_type,status:batch.rows[0].status,
    summary:counts.rows[0],offset,limit,items:page.rows};
  });
  if(!result)return res.status(404).json({error:"Import batch not found"});
  res.json(result);
 }catch(e){next(e);}
});

app.post("/v1/tenants/:tenantId/imports/:batchId/validate",membership,requirePermission("imports.validate"),async(req,res,next)=>{try{
 if(!privacyRequestIdValid(req.params.batchId))return res.status(400).json({error:"Invalid batch ID"});
 const result=await withTenant(req.membership.tenantId,req.identity.subject,async client=>{
  const batch=await client.query("SELECT id,status,source_type,source_period_start::text AS source_period_start,source_period_end::text AS source_period_end FROM import_batches WHERE id=$1 AND tenant_id=$2 FOR UPDATE",[req.params.batchId,req.membership.tenantId]);
  if(!batch.rowCount)return {status:404,error:"Import batch not found"};
  if(!["uploaded","review","validating"].includes(batch.rows[0].status))return {status:409,error:"Import batch is not open for validation"};
  const payroll=batch.rows[0].source_type==="payroll";
  if(!payroll&&!["customer_invoice","supplier_invoice"].includes(batch.rows[0].source_type))return {status:422,error:"Unsupported import source type"};
  const raw=await client.query("SELECT id,row_number,payload FROM raw_import_rows WHERE batch_id=$1 AND tenant_id=$2 ORDER BY row_number",[req.params.batchId,req.membership.tenantId]);
  if(!raw.rowCount)return {status:422,error:"No persisted import rows found. Ingest rows before validation."};
  const input=raw.rows.map(r=>({...r.payload,__rowNumber:String(r.row_number)}));
  const checked=payroll?validatePayrollRows(input,{periodStart:batch.rows[0].source_period_start,periodEnd:batch.rows[0].source_period_end}):validateInvoiceRows(input);
  const targetType=payroll?"payroll_row":"invoice_row",methodVersion=payroll?"payroll-validator-0.1.0":"invoice-validator-0.1.0";
  let valid=0,held=0;
  for(let i=0;i<raw.rows.length;i++){
   const item=checked[i],row=raw.rows[i],decision=item.errors.length?"held":"candidate";
   if(decision==="held")held++;else valid++;
   await client.query("INSERT INTO mapping_decisions(tenant_id,raw_row_id,target_type,target_id,decision,confidence,method_version,reason) VALUES($1,$2,$3,NULL,$4,'LOW',$5,$6) ON CONFLICT(tenant_id,raw_row_id,method_version) DO UPDATE SET decision=EXCLUDED.decision,reason=EXCLUDED.reason WHERE mapping_decisions.decision IN ('candidate','held')",[req.membership.tenantId,row.id,targetType,decision,methodVersion,item.errors.join("; ")||"Structural validation only; requires human review; no automatic payroll allocation or acceptance"]);
  }
  await client.query("UPDATE import_batches SET status='review' WHERE id=$1 AND tenant_id=$2",[req.params.batchId,req.membership.tenantId]);
  return {status:200,batchId:req.params.batchId,sourceType:batch.rows[0].source_type,total:raw.rowCount,validCandidateRows:valid,heldRows:held,automaticallyAccepted:0};
 });
 if(result.error)return res.status(result.status).json({error:result.error});
 const {status,...body}=result;res.status(status).json(body);
 }catch(e){next(e);}});

app.post("/v1/tenants/:tenantId/matches/:matchId/decision",membership,requirePermission("matching.decide"),requireStepUp(),async(req,res,next)=>{try{
 const {decision,reason,costCategory,payrollOverlapReviewed,duplicateExpenseReviewed,expectedDirection,siteOverheadReviewed,sharedOverheadShares,sharedOverheadBasis,sharedOverheadReviewed,sharedOverheadProposalId}=req.body||{};
 if(!["confirmed","rejected","held","propose_shared_overhead"].includes(decision)||typeof reason!=="string"||reason.trim().length<3||reason.length>2000)return res.status(400).json({error:"Decision and reason are required"});
 const result=await withTenant(req.membership.tenantId,req.identity.subject,async client=>{
  const member=req.membership;
  const candidate=await client.query("SELECT mr.id,mr.contract_id,mr.site_id,mr.service_period_start::text AS service_start,mr.service_period_end::text AS service_end,mr.confidence,mr.evidence,il.amount::text AS source_amount,i.direction,i.currency,i.tax_basis FROM match_reviews mr JOIN invoice_lines il ON il.id=mr.invoice_line_id AND il.tenant_id=mr.tenant_id JOIN invoices i ON i.id=il.invoice_id AND i.tenant_id=il.tenant_id WHERE mr.id=$1 AND mr.tenant_id=$2 AND mr.decision IN ('candidate','held') FOR UPDATE OF mr,il,i",[req.params.matchId,member.tenantId]);
  if(!candidate.rowCount)return null;
  const m=candidate.rows[0];
  if(expectedDirection!==undefined&&(!["customer","supplier"].includes(expectedDirection)||expectedDirection!==m.direction))return {error:"Invoice direction mismatch",status:422};
  const canonical=m.evidence?.canonicalInvoice;
  if(canonical?.method==="canonical-invoice-0.1.0"&&decision==="confirmed"&&(canonical.preparedBy===member.userId||canonical.importedBy===member.userId))return {error:"Independent match confirmer required",status:403};
  let expenseReview=null;
  const proposing=decision==="propose_shared_overhead";
  const proposal=m.evidence?.sharedOverheadProposal;
  const sharedFields=[sharedOverheadShares,sharedOverheadBasis,sharedOverheadReviewed,sharedOverheadProposalId];
  if(sharedFields.some(v=>v!==undefined)&&(m.direction!=="supplier"||(!proposing&&decision!=="confirmed")||costCategory!=="shared_overhead"))return {error:"Shared allocation fields require a shared supplier proposal or confirmation",status:422};
  if(proposing&&(m.direction!=="supplier"||costCategory!=="shared_overhead"||expectedDirection!=="supplier"))return {error:"Shared supplier proposal required",status:422};
  if(proposal&&decision==="confirmed"&&costCategory!=="shared_overhead")return {error:"A shared proposal cannot be reclassified; reject it instead",status:409};
  if(m.direction!=="supplier"&&[costCategory,payrollOverlapReviewed,duplicateExpenseReviewed,siteOverheadReviewed].some(v=>v!==undefined))return {error:"Expense review requires a supplier invoice match",status:422};
  if(m.direction==="supplier"&&(decision==="confirmed"||proposing)){
   if(!["supplier","subcontractor","other_delivery","site_overhead","shared_overhead"].includes(costCategory)||payrollOverlapReviewed!==true||duplicateExpenseReviewed!==true||(costCategory==="site_overhead"&&siteOverheadReviewed!==true))
    return {error:"Confirm expense category, payroll-overlap review and duplicate-expense review",status:422};
   if(!m.contract_id||!m.site_id||!m.service_start||!m.service_end||m.service_end<m.service_start||!["HIGH","MEDIUM"].includes(m.confidence)||m.currency!=="AUD"||!["gst_exclusive","no_gst"].includes(m.tax_basis))
    return {error:"Supplier match evidence must be aligned, attributable and supported",status:422};
   const pair=await client.query("SELECT 1 FROM contracts c JOIN sites s ON s.tenant_id=c.tenant_id AND s.business_id=c.business_id WHERE c.tenant_id=$1 AND c.id=$2 AND s.id=$3 AND c.status='active' AND s.status='active'",[member.tenantId,m.contract_id,m.site_id]);
   if(!pair.rowCount)return {error:"Supplier match contract and site must belong to one business",status:422};
   expenseReview={costCategory,payrollOverlapReviewed:true,duplicateExpenseReviewed:true,...(costCategory==="site_overhead"?{siteOverheadReviewed:true}:{})};
   if(costCategory==="shared_overhead"){
    if(canonical?.method!=="canonical-invoice-0.1.0"||!canonical.preparedBy||!canonical.importedBy||canonical.preparedBy===canonical.importedBy||expectedDirection!=="supplier"||sharedOverheadReviewed!==true)return {error:"Independent canonical source and explicit shared allocation review required",status:422};
    if(proposing){
     if(canonical.preparedBy!==member.userId)return {error:"Only the independent source preparer may propose this allocation",status:403};
     if(proposal)return {error:"A proposal already exists; inspect or reject it",status:409};
     if(sharedOverheadProposalId!==undefined||typeof sharedOverheadBasis!=="string"||sharedOverheadBasis.trim().length<3||sharedOverheadBasis.length>1000)return {error:"Document the proposed allocation basis",status:422};
    }else{
     if(!proposal||typeof sharedOverheadProposalId!=="string"||proposal.id!==sharedOverheadProposalId||sharedOverheadShares!==undefined||sharedOverheadBasis!==undefined)return {error:"Load and approve the exact saved proposal; do not resubmit shares",status:422};
     if(proposal.proposedBy===member.userId||proposal.proposedBy!==canonical.preparedBy)return {error:"Independent proposal confirmer required",status:403};
     if(proposal.method!=="shared-proposal-0.1.0"||proposal.sourceAmount!==m.source_amount||proposal.contractId!==m.contract_id||proposal.anchorSiteId!==m.site_id||proposal.serviceStart!==m.service_start||proposal.serviceEnd!==m.service_end||proposal.taxBasis!==m.tax_basis)return {error:"Source evidence changed after proposal",status:409};
    }
    const allocation=reconcileSharedOverhead(m.source_amount,proposing?sharedOverheadShares:proposal.shares,{anchorSiteId:m.site_id});
    if(allocation.error)return {error:allocation.error,status:422};
    const sites=await client.query("SELECT s.id FROM sites s JOIN contracts c ON c.tenant_id=s.tenant_id AND c.business_id=s.business_id WHERE s.tenant_id=$1 AND c.id=$2 AND s.id=ANY($3::uuid[]) AND c.status='active' AND s.status='active' ORDER BY s.id FOR SHARE OF s,c",[member.tenantId,m.contract_id,allocation.shares.map(l=>l.siteId)]);
    if(sites.rowCount!==allocation.shares.length)return {error:"All shared allocation sites must belong to the same active contract business",status:422};
    if(proposing){
     const draft={id:randomUUID(),method:"shared-proposal-0.1.0",proposedBy:member.userId,sourceAmount:m.source_amount,contractId:m.contract_id,anchorSiteId:m.site_id,serviceStart:m.service_start,serviceEnd:m.service_end,taxBasis:m.tax_basis,shares:allocation.shares,basis:sharedOverheadBasis.trim()};
     await client.query("UPDATE match_reviews SET evidence=evidence||jsonb_build_object('sharedOverheadProposal',$1::jsonb) WHERE tenant_id=$2 AND id=$3",[JSON.stringify(draft),member.tenantId,m.id]);
     await appendAudit(client,member,"shared_overhead_proposed","match_review",m.id,reason.trim(),{proposalId:draft.id,shares:draft.shares,basis:draft.basis});
     return {proposal:draft,decision:"proposal_saved"};
    }
    expenseReview.sharedOverhead={method:"exact-site-shares-0.1.0",sourceAmount:m.source_amount,shares:allocation.shares,basisReviewed:true,proposalId:proposal.id};
    // Keep the allocation rationale in the protected audit chain, not report evidence.
   }
  }
  const updated=await client.query("UPDATE match_reviews SET decision=$1,reviewer_id=$2,reviewed_at=now(),evidence=CASE WHEN $5::jsonb IS NULL THEN evidence ELSE (CASE WHEN jsonb_typeof(evidence)='object' THEN evidence ELSE '{}'::jsonb END) || jsonb_build_object('deliveryExpenseReview',$5::jsonb) END WHERE id=$3 AND tenant_id=$4 AND decision IN ('candidate','held') RETURNING id,decision,reviewed_at",[decision,member.userId,req.params.matchId,member.tenantId,expenseReview?JSON.stringify(expenseReview):null]);
  if(!updated.rowCount)return null;
  await appendAudit(client,member,"invoice_match_decision","match_review",req.params.matchId,reason.trim(),   {decision,...(expenseReview?{deliveryExpenseReview:expenseReview}:{}),...(costCategory==="shared_overhead"&&decision==="confirmed"?{sharedOverheadProposalId:proposal.id}:{})});
  return updated.rows[0];
 });
 if(!result)return res.status(404).json({error:"Review candidate not found or already finalised"});
 if(result.error)return res.status(result.status).json({error:result.error});
 res.status(201).json({decision:result});
 }catch(e){next(e);}});

registerAttachmentQuarantineRoutes(app,membership);
registerInvoiceRoutes(app,membership);
registerSourceReconciliationRoutes(app,membership);
registerContributionRoutes(app,membership);

app.get("/v1/tenants/:tenantId/calculations/:runId",membership,requirePermission("calculations.read"),async(req,res,next)=>{try{
 const result=await withTenant(req.membership.tenantId,req.identity.subject,client=>client.query("SELECT id,contract_id,site_id,period_start,period_end,formula_version,inputs,outputs,completeness,created_at FROM calculation_runs WHERE id=$1 AND tenant_id=$2",[req.params.runId,req.membership.tenantId]));
 if(!result.rowCount)return res.status(404).json({error:"Calculation run not found"});
 res.json(result.rows[0]);
 }catch(e){next(e);}});
 

registerPayrollRoutes(app,membership);

app.use((err,req,res,next)=>{const id=randomUUID();const status=["23505","PPR01"].includes(err.code)?409:(Number.isInteger(err.status)&&err.status>=400&&err.status<500?err.status:500);const safeCode=typeof err.code==="string"&&/^[A-Z0-9_]{1,32}$/.test(err.code)?err.code:undefined;process.stderr.write(JSON.stringify({event:"request_error",reference:id,status,method:req.method,errorCode:safeCode,timestamp:new Date().toISOString()})+"\n");const publicErrors={400:"Invalid request",401:"Authentication required",403:"Request denied",404:"Resource not found",409:"Conflicting record; refresh and review the current state",413:"Request too large",415:"Unsupported media type",422:"Request could not be processed",429:"Too many requests"};res.status(status).json({error:publicErrors[status]||"Internal server error",reference:id});});
const port=Number(process.env.PORT||8080);
if(process.env.NODE_ENV!=="test"){
 const server=app.listen(port,()=>process.stdout.write("ProfitPilot API listening on "+port+"\n"));
 server.headersTimeout=10_000;
 server.requestTimeout=15_000;
 server.keepAliveTimeout=5_000;
 server.maxHeadersCount=64;
}
export default app;

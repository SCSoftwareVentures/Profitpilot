import "dotenv/config";
import express from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import {randomUUID,createHash} from "node:crypto";
import {pool,withTenant,health} from "./db.js";
import {authRequired,requireRole} from "./auth.js";
import {parseCsv,validateInvoiceRows} from "../src/engine.js";

const app=express();
app.disable("x-powered-by");
app.use(helmet());
app.use(cors({origin:(process.env.CORS_ORIGIN||"").split(",").map(x=>x.trim()).filter(Boolean),credentials:false,methods:["GET","POST"]}));
app.use(express.json({limit:"100kb"}));
app.use(rateLimit({windowMs:60_000,limit:100,standardHeaders:true,legacyHeaders:false}));
app.get("/health",async(req,res)=>{try{await health();res.json({status:"ok",database:"connected"});}catch{res.status(503).json({status:"unavailable"});}});
app.use("/v1",authRequired());

async function membership(req,res,next){
 const tenantId=req.params.tenantId;
 if(!/^[0-9a-f-]{36}$/i.test(tenantId))return res.status(400).json({error:"Invalid tenant ID"});
 try{
  const r=await pool.query("SELECT role,status FROM tenant_memberships tm JOIN users u ON u.id=tm.user_id JOIN tenants t ON t.id=tm.tenant_id WHERE tm.tenant_id=$1 AND u.auth_subject=$2 AND tm.status='active' AND u.status='active' AND t.status='active'",[tenantId,req.identity.subject]);
  if(!r.rowCount)return res.status(403).json({error:"No active membership for this tenant"});
  req.membership={tenantId,role:r.rows[0].role};next();
 }catch(e){next(e);}
}
app.get("/v1/me",async(req,res,next)=>{try{const r=await pool.query("SELECT t.id AS tenant_id,t.legal_name,tm.role FROM tenant_memberships tm JOIN users u ON u.id=tm.user_id JOIN tenants t ON t.id=tm.tenant_id WHERE u.auth_subject=$1 AND tm.status='active' AND u.status='active' AND t.status='active'",[req.identity.subject]);res.json({subject:req.identity.subject,memberships:r.rows});}catch(e){next(e);}});
app.get("/v1/tenants/:tenantId/contracts",membership,async(req,res,next)=>{try{const rows=await withTenant(req.membership.tenantId,async c=>(await c.query("SELECT id,customer_name,status FROM contracts WHERE tenant_id=$1 ORDER BY customer_name",[req.membership.tenantId])).rows);res.json({items:rows});}catch(e){next(e);}});
app.post("/v1/tenants/:tenantId/imports",membership,requireRole("owner","admin","analyst"),async(req,res,next)=>{
 try{
  const {sourceType,fileName,sha256,permissionReference,periodStart,periodEnd}=req.body||{};
  if(!["payroll","customer_invoice","supplier_invoice"].includes(sourceType)||typeof fileName!=="string"||fileName.length>255||!/^[a-f0-9]{64}$/i.test(sha256||"")||typeof permissionReference!=="string"||!permissionReference.trim()||!/^\d{4}-\d{2}-\d{2}$/.test(periodStart||"")||!/^\d{4}-\d{2}-\d{2}$/.test(periodEnd||"")||periodEnd<periodStart)return res.status(400).json({error:"Invalid import metadata"});
  const id=randomUUID();
  const result=await withTenant(req.membership.tenantId,async c=>c.query("INSERT INTO import_batches(id,tenant_id,source_type,source_period_start,source_period_end,permission_ref,status,file_sha256,file_name,created_by) SELECT $1,$2,$3,$4,$5,$6,'uploaded',$7,$8,u.id FROM users u WHERE u.auth_subject=$9 ON CONFLICT(tenant_id,file_sha256) DO NOTHING RETURNING id,status",[id,req.membership.tenantId,sourceType,periodStart,periodEnd,permissionReference.trim(),sha256.toLowerCase(),fileName,req.identity.subject]));
  if(!result.rowCount){const old=await withTenant(req.membership.tenantId,async c=>c.query("SELECT id,status FROM import_batches WHERE tenant_id=$1 AND file_sha256=$2",[req.membership.tenantId,sha256.toLowerCase()]));return res.status(200).json({batch:old.rows[0],idempotent:true});}
  res.status(201).json({batch:result.rows[0]});
 }catch(e){next(e);}
});
app.post("/v1/tenants/:tenantId/imports/:batchId/validate",membership,requireRole("owner","admin","analyst","reviewer"),async(req,res,next)=>{try{
 const result=await withTenant(req.membership.tenantId,async c=>{const r=await c.query("UPDATE import_batches SET status='review' WHERE id=$1 AND tenant_id=$2 AND status IN ('uploaded','failed') RETURNING id,status",[req.params.batchId,req.membership.tenantId]);return r.rows[0]||null;});
 if(!result)return res.status(404).json({error:"Batch not found or not eligible for validation"});
 res.status(202).json({batch:result,message:"Upload transport and isolated parser worker must be configured before production validation."});
 }catch(e){next(e);}});
app.post("/v1/tenants/:tenantId/matches/:matchId/decision",membership,requireRole("owner","admin","reviewer"),async(req,res,next)=>{try{
 const {decision,reason}=req.body||{};if(!["confirmed","rejected","held"].includes(decision)||typeof reason!=="string"||reason.trim().length<3||reason.length>2000)return res.status(400).json({error:"Decision and reason are required"});
 res.status(501).json({error:"Match decision persistence requires the match candidate table migration; no decision was recorded."});
 }catch(e){next(e);}});
app.post("/v1/tenants/:tenantId/calculations",membership,requireRole("owner","admin","analyst","reviewer"),async(req,res,next)=>{try{
 res.status(501).json({error:"Calculation persistence endpoint awaits immutable input/run migration. No calculation was recorded."});
 }catch(e){next(e);}});
app.use((err,req,res,next)=>{const id=randomUUID();process.stderr.write(JSON.stringify({event:"request_error",id,message:err.message})+"\n");res.status(500).json({error:"Internal server error",reference:id});});
const port=Number(process.env.PORT||8080);
if(process.env.NODE_ENV!=="test")app.listen(port,()=>process.stdout.write("ProfitPilot API listening on "+port+"\n"));
export default app;

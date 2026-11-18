import pg from "pg";
import {X509Certificate} from "node:crypto";
import {pathToFileURL} from "node:url";
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CATEGORIES=new Set(["suspected_compromise","data_exposure","integrity_failure","operational_emergency"]);
const COUNT_FIELDS=["activeTenantIncidents","temporarilyContainedActors","identitySecurityEvents24h","pendingOrRetryableScans","processingScans","pendingOrProcessingPromotions","failedPromotions"];
const exact=(v,keys)=>v!==null&&typeof v==="object"&&!Array.isArray(v)&&Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));
const validTime=s=>typeof s==="string"&&Number.isFinite(Date.parse(s));
export function parseSecurityPage(args){
 const [limit="50",cursor,...extra]=args;
 if(extra.length||typeof limit!=="string"||!/^(?:[1-9]|[1-9][0-9]|100)$/.test(limit))throw new Error("Invalid security page");
 if(cursor!==undefined&&!UUID.test(cursor))throw new Error("Invalid security cursor");
 return {limit:Number(limit),cursor:cursor?.toLowerCase()??null};
}
export function securityReaderConfig(env=process.env){
 if(env.NODE_TLS_REJECT_UNAUTHORIZED==="0"||env.PGOPTIONS||env.PGSERVICE||env.PGSERVICEFILE||env.PGSSLKEY||env.PGSSLCERT||env.PGSSLROOTCERT)throw new Error("Unsafe security reader environment");
 const url=new URL(env.SECURITY_READER_DATABASE_URL||"");
 const user=decodeURIComponent(url.username),password=decodeURIComponent(url.password);
 const ca=env.SECURITY_READER_DATABASE_CA?.trim();
 if(!["postgres:","postgresql:"].includes(url.protocol)||url.search||url.hash||!url.hostname||!url.pathname.slice(1)||user!=="profitpilot_security_reader"||password.length<24||!ca)throw new Error("Restricted verified TLS security reader required");
 const certs=ca.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g)||[];
 if(!certs.length||ca.replace(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g,"").trim())throw new Error("Invalid security reader CA");
 for(const pem of certs){const c=new X509Certificate(pem);if(!c.ca||Date.parse(c.validFrom)>Date.now()||Date.parse(c.validTo)<=Date.now())throw new Error("Invalid security reader CA");}
 return {connectionString:url.href,ssl:{ca,rejectUnauthorized:true},max:1,connectionTimeoutMillis:5000,statement_timeout:5000,application_name:"profitpilot_security_command"};
}
export function validateSnapshot(report,{limit=50,cursor=null}={}){
 if(!exact(report,["schemaVersion","observedAt","catalogVerified","status","counts","activeIncidents","nextCursor"])||report.schemaVersion!==1||!validTime(report.observedAt))throw new Error("Invalid security snapshot");
 if(report.catalogVerified===false){
  if(report.status!=="catalog_drift"||report.counts!==null||report.activeIncidents!==null||report.nextCursor!==null)throw new Error("Invalid drift report");
  return report;
 }
 if(report.catalogVerified!==true||!exact(report.counts,COUNT_FIELDS)||COUNT_FIELDS.some(k=>!Number.isSafeInteger(report.counts[k])||report.counts[k]<0)||!Array.isArray(report.activeIncidents)||report.activeIncidents.length>limit||report.activeIncidents.length>report.counts.activeTenantIncidents)throw new Error("Invalid security counters");
 const contained=report.counts.activeTenantIncidents>0||report.counts.temporarilyContainedActors>0;
 if(report.status!==(contained?"containment_active":"no_active_containment"))throw new Error("Invalid containment status");
 let prior=cursor;
 for(const incident of report.activeIncidents){
  if(!exact(incident,["incidentId","tenantId","category","activatedAt"])||typeof incident.incidentId!=="string"||!UUID.test(incident.incidentId)||incident.incidentId!==incident.incidentId.toLowerCase()||typeof incident.tenantId!=="string"||!UUID.test(incident.tenantId)||!CATEGORIES.has(incident.category)||!validTime(incident.activatedAt)||(prior!==null&&incident.incidentId<=prior))throw new Error("Invalid incident metadata");
  prior=incident.incidentId;
 }
 if(report.nextCursor!==null&&(report.activeIncidents.length!==limit||report.nextCursor!==prior))throw new Error("Invalid next incident cursor");
 return report;
}
export async function readSecuritySnapshot(db,page){
 const result=await db.query("SELECT private.security_command_snapshot($1,$2) AS report",[page.limit,page.cursor]);
 if(result.rowCount!==1)throw new Error("Security snapshot unavailable");
 return validateSnapshot(result.rows[0].report,page);
}
async function main(){
 const page=parseSecurityPage(process.argv.slice(2)),pool=new pg.Pool(securityReaderConfig());
 try{
  const client=await pool.connect();
  try{
   const role=(await client.query("SELECT session_user AS login,current_user AS runtime,coalesce((SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()),false) AS tls")).rows[0];
   if(role?.login!=="profitpilot_security_reader"||role.runtime!=="profitpilot_security_reader"||role.tls!==true)throw new Error("Unexpected reader authority");
   const snapshot=await readSecuritySnapshot(client,page);
   process.stdout.write(JSON.stringify(snapshot)+"\n");
   if(!snapshot.catalogVerified)process.exitCode=2;
  }finally{client.release();}
 }finally{await pool.end();}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 main().catch(()=>{process.stderr.write("Security command snapshot unavailable; details suppressed.\n");process.exitCode=1;});
}

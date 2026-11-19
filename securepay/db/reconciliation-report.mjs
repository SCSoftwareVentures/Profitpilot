// Read-only reporting, except for the database's append-only access audit.
import {createHmac,randomUUID,createHash,sign,verify} from "node:crypto";
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const hex=/^[0-9a-f]{64}$/;
const integer=/^-?(0|[1-9][0-9]*)$/;
const isId=x=>typeof x==="string"&&uuid.test(x);
const cents=x=>typeof x==="string"&&integer.test(x)&&x.length<=40;
function validate(r){
 if(!r||r.schema!=="securepay-report-v1"||r.mode!=="sandbox"||r.moneyMoved!==false||!isId(r.tenantId)||!isId(r.reportId)||!Number.isFinite(Date.parse(r.generatedAt))||!Array.isArray(r.milestones)||r.milestones.length>250||r.checkpoint?.tenantId!==r.tenantId||!cents(r.checkpoint.last_seq)||BigInt(r.checkpoint.last_seq)<0n||!hex.test(r.checkpoint.last_hash))throw Error("Invalid sandbox report");
 const seen=new Set();
 for(const m of r.milestones){
  if(!isId(m.milestoneId)||seen.has(m.milestoneId)||!["planned","submitted","disputed","approved","release_pending","released","settled","cancelled"].includes(m.status)||!["unfunded","funded","held","released","settled"].includes(m.fundingStatus)||
   ![m.caseId,m.settlementId].every(v=>v===null||isId(v))||![null,"open","decided","appealed","final","authorized","settled"].includes(m.caseStatus)||
   ![m.fundedCents,m.payoutCents,m.refundCents,m.remainingCents,m.unresolvedIssues].every(cents)||typeof m.journalVerified!=="boolean"||!Array.isArray(m.legs)||m.legs.length>2)throw Error("Invalid milestone report");
  seen.add(m.milestoneId);
  for(const l of m.legs)if(!["payout","refund"].includes(l.kind)||!["pending","submitted","unknown","not_executed","confirmed"].includes(l.status)||!cents(l.amountCents)||BigInt(l.amountCents)<=0n||!Number.isInteger(l.attempts)||l.attempts<0||l.attempts>4)throw Error("Invalid payment leg");
 }
 return r;
}
export async function loadReconciliationReport(pool,{tenantId,actorId,key}){
 if(!pool?.connect||!isId(tenantId)||!isId(actorId)||!Buffer.isBuffer(key)||key.length!==32)throw Error("Reporting authority unavailable");
 const client=await pool.connect();
 try{
  await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ");
  const id=randomUUID(),expiry=Math.floor(Date.now()/1000)+20;
  const signature=createHmac("sha256",key).update(["sp-report-v1",id,tenantId,actorId,expiry].join(":")).digest("hex");
  const {rows:[row]}=await client.query("SELECT securepay_private.reconciliation_report($1::uuid,$2::uuid,$3::uuid,$4::bigint,$5::text) AS report",[id,tenantId,actorId,expiry,signature]);
  if(row?.report?.tenantId!==tenantId||row.report.reportId!==id)throw Error("Reporting denied");
  const report=validate(row.report);
  await client.query("COMMIT");return report;
 }catch(err){try{await client.query("ROLLBACK");}catch{}throw err;}finally{client.release();}
}
export function summarizeReport(report){
 validate(report);
 const totals={fundedCents:0n,payoutCents:0n,refundCents:0n,remainingCents:0n,unresolvedIssues:0n};
 let mismatches=0,uncertainLegs=0,disputedMilestones=0;
 for(const m of report.milestones){
  for(const k of Object.keys(totals))totals[k]+=BigInt(m[k]);
  if(!m.journalVerified)mismatches++;
  uncertainLegs+=m.legs.filter(l=>["submitted","unknown","not_executed"].includes(l.status)).length;
  if(m.status==="disputed")disputedMilestones++;
 }
 return {...Object.fromEntries(Object.entries(totals).map(([k,v])=>[k,String(v)])),milestoneCount:report.milestones.length,mismatches,uncertainLegs,disputedMilestones};
}
const canonical=value=>Array.isArray(value)?"["+value.map(canonical).join(",")+"]":value&&typeof value==="object"?"{"+Object.keys(value).sort().map(k=>JSON.stringify(k)+":"+canonical(value[k])).join(",")+"}":JSON.stringify(value);
export function signReport(report,privateKey){
 validate(report);
 if(privateKey?.asymmetricKeyType!=="ed25519"||privateKey.type!=="private")throw Error("Independent Ed25519 export key required");
 const body=canonical(report),digest=createHash("sha256").update(body).digest("hex");
 return {format:"securepay-signed-report-v1",report,digest,signature:sign(null,Buffer.from("securepay-report-v1:"+digest),privateKey).toString("base64")};
}
export function verifySignedReport(envelope,publicKey){
 try{
  if(envelope.format!=="securepay-signed-report-v1"||publicKey?.asymmetricKeyType!=="ed25519"||publicKey.type!=="public")return false;
  validate(envelope.report);
  const digest=createHash("sha256").update(canonical(envelope.report)).digest("hex");
  return digest===envelope.digest&&verify(null,Buffer.from("securepay-report-v1:"+digest),publicKey,Buffer.from(envelope.signature,"base64"));
 }catch{return false;}
}
export function reportCSV(report){
 validate(report);
 const fields=["milestoneId","status","fundingStatus","fundedCents","payoutCents","refundCents","remainingCents","journalVerified","unresolvedIssues"];
 // Values are constrained by validate; quote and neutralize spreadsheet formula prefixes.
 const cell=v=>{const s=String(v);return '"'+(/^[=+@-]/.test(s)?"'"+s:s).replaceAll('"','""')+'"';};
 return "mode,"+fields.join(",")+"\r\n"+report.milestones.map(m=>["sandbox",...fields.map(k=>m[k])].map(cell).join(",")).join("\r\n")+"\r\n";
}
const esc=s=>String(s).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;").replaceAll("'","&#39;");
const aud=s=>{const n=BigInt(s),a=n<0n?-n:n;return (n<0n?"-":"")+"$"+String(a/100n).replace(/\B(?=(\d{3})+(?!\d))/g,",")+"."+String(a%100n).padStart(2,"0");};
export function renderReconciliationDashboard(report,{buyerSummary=false}={}){
 const summary=summarizeReport(report);
 const metrics=[["Confirmed funding",aud(summary.fundedCents)],["Confirmed payouts",aud(summary.payoutCents)],["Confirmed refunds",aud(summary.refundCents)],["Remaining",aud(summary.remainingCents)],["Journal mismatches",summary.mismatches],["Unresolved issues",summary.unresolvedIssues],["Uncertain legs",summary.uncertainLegs],["Disputed milestones",summary.disputedMilestones]];
 const rows=report.milestones.map(m=>"<tr>"+[m.milestoneId,m.status,m.fundingStatus,aud(m.fundedCents),aud(m.payoutCents),aud(m.refundCents),aud(m.remainingCents),m.journalVerified?"Matched":"Mismatch",m.unresolvedIssues,m.legs.map(l=>l.kind+": "+l.status+" ("+l.attempts+")").join("; ")||"None"].map(v=>"<td>"+esc(v)+"</td>").join("")+"</tr>").join("");
 return "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\"><title>SecurePay reconciliation</title><style>body{font:16px system-ui;margin:0;background:#f4f6fa;color:#192638}main{max-width:1200px;margin:auto;padding:24px}h1{font-size:28px}.notice{border-left:4px solid #a16011;padding:12px;background:#fff5e6}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:20px 0}.metric{background:white;padding:16px;border:1px solid #dbe2ea;border-radius:8px}.metric strong{display:block;font-size:22px;margin-top:6px}.table{overflow:auto;background:white}table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:10px;border-bottom:1px solid #dbe2ea;white-space:nowrap}th{background:#e8edf4}small{overflow-wrap:anywhere}</style></head><body><main><h1>SecurePay | Reconciliation</h1><p class=\"notice\">SANDBOX ONLY — synthetic transactions. No money moved. Not a bank statement.</p><p>Snapshot: "+esc(report.generatedAt)+" · "+summary.milestoneCount+" milestones</p><section class=\"grid\">"+metrics.map(([label,value])=>"<div class=\"metric\">"+esc(label)+"<strong>"+esc(value)+"</strong></div>").join("")+"</section>"+(buyerSummary?"<p>Buyer summary: operational identifiers omitted. Use only approved synthetic data.</p>":"<div class=\"table\"><table><thead><tr><th>Milestone</th><th>State</th><th>Funding</th><th>Funded</th><th>Payout</th><th>Refund</th><th>Remaining</th><th>Journal</th><th>Issues</th><th>Payment legs</th></tr></thead><tbody>"+rows+"</tbody></table></div><p><small>Audit checkpoint "+esc(report.checkpoint.last_seq)+": "+esc(report.checkpoint.last_hash)+"</small></p>")+"</main></body></html>";
}

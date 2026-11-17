// Privacy-minimised process-local detection. Never accept request data into the sink.
const categories=Object.freeze({
 authentication_denied:20,
 authorization_denied:10,
 rate_limited:10,
 malformed_or_oversized_request:20,
 request_aborted:20,
 service_error:5,
 dependency_unavailable:3,
 account_revocation:5,
 permission_changed:5,
 sensitive_privacy_access:10,
 security_audit_access:10
});
const sensitiveRoutes=new Map([
 ["POST /v1/me/sessions/revoke-all","account_revocation"],
 ["DELETE /v1/me/sessions/:jti","account_revocation"],
 ["POST /v1/tenants/:tenantId/security/permissions/overrides","permission_changed"],
 ["DELETE /v1/tenants/:tenantId/security/permissions/overrides/:userId/:permissionKey","permission_changed"],
 ["POST /v1/tenants/:tenantId/privacy/requests/:requestId/export","sensitive_privacy_access"],
 ["POST /v1/tenants/:tenantId/privacy/requests/:requestId/read-details","sensitive_privacy_access"],
 ["GET /v1/tenants/:tenantId/security/permissions","security_audit_access"],
 ["GET /v1/tenants/:tenantId/security/audit","security_audit_access"]
]);
const maxCount=1_000_000_000;
export function createSecurityTelemetry({clock=Date.now,emit=event=>process.stderr.write(JSON.stringify(event)+"\n"),windowMs=60_000}={}){
 if(!Number.isSafeInteger(windowMs)||windowMs<1000||windowMs>300000)throw Error("Invalid telemetry window");
 let start=null,counts=Object.create(null),alerted=new Set();
 function output(record){
  // Telemetry failure must not expose a request or crash the API. The deployment
  // must independently monitor its log collector and missing telemetry.
  try{emit(record);}catch{}
 }
 function roll(now){
  if(!Number.isSafeInteger(now)||now<0)return false;
  const bucket=Math.floor(now/windowMs)*windowMs;
  if(start!==null&&bucket<start)return false; // no backward-clock bucket reset
  if(start===null){start=bucket;return true;}
  if(bucket===start)return true;
  if(Object.keys(counts).length)output({event:"security_window",version:1,windowStart:new Date(start).toISOString(),windowMs,counts:{...counts}});
  start=bucket;counts=Object.create(null);alerted=new Set();
  return true;
 }
 return Object.freeze({
  record(category){
   if(!Object.hasOwn(categories,category)||!roll(clock()))return false;
   const count=counts[category]=Math.min((counts[category]||0)+1,maxCount);
   if(count>=categories[category]&&!alerted.has(category)){
    alerted.add(category);
    output({event:"security_threshold",version:1,category,count,threshold:categories[category],windowStart:new Date(start).toISOString(),windowMs});
   }
   return true;
  },
  flush(){return roll(clock());}
 });
}
export function securityTelemetryMiddleware(telemetry){
 return (req,res,next)=>{
  // Inspect only the scope here; neither raw path nor any header, subject, IP,
  // token, body, query, exception or tenant identifier is passed to telemetry.
  const scope=req.path==="/health"?"health":req.path==="/v1"||req.path.startsWith("/v1/")?"api":null;
  if(!scope)return next();
  let finished=false;
  res.once("finish",()=>{
   finished=true;
   const status=res.statusCode;
   if(status===401)telemetry.record("authentication_denied");
   else if(status===403)telemetry.record("authorization_denied");
   else if(status===429)telemetry.record("rate_limited");
   else if([400,413,415,422].includes(status))telemetry.record("malformed_or_oversized_request");
   else if(status===503)telemetry.record("dependency_unavailable");
   else if(status>=500)telemetry.record("service_error");
   else if(status>=200&&status<300&&scope==="api"){
    const category=sensitiveRoutes.get(req.method+" "+req.route?.path);
    if(category)telemetry.record(category);
   }
  });
  res.once("close",()=>{if(!finished)telemetry.record("request_aborted");});
  next();
 };
}

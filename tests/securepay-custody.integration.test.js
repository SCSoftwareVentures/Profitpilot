import test from "node:test";
import assert from "node:assert/strict";
import {createServer} from "node:http";
import {createHash,generateKeyPairSync,randomUUID} from "node:crypto";
import {SignJWT,exportJWK} from "jose";
import pg from "pg";
const enabled=Boolean(process.env.TEST_ADMIN_DATABASE_URL&&process.env.TEST_APP_DATABASE_URL);
test("S9 sealed original bytes: scanner-required, immutable, tenant isolated",{skip:!enabled},async()=>{
 const a="abababab-abab-4bab-8bab-abababababab",b="cdcdcdcd-cdcd-4dcd-8dcd-cdcdcdcdcdcd";
 const owner="efefefef-efef-4fef-8fef-efefefefefef",reader="89898989-8989-4989-8989-898989898989",foreign="78787878-7878-4787-8787-787878787878";
 const issuer="https://securepay-s9-ci.invalid/",audience="securepay-s9-api";
 const {privateKey,publicKey}=generateKeyPairSync("rsa",{modulusLength:2048});
 const jwk=await exportJWK(publicKey);Object.assign(jwk,{kid:"s9-key",alg:"RS256",use:"sig"});
 const jwks=createServer((req,res)=>{res.writeHead(req.url==="/jwks"?200:404,{"content-type":"application/json"}).end(JSON.stringify({keys:[jwk]}));});
 await new Promise(resolve=>jwks.listen(0,"127.0.0.1",resolve));
 process.env.NODE_ENV="test";process.env.DATABASE_URL=process.env.TEST_APP_DATABASE_URL;
 process.env.AUTH_ISSUER=issuer;process.env.AUTH_AUDIENCE=audience;
 process.env.AUTH_JWKS_URL="http://127.0.0.1:"+jwks.address().port+"/jwks";
 process.env.MALWARE_SCAN_MODE="";
 const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
 let api,scannedApi,pool;
 try{
  await admin.query("INSERT INTO tenants(id,legal_name) VALUES($1,'S9 test A'),($2,'S9 test B') ON CONFLICT(id) DO NOTHING",[a,b]);
  await admin.query("INSERT INTO users(id,auth_subject,email) VALUES($1,'s9-owner','s9-owner@invalid'),($2,'s9-reader','s9-reader@invalid'),($3,'s9-foreign','s9-foreign@invalid') ON CONFLICT(auth_subject) DO NOTHING",[owner,reader,foreign]);
  await admin.query("INSERT INTO tenant_memberships(tenant_id,user_id,role,status) VALUES($1,$2,'owner','active'),($1,$3,'read_only','active'),($4,$5,'owner','active') ON CONFLICT(tenant_id,user_id) DO UPDATE SET role=EXCLUDED.role,status=EXCLUDED.status",[a,owner,reader,b,foreign]);
  const {default:app}=await import("../server/index.js");
  const d=await import("../server/db.js");pool=d.pool;
  api=createServer(app);await new Promise(resolve=>api.listen(0,"127.0.0.1",resolve));
  const caseA=(await admin.query("INSERT INTO securepay_case_rehearsals(tenant_id,client_request_id,job_reference,claim_reference,opened_by) VALUES($1,gen_random_uuid(),'job.s9.ci','claim.s9.ci',$2) RETURNING id",[a,owner])).rows[0].id;
  const evidenceA=(await admin.query("INSERT INTO securepay_evidence_rehearsals(tenant_id,case_id,client_request_id,recorded_by,evidence_type,evidence_reference) VALUES($1,$2,gen_random_uuid(),$3,'claim_reported','evidence.s9.ci') RETURNING id",[a,caseA,owner])).rows[0].id;
  const caseB=(await admin.query("INSERT INTO securepay_case_rehearsals(tenant_id,client_request_id,job_reference,claim_reference,opened_by) VALUES($1,gen_random_uuid(),'job.s9.foreign','claim.s9.foreign',$2) RETURNING id",[b,foreign])).rows[0].id;
  const evidenceB=(await admin.query("INSERT INTO securepay_evidence_rehearsals(tenant_id,case_id,client_request_id,recorded_by,evidence_type,evidence_reference) VALUES($1,$2,gen_random_uuid(),$3,'claim_reported','evidence.s9.foreign') RETURNING id",[b,caseB,foreign])).rows[0].id;
  const {default:express}=await import("express");
  const {authRequired,requireRole}=await import("../server/auth.js");
  const {installSecurepayFileCustodyRoutes}=await import("../server/securepay-file-custody-storage.js");
  const scanApp=express();scanApp.use("/v1",authRequired());
  scanApp.use("/v1",express.json({limit:"100kb",inflate:false}));
  const member=async(req,res,next)=>{try{
   const t=req.params.tenantId;
   const r=await d.withTenant(t,req.identity.subject,c=>c.query("SELECT tm.role FROM tenant_memberships tm JOIN users u ON u.id=tm.user_id JOIN tenants t ON t.id=tm.tenant_id WHERE tm.tenant_id=$1 AND u.auth_subject=$2 AND tm.status='active' AND u.status='active' AND t.status='active'",[t,req.identity.subject]));
   if(!r.rowCount)return res.status(403).json({error:"No membership"});
   req.membership={tenantId:t,role:r.rows[0].role};next();
  }catch(e){next(e);}};
  let scans=0;
  installSecurepayFileCustodyRoutes(scanApp,{membership:member,requireRole,withTenant:d.withTenant,
   scannerEnabled:true,scan:async(bytes,opts)=>{scans++;assert.equal(opts.enabled,true);
    return bytes.toString().includes("FAKE_INFECTED")?"infected":
      bytes.toString().includes("SCAN_UNAVAILABLE")?"unavailable":"scanner_reported_clean";}});
  scanApp.use((err,_req,res,_next)=>res.status(err.status||500).json({error:err.message}));
  scannedApi=createServer(scanApp);await new Promise(resolve=>scannedApi.listen(0,"127.0.0.1",resolve));
  const bytes=Buffer.from("Harmless S9 synthetic dispute document.\n");
  const hash=createHash("sha256").update(bytes).digest("hex");
  const token=async subject=>new SignJWT({}).setProtectedHeader({alg:"RS256",kid:jwk.kid})
   .setIssuer(issuer).setAudience(audience).setSubject(subject).setIssuedAt().setExpirationTime("5m").sign(privateKey);
  const route="/v1/tenants/"+a+"/prototype/securepay-cases/"+caseA+"/evidence/"+evidenceA+"/custody-file";
  const fetchData=async(which,path,{method="POST",subject="s9-owner",data=bytes,sha,reqId=randomUUID(),type="text/plain",encoding}={})=>{
   const headers={authorization:"Bearer "+await token(subject)};
   if(method==="POST"){Object.assign(headers,{"content-type":"application/octet-stream","x-client-request-id":reqId,
    "x-evidence-sha256":sha||createHash("sha256").update(data).digest("hex"),"x-evidence-media-type":type});if(encoding)headers["content-encoding"]=encoding;}
   const response=await fetch("http://127.0.0.1:"+which.address().port+path,{method,headers,body:method==="POST"?data:undefined});
   return {status:response.status,body:await response.json()};
  };
  assert.equal((await fetchData(api,route)).status,503,"real scanner disabled: fail closed before bytes are saved");
  assert.equal((await fetchData(scannedApi,route,{subject:"s9-reader"})).status,403);
  assert.equal((await fetchData(scannedApi,route,{data:Buffer.from("FAKE_INFECTED")})).status,422);
  assert.equal((await fetchData(scannedApi,route,{data:Buffer.from("SCAN_UNAVAILABLE")})).status,503);
  assert.equal((await fetchData(scannedApi,route,{sha:"a".repeat(64)})).status,422);
  assert.equal((await fetchData(scannedApi,route,{type:"text/html"})).status,400);
  assert.equal((await fetchData(scannedApi,route,{encoding:"gzip"})).status,415);
  const reqId=randomUUID();
  const written=await fetchData(scannedApi,route,{reqId});
  assert.equal(written.status,201,JSON.stringify(written));
  assert.equal(written.body.item.sha256,hash);
  assert.equal(written.body.item.origin_verified,false);
  assert.equal(written.body.independentCustodyVerified,false);
  assert.equal(Object.hasOwn(written.body.item,"original_bytes"),false);
  assert.equal((await fetchData(scannedApi,route,{reqId})).status,200);
  assert.equal((await fetchData(scannedApi,route)).status,409);
  assert.equal((await fetchData(scannedApi,route,{reqId,data:Buffer.from("Altered S9 bytes!")})).status,409);
  const retrieved=await fetchData(scannedApi,route,{method:"GET"});
  assert.equal(retrieved.status,200);assert.equal(retrieved.body.received,true);
  assert.equal(Object.hasOwn(retrieved.body.item,"original_bytes"),false);
  assert.equal((await fetchData(scannedApi,route,{method:"GET",subject:"s9-reader"})).status,403);
  assert.equal((await fetchData(scannedApi,"/v1/tenants/"+a+"/prototype/securepay-cases/"+caseB+"/evidence/"+evidenceA+"/custody-file")).status,404);
  assert.equal((await fetchData(scannedApi,"/v1/tenants/"+a+"/prototype/securepay-cases/"+caseB+"/evidence/"+evidenceB+"/custody-file",{method:"GET"})).status,404);
  assert.ok(scans>=4);
  const valid=await admin.query("SELECT sha256=encode(public.digest(original_bytes,'sha256'),'hex') AS exact FROM securepay_evidence_custody_receipts WHERE tenant_id=$1 AND evidence_id=$2",[a,evidenceA]);
  assert.equal(valid.rows[0].exact,true);
  await assert.rejects(()=>d.withTenant(a,"s9-owner",c=>c.query("SELECT original_bytes FROM securepay_evidence_custody_receipts")),/permission denied/i);
  await assert.rejects(()=>d.withTenant(a,"s9-owner",c=>c.query("DELETE FROM securepay_evidence_custody_receipts WHERE id=$1",[written.body.item.id])),/permission denied|append-only/i);
  await assert.rejects(()=>d.withTenant(a,"s9-owner",c=>c.query("UPDATE securepay_evidence_custody_receipts SET sha256=$1 WHERE id=$2",["a".repeat(64),written.body.item.id])),/permission denied|append-only/i);
  await assert.rejects(()=>d.withTenant(a,"s9-owner",c=>c.query("INSERT INTO securepay_evidence_custody_receipts(tenant_id,case_id,evidence_id,client_request_id,received_by,sha256,byte_count,media_type,original_bytes) VALUES($1,$2,$3,gen_random_uuid(),private.actor_id(),$4,$5,'text/plain',$6)",[a,caseA,evidenceB,hash,bytes.length,bytes])),/foreign key|row-level security|permission denied/i);
 }finally{
  if(scannedApi)await new Promise(resolve=>scannedApi.close(resolve));
  if(api)await new Promise(resolve=>api.close(resolve));
  if(pool)await pool.end();
  await admin.end();
  await new Promise(resolve=>jwks.close(resolve));
 }
});

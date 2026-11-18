import test from "node:test";
import assert from "node:assert/strict";
import {createServer} from "node:http";
import {randomUUID,createHash} from "node:crypto";
import {generateKeyPair,exportJWK,SignJWT} from "jose";
import pg from "pg";

test("actual authenticated privacy case and release API",{skip:!process.env.TEST_ADMIN_DATABASE_URL||!process.env.TEST_APP_DATABASE_URL,timeout:60000},async()=>{
 const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL,max:2});
 const t=randomUUID(),other=randomUUID(),owner=randomUUID(),reviewer=randomUUID(),analyst=randomUUID(),reader=randomUUID();
 const identities={owner,reviewer,analyst,reader};const subjects=Object.fromEntries(Object.entries(identities).map(([k,v])=>[k,"ci-sensitive-"+v]));
 const {publicKey,privateKey}=await generateKeyPair("RS256"),jwk=await exportJWK(publicKey);
 Object.assign(jwk,{kid:"ci-sensitive",alg:"RS256",use:"sig"});
 const keys=createServer((_req,res)=>{res.setHeader("Content-Type","application/json");res.end(JSON.stringify({keys:[jwk]}));});
 await new Promise(r=>keys.listen(0,"127.0.0.1",r));
 process.env.NODE_ENV="test";process.env.SYNTHETIC_SECURITY_UI_ENABLED="true";process.env.DATABASE_URL=process.env.TEST_APP_DATABASE_URL;
 process.env.AUTH_ISSUER="https://sensitive-ci.invalid/";process.env.AUTH_AUDIENCE="profitpilot-api";
 process.env.AUTH_JWKS_URL="http://127.0.0.1:"+keys.address().port+"/jwks";
 const [{default:app},{pool:runtime}]=await Promise.all([import("../server/index.js"),import("../server/db.js")]);
 const api=createServer(app);await new Promise(r=>api.listen(0,"127.0.0.1",r));
 const base="http://127.0.0.1:"+api.address().port,authTime=Math.floor(Date.now()/1000)-10;
 const auth=async(role,opts={})=>new SignJWT({email:"verified-"+role+"@example.invalid",email_verified:true,amr:["mfa"],auth_time:authTime,sid:"ci-sensitive-"+role,...opts})
  .setProtectedHeader({alg:"RS256",kid:jwk.kid}).setIssuer(process.env.AUTH_ISSUER).setAudience(process.env.AUTH_AUDIENCE).setSubject(subjects[role]).setIssuedAt().setExpirationTime("5m").sign(privateKey);
 async function call(role,path,{tenant=t,body,claims}={}){
  const r=await fetch(base+"/v1/tenants/"+tenant+path,{method:body===undefined?"GET":"POST",headers:{authorization:"Bearer "+await auth(role,claims),...(body===undefined?{}:{"content-type":"application/json"})},body:body===undefined?undefined:JSON.stringify(body)});
  assert.match(r.headers.get("cache-control"),/no-store/);
  return {status:r.status,data:await r.json()};
 }
 const expect=async(role,path,status,opts={})=>{const result=await call(role,path,opts);assert.equal(result.status,status,path+" / "+role+" "+JSON.stringify(result.data));return result.data;};
 const hash=s=>createHash("sha256").update(s).digest("hex");
 try{
  const screen=await fetch(base+"/candidate/security/");
  assert.equal(screen.status,200);assert.match(screen.headers.get("cache-control"),/no-store/);assert.match(screen.headers.get("content-security-policy"),/script-src 'self'/);
  assert.match(await screen.text(),/Non-production, synthetic records only/);
  const script=await fetch(base+"/candidate/security/app.js");assert.equal(script.status,200);assert.match(await script.text(),/credentials:"omit"/);
  await admin.query("INSERT INTO public.tenants(id,legal_name) VALUES($1,'Synthetic privacy operator API'),($2,'Synthetic privacy operator other')",[t,other]);
  for(const [role,id] of Object.entries(identities))await admin.query("INSERT INTO public.users(id,auth_subject,email) VALUES($1,$2,$3)",[id,subjects[role],"old-"+role+"@example.invalid"]);
  for(const [role,id] of Object.entries(identities))await admin.query("INSERT INTO public.tenant_memberships(tenant_id,user_id,role) VALUES($1,$2,$3)",[t,id,role==="reader"?"read_only":role==="reviewer"?"admin":role]);
  await admin.query("INSERT INTO public.tenant_memberships(tenant_id,user_id,role) VALUES($1,$2,'admin')",[other,reviewer]);
  // Privacy requests are status-only; evidence is kept in an approved
  // assisted process. No arbitrary target or third-party data is disclosed.
  const caseId=randomUUID(),casePath="/privacy/cases/"+caseId;
  const requestCase={action:"request",kind:"access",confirm:true};
  const opened=await expect("reader",casePath,200,{body:requestCase});
  assert.equal(opened.status,"received");assert.equal(opened.kind,"access");
  assert.ok(opened.internalReviewTarget);assert.equal(opened.escalationDue,false);
  await expect("reader",casePath,409,{body:requestCase});
  await expect("analyst",casePath,403);
  await expect("reviewer",casePath,403,{tenant:other});
  await expect("reader",casePath,403,{body:{action:"acknowledge",confirm:true}});
  await expect("owner",casePath,403,{body:{action:"resolve",reasonCode:"fulfilled",evidenceDigest:hash("synthetic-response"),confirm:true}});
  assert.equal((await expect("owner",casePath,200,{body:{action:"acknowledge",confirm:true}})).status,"acknowledged");
  assert.equal((await expect("owner",casePath,200,{body:{action:"resolve",reasonCode:"fulfilled",evidenceDigest:hash("synthetic-response"),confirm:true}})).status,"resolved");
  const resultCase=await expect("reader",casePath,200);
  assert.equal(resultCase.status,"resolved");assert.equal(resultCase.reasonCode,"fulfilled");
  assert.ok(!Object.hasOwn(resultCase,"evidenceDigest")&&!Object.hasOwn(resultCase,"openedBy"));
  await expect("owner",casePath,409,{body:{action:"resolve",reasonCode:"fulfilled",evidenceDigest:hash("other"),confirm:true}});
  const staffPath="/privacy/cases/"+randomUUID();
  assert.equal((await expect("owner",staffPath,200,{body:{action:"intake",kind:"correction",evidenceDigest:hash("verified-assisted-intake"),confirm:true}})).status,"received");
  await expect("reader",staffPath,403);
  await expect("owner",staffPath,200,{body:{action:"acknowledge",confirm:true}});
  await expect("owner",staffPath,403,{body:{action:"refuse",reasonCode:"identity_not_verified",evidenceDigest:hash("synthetic-refusal"),confirm:true}});
  assert.equal((await expect("reviewer",staffPath,200,{body:{action:"refuse",reasonCode:"identity_not_verified",evidenceDigest:hash("synthetic-refusal"),confirm:true}})).status,"refused");
  await assert.rejects(()=>runtime.query("SELECT * FROM private.privacy_rights_cases"),e=>e.code==="42501");

  // Exact authenticated privacy response authorization. No plaintext, recipient
  // address, key bytes or external transport are admitted through the API.
  const deliveryOrder=randomUUID(),deliveryPath=casePath+"/deliveries/"+deliveryOrder;
  const deliveryInput={recipientType:"self",recipientKeyDigest:hash("synthetic recipient"),senderKeyDigest:hash("synthetic sender"),authorityDigest:hash("synthetic authority"),redactionDigest:hash("synthetic redaction"),responseDigest:hash("synthetic response"),envelopeDigest:hash("synthetic envelope")};
  await expect("reader",deliveryPath+"/preview",403,{body:deliveryInput});
  await expect("reviewer",deliveryPath+"/preview",403,{tenant:other,body:deliveryInput});
  await expect("owner",deliveryPath+"/preview",403,{body:deliveryInput,claims:{amr:["pwd"]}});
  await expect("owner",deliveryPath+"/preview",400,{body:{...deliveryInput,plaintext:"not admitted"}});
  await expect("owner",staffPath+"/deliveries/"+randomUUID()+"/preview",403,{body:{...deliveryInput,recipientType:"authorized_representative"}});
  const deliveryPreview=await expect("owner",deliveryPath+"/preview",200,{body:deliveryInput});
  assert.equal(deliveryPreview.deliveryVerified,false);
  const deliveryAction=(step,changes={})=>({...deliveryInput,scopeDigest:deliveryPreview.scopeDigest,step,confirm:true,...changes});
  await expect("owner",deliveryPath,403,{body:deliveryAction("consume")});
  await expect("owner",deliveryPath,403,{body:deliveryAction("request",{scopeDigest:hash("forged")})});
  assert.equal((await expect("owner",deliveryPath,200,{body:deliveryAction("request")})).status,"requested");
  await expect("reader",deliveryPath,403);
  await expect("reviewer",deliveryPath,403,{tenant:other});
  await expect("owner",deliveryPath,403,{body:deliveryAction("approve")});
  await expect("reviewer",deliveryPath,403,{body:deliveryAction("approve",{recipientKeyDigest:hash("wrong recipient")})});
  assert.equal((await expect("reviewer",deliveryPath,200,{body:deliveryAction("approve")})).status,"approved");
  assert.equal((await expect("owner",deliveryPath,200)).status,"approved");
  await expect("reviewer",deliveryPath,403,{body:deliveryAction("consume")});
  await expect("owner",deliveryPath,403,{body:deliveryAction("consume",{envelopeDigest:hash("wrong envelope")})});
  const released=await expect("owner",deliveryPath,200,{body:deliveryAction("consume")});
  assert.equal(released.status,"release-authorized");assert.equal(released.deliveryVerified,false);
  assert.ok(released.releaseAuthorizedAt);assert.ok(!Object.hasOwn(released,"responseDigest"));
  await expect("owner",deliveryPath,409,{body:deliveryAction("consume")});
  assert.equal((await expect("reviewer",deliveryPath,200)).status,"release-authorized");
  await assert.rejects(()=>runtime.query("SELECT * FROM private.privacy_delivery_requests"),e=>e.code==="42501");
  await assert.rejects(()=>runtime.query("SELECT * FROM private.privacy_delivery_authorizations"),e=>e.code==="42501");

  // Evidence-only reconciliation: no submitted key material, signatures, or
  // assertion of delivery. The release and review orders must be distinct.
  const reviewId=randomUUID(),receiptPath=deliveryPath+"/receipts/"+reviewId;
  const input={challengeDigest:hash("synthetic challenge"),receiptDigest:hash("synthetic acknowledgement"),receiptKeyDigest:hash("independently checked signing key"),verificationEvidenceDigest:hash("independent offline verification")};
  assert.equal((await expect("owner",deliveryPath,200)).receiptEvidenceRecorded,false);
  await expect("reader",receiptPath+"/preview",403,{body:input});
  await expect("reviewer",receiptPath+"/preview",403,{tenant:other,body:input});
  await expect("owner",receiptPath+"/preview",403,{body:input,claims:{amr:["pwd"]}});
  await expect("owner",receiptPath+"/preview",400,{body:{...input,delivered:true}});
  await expect("owner",receiptPath+"/preview",403,{body:{...input,receiptKeyDigest:deliveryInput.senderKeyDigest}});
  await expect("owner",deliveryPath+"/receipts/"+deliveryOrder+"/preview",403,{body:input});
  await expect("owner",casePath+"/deliveries/"+randomUUID()+"/receipts/"+reviewId+"/preview",403,{body:input});
  const preview=await expect("owner",receiptPath+"/preview",200,{body:input});
  assert.equal(preview.deliveryVerified,false);assert.equal(preview.receiptEvidenceRecorded,false);
  const op=(step,change={})=>({...input,scopeDigest:preview.scopeDigest,step,confirm:true,...change});
  await expect("owner",receiptPath,403,{body:op("consume")});
  await expect("owner",receiptPath,403,{body:op("request",{scopeDigest:hash("forgery")})});
  assert.equal((await expect("owner",receiptPath,200,{body:op("request")})).status,"requested");
  await expect("reader",receiptPath,403);
  await expect("reviewer",receiptPath,403,{tenant:other});
  await expect("owner",receiptPath,403,{body:op("approve")});
  await expect("reviewer",receiptPath,403,{body:op("approve",{receiptDigest:hash("substitute")})});
  assert.equal((await expect("reviewer",receiptPath,200,{body:op("approve")})).status,"approved");
  await expect("reviewer",receiptPath,403,{body:op("consume")});
  const recorded=await expect("owner",receiptPath,200,{body:op("consume")});
  assert.equal(recorded.status,"evidence-recorded");assert.equal(recorded.receiptEvidenceRecorded,true);assert.equal(recorded.deliveryVerified,false);
  assert.ok(!Object.hasOwn(recorded,"receiptDigest")&&!Object.hasOwn(recorded,"verificationEvidenceDigest"));
  await expect("owner",receiptPath,409,{body:op("consume")});
  const receiptStatus=await expect("reviewer",receiptPath,200);
  assert.equal(receiptStatus.status,"evidence-recorded");
  const releaseStatus=await expect("owner",deliveryPath,200);
  assert.equal(releaseStatus.receiptEvidenceRecorded,true);assert.equal(releaseStatus.deliveryVerified,false);
  await expect("owner",deliveryPath+"/receipts/"+randomUUID()+"/preview",409,{body:input});
  await assert.rejects(()=>runtime.query("SELECT * FROM private.privacy_receipt_requests"),e=>e.code==="42501");
  await assert.rejects(()=>runtime.query("SELECT * FROM private.privacy_receipt_evidence"),e=>e.code==="42501");
  assert.equal((await admin.query("SELECT private.verify_audit_chain($1) AS ok",[t])).rows[0].ok,true);
 }finally{await new Promise(r=>api.close(r));await new Promise(r=>keys.close(r));await Promise.all([admin.end(),runtime.end()]);}
});

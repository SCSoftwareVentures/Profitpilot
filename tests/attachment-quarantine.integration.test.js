import test from "node:test";
import assert from "node:assert/strict";
import {createServer} from "node:http";
import {randomBytes,randomUUID} from "node:crypto";
import {generateKeyPair,exportJWK,SignJWT} from "jose";
import pg from "pg";
import {openQuarantinedAttachment} from "../src/attachment-quarantine.js";
test("synthetic encrypted quarantine rejects wrong actors, direct reads and unsafe lifecycle", {skip:!process.env.TEST_ADMIN_DATABASE_URL},async()=>{
 const tenant=randomUUID(),user=randomUUID(),owner=randomUUID(),batch=randomUUID(),otherTenant=randomUUID(),otherUser=randomUUID();
 const issuer="https://quarantine-ci.invalid/",audience="profitpilot-api",key=randomBytes(32).toString("hex");
 const {publicKey,privateKey}=await generateKeyPair("RS256"),jwk={...await exportJWK(publicKey),kid:"quarantine-ci",alg:"RS256",use:"sig"};
 const jwks=createServer((q,r)=>{r.setHeader("content-type","application/json");r.end(JSON.stringify({keys:[jwk]}));});
 await new Promise(r=>jwks.listen(0,"127.0.0.1",r));
 const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
 Object.assign(process.env,{NODE_ENV:"test",DATABASE_URL:process.env.TEST_APP_DATABASE_URL,AUTH_ISSUER:issuer,AUTH_AUDIENCE:audience,AUTH_STEP_UP_ACR:"urn:profitpilot:step-up",AUTH_JWKS_URL:"http://127.0.0.1:"+jwks.address().port+"/jwks",ATTACHMENT_ENCRYPTION_KEY:key,ATTACHMENT_ENCRYPTION_KEY_ID:"synthetic-quarantine"});
 const [{default:app},{pool,withTenant}]=await Promise.all([import("../server/index.js"),import("../server/db.js")]);
 const api=createServer(app);await new Promise(r=>api.listen(0,"127.0.0.1",r));
 const base="http://127.0.0.1:"+api.address().port,root="/v1/tenants/"+tenant+"/imports/"+batch+"/quarantine";
 const bytes=Buffer.from("%PDF-1.7\nSYNTHETIC QUARANTINE BODY\n");
 async function req(path,subject,{body=bytes,type="application/pdf",mfa=true,method="POST"}={}){
  const token=await new SignJWT({auth_time:Math.floor(Date.now()/1000),acr:"urn:profitpilot:step-up",amr:mfa?["pwd","mfa"]:["pwd"]}).setProtectedHeader({alg:"RS256",kid:jwk.kid}).setIssuer(issuer).setAudience(audience).setSubject(subject).setIssuedAt().setExpirationTime("5m").setJti(randomBytes(16).toString("hex")).sign(privateKey);
  return fetch(base+path,{method,headers:{authorization:"Bearer "+token,"content-type":type},...(method!=="GET"?{body}:{})});
 }
 try{
  await admin.query("INSERT INTO tenants(id,legal_name) VALUES($1,'Synthetic quarantine CI'),($2,'Foreign synthetic CI')",[tenant,otherTenant]);
  await admin.query("INSERT INTO users(id,auth_subject,email,auth_issuer) VALUES($1,'quarantine-ci-user','q@example.invalid',$4),($2,'quarantine-ci-owner','qo@example.invalid',$4),($3,'quarantine-ci-foreign','qf@example.invalid',$4)",[user,owner,otherUser,issuer]);
  await admin.query("INSERT INTO tenant_memberships(tenant_id,user_id,role) VALUES($1,$2,'analyst'),($1,$3,'owner'),($4,$5,'analyst')",[tenant,user,owner,otherTenant,otherUser]);
  await admin.query("INSERT INTO import_batches(id,tenant_id,source_type,source_period_start,source_period_end,permission_ref,status,file_sha256,file_name,created_by) VALUES($1,$2,'payroll','2026-02-01','2026-02-28','Synthetic only','uploaded',$3,'synthetic.csv',$4)",[batch,tenant,randomBytes(32).toString("hex"),user]);
  delete process.env.ENABLE_SYNTHETIC_ATTACHMENT_QUARANTINE;
  assert.equal((await req(root,"quarantine-ci-user")).status,404);
  process.env.ENABLE_SYNTHETIC_ATTACHMENT_QUARANTINE="true";
  assert.equal((await req(root,"quarantine-ci-user",{mfa:false})).status,403);
  assert.equal((await req(root,"quarantine-ci-owner")).status,403);
  assert.equal((await req(root,"quarantine-ci-foreign")).status,403);
  assert.equal((await req(root,"quarantine-ci-user",{type:"application/zip"})).status,415);
  assert.equal((await req(root,"quarantine-ci-user",{body:Buffer.from("not a supported file")})).status,422);
  const uploaded=await req(root,"quarantine-ci-user");
  assert.equal(uploaded.status,201,await uploaded.clone().text());
  const receipt=await uploaded.json();assert.equal(receipt.scannerVerified,false);assert.equal(receipt.downloadAvailable,false);
  const row=(await admin.query("SELECT * FROM private.quarantined_attachments WHERE id=$1",[receipt.id])).rows[0];
  assert.equal(row.ciphertext.includes(bytes),false);
  assert.deepEqual(openQuarantinedAttachment(row,{tenantId:tenant,batchId:batch,userId:user,id:receipt.id,type:row.media_type,keyId:row.key_id,size:row.byte_count},key),bytes);
  await assert.rejects(()=>withTenant(tenant,"quarantine-ci-user",c=>c.query("SELECT ciphertext FROM private.quarantined_attachments")),/permission denied/i);
  assert.equal((await req(root+"/"+receipt.id,"quarantine-ci-user",{method:"GET"})).status,404);
  const discard=root+"/"+receipt.id+"/discard",discardOptions={type:"application/json",body:JSON.stringify({discardQuarantineOnly:true})};
  assert.equal((await req(discard,"quarantine-ci-owner",discardOptions)).status,404);
  await admin.query("INSERT INTO private.privacy_retention_holds(tenant_id,subject_user_id,authority_reference) VALUES($1,$2,'Synthetic hold')",[tenant,user]);
  assert.equal((await req(discard,"quarantine-ci-user",discardOptions)).status,409);
  await admin.query("DELETE FROM private.privacy_retention_holds WHERE tenant_id=$1 AND subject_user_id=$2",[tenant,user]);
  assert.equal((await req(discard,"quarantine-ci-user",discardOptions)).status,200);
  const discarded=(await admin.query("SELECT ciphertext,nonce,tag,discarded_at IS NOT NULL AS discarded FROM private.quarantined_attachments WHERE id=$1",[receipt.id])).rows[0];
  assert.deepEqual(discarded,{ciphertext:null,nonce:null,tag:null,discarded:true});
  assert.equal((await req(discard,"quarantine-ci-user",discardOptions)).status,409);
  await assert.rejects(()=>admin.query("DELETE FROM private.quarantined_attachments WHERE id=$1",[receipt.id]),/tombstones/i);
  const restore=(await admin.query("SELECT private.privacy_restore_state() AS state")).rows[0].state;
  assert.ok(restore.markers.some(x=>x.kind==="attachment_discard"&&x.id===receipt.id));
 }finally{await new Promise(r=>api.close(r));await new Promise(r=>jwks.close(r));await pool.end();await admin.end();}
});

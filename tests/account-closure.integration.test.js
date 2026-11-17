import test from "node:test";
import assert from "node:assert/strict";
import {createServer} from "node:http";
import {randomBytes} from "node:crypto";
import {generateKeyPair,exportJWK,SignJWT} from "jose";
import pg from "pg";
import {signCheckpoint,verifyCheckpoint,checkpointDigest} from "../scripts/privacy-restore-checkpoint.js";
test("account closure, token revocation, email erasure and restore safeguards",{skip:!process.env.TEST_ADMIN_DATABASE_URL},async()=>{
 const tenant="91919191-1111-4111-8111-111111111111",otherTenant="92929292-1111-4111-8111-111111111111";
 const user="93939393-1111-4111-8111-111111111111",owner="94949494-1111-4111-8111-111111111111",other="95959595-1111-4111-8111-111111111111",multi="96969696-1111-4111-8111-111111111111";
 const issuer="https://closure-ci.invalid/",audience="profitpilot-api";
 const {publicKey,privateKey}=await generateKeyPair("RS256");
 const jwk={...await exportJWK(publicKey),kid:"closure-test",alg:"RS256",use:"sig"};
 const jwks=createServer((req,res)=>{res.setHeader("content-type","application/json");res.end(JSON.stringify({keys:[jwk]}));});
 await new Promise(r=>jwks.listen(0,"127.0.0.1",r));
 Object.assign(process.env,{NODE_ENV:"test",DATABASE_URL:process.env.TEST_APP_DATABASE_URL,AUTH_ISSUER:issuer,AUTH_AUDIENCE:audience,AUTH_STEP_UP_ACR:"urn:profitpilot:step-up",AUTH_JWKS_URL:"http://127.0.0.1:"+jwks.address().port+"/jwks"});
 const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
 const [{default:app},{pool,withTenant}]=await Promise.all([import("../server/index.js"),import("../server/db.js")]);
 const api=createServer(app);await new Promise(r=>api.listen(0,"127.0.0.1",r));
 const base="http://127.0.0.1:"+api.address().port,root="/v1/tenants/"+tenant+"/privacy/requests";
 async function token(sub,{authTime=Math.floor(Date.now()/1000),mfa=true}={}){
  return new SignJWT({auth_time:authTime,acr:"urn:profitpilot:step-up",amr:mfa?["pwd","mfa"]:["pwd"]})
  .setProtectedHeader({alg:"RS256",kid:jwk.kid}).setIssuer(issuer).setAudience(audience).setSubject(sub)
  .setIssuedAt().setExpirationTime("5m").setJti(randomBytes(16).toString("hex")).sign(privateKey);
 }
 async function req(path,sub,body,options={}){
  const headers={authorization:"Bearer "+(options.bearer||await token(sub,options))};
  if(body!==undefined)headers["content-type"]="application/json";
  return fetch(base+path,{method:body!==undefined?"POST":"GET",headers,body:body===undefined?undefined:JSON.stringify(body)});
 }
 async function reviewed(sub,manager="closure-owner"){
  const create=await req(root,sub,{requestType:"account_closure",details:"Close local account"});
  assert.equal(create.status,201);
  const id=(await create.json()).id,p=root+"/"+id;
  assert.equal((await req(p+"/decision",manager,{action:"verify_identity",reason:"Begin verification"})).status,200);
  assert.equal((await req(p+"/confirm-account",sub,{})).status,200);
  assert.equal((await req(p+"/decision",manager,{action:"begin_review",reason:"Separate manager verified requester"})).status,200);
  return {id,p};
 }
 try{
  await admin.query("INSERT INTO tenants(id,legal_name) VALUES($1,'Closure CI'),($2,'Other CI')",[tenant,otherTenant]);
  await admin.query("INSERT INTO users(id,auth_subject,email) VALUES($1,'closure-user','erase-me@example.invalid'),($2,'closure-owner','owner@example.invalid'),($3,'closure-other','other@example.invalid'),($4,'closure-multi','multi@example.invalid')",[user,owner,other,multi]);
  await admin.query("INSERT INTO tenant_memberships(tenant_id,user_id,role) VALUES($1,$2,'analyst'),($1,$3,'owner'),($1,$4,'admin'),($1,$5,'analyst'),($6,$5,'analyst')",[tenant,user,owner,other,multi,otherTenant]);
  assert.equal((await req("/v1/me","unknown-closure-subject")).status,401);
  const multiReq=await reviewed("closure-multi");
  assert.equal((await req(multiReq.p+"/approve-closure","closure-owner",{eraseEmail:false})).status,200);
  await new Promise(r=>setTimeout(r,1100));
  assert.equal((await req(multiReq.p+"/execute-closure","closure-multi",{eraseEmail:false})).status,409,"one organization cannot authorize global closure");
  const ownerReq=await reviewed("closure-owner","closure-other");
  assert.equal((await req(ownerReq.p+"/approve-closure","closure-other",{eraseEmail:false})).status,409);
  const x=await reviewed("closure-user");
  const approve=x.p+"/approve-closure",execute=x.p+"/execute-closure";
  assert.equal((await req(approve,"closure-owner",{eraseEmail:true})).status,409,"no default profile erasure policy");
  await admin.query("INSERT INTO private.privacy_retention_policies(tenant_id,revision,enabled,minimum_closed_age_days,authority_reference,allow_profile_email_erasure) VALUES($1,gen_random_uuid(),true,30,'Synthetic CI only',true)",[tenant]);
  assert.equal((await req(approve,"closure-user",{eraseEmail:true})).status,403);
  assert.equal((await req(approve,"closure-owner",{eraseEmail:true},{mfa:false})).status,403);
  assert.equal((await req(approve,"closure-owner",{eraseEmail:true})).status,200);
  assert.equal((await req(execute,"closure-other",{eraseEmail:true})).status,404);
  assert.equal((await req(execute,"closure-user",{eraseEmail:false})).status,409);
  await assert.rejects(()=>withTenant(tenant,"closure-user",c=>c.query("SELECT * FROM private.account_closures")),/permission denied/);
  await assert.rejects(()=>withTenant(tenant,"closure-user",c=>c.query("SELECT private.execute_account_closure($1,$2,true,$3,$4)",[tenant,x.id,Math.floor(Date.now()/1000),"0".repeat(64)])),/step-up proof/i);
  const before=(await admin.query("SELECT private.privacy_restore_state() AS state")).rows[0].state;
  await new Promise(r=>setTimeout(r,1100));
  await admin.query("INSERT INTO private.privacy_retention_holds(tenant_id,subject_user_id,authority_reference) VALUES($1,$2,'CI hold')",[tenant,user]);
  assert.equal((await req(execute,"closure-user",{eraseEmail:true})).status,409);
  await admin.query("DELETE FROM private.privacy_retention_holds WHERE tenant_id=$1 AND subject_user_id=$2",[tenant,user]);
  assert.equal((await req(execute,"closure-user",{eraseEmail:true})).status,409,"hold release cannot revive grant");
  assert.equal((await req(approve,"closure-owner",{eraseEmail:true})).status,200);
  await admin.query("UPDATE private.privacy_retention_policies SET allow_profile_email_erasure=false WHERE tenant_id=$1",[tenant]);
  await new Promise(r=>setTimeout(r,1100));
  assert.equal((await req(execute,"closure-user",{eraseEmail:true})).status,409);
  await admin.query("UPDATE private.privacy_retention_policies SET allow_profile_email_erasure=true WHERE tenant_id=$1",[tenant]);
  assert.equal((await req(approve,"closure-owner",{eraseEmail:true})).status,200);
  const approved=(await admin.query("SELECT floor(extract(epoch FROM approved_at))::bigint AS t FROM private.account_closure_approvals WHERE request_id=$1",[x.id])).rows[0].t;
  assert.equal((await req(execute,"closure-user",{eraseEmail:true},{authTime:Number(approved)})).status,409);
  const oldToken=await token("closure-user");
  assert.equal((await req("/v1/me","closure-user",undefined,{bearer:oldToken})).status,200);
  await new Promise(r=>setTimeout(r,1100));
  const done=await req(execute,"closure-user",{eraseEmail:true});assert.equal(done.status,200);
  const receipt=await done.json();assert.equal(receipt.accountClosed,true);assert.equal(receipt.profileEmailErased,true);
  assert.equal(receipt.completePersonalDataDeletion,false);assert.equal(receipt.providerAccountErased,false);
  assert.equal((await req("/v1/me","closure-user",undefined,{bearer:oldToken})).status,401);
  assert.equal((await req("/v1/me","closure-user")).status,401,"fresh signed provider token is denied");
  assert.equal((await req(execute,"closure-user",{eraseEmail:true})).status,401);
  assert.equal((await req("/v1/me","closure-owner")).status,200);
  const account=(await admin.query("SELECT status,email FROM users WHERE id=$1",[user])).rows[0];
  assert.deepEqual(account,{status:"disabled",email:"erased-"+user+"@invalid.example"});
  assert.equal((await admin.query("SELECT count(*)::int AS n FROM private.auth_sessions WHERE subject='closure-user' AND revoked_at IS NULL")).rows[0].n,0);
  assert.equal((await admin.query("SELECT status FROM tenant_memberships WHERE tenant_id=$1 AND user_id=$2",[tenant,user])).rows[0].status,"revoked");
  await assert.rejects(()=>admin.query("UPDATE users SET status='active' WHERE id=$1",[user]),/Closed account/);
  await assert.rejects(()=>admin.query("UPDATE users SET email='resurrected@example.invalid' WHERE id=$1",[user]),/Closed account/);
  await assert.rejects(()=>admin.query("INSERT INTO tenant_memberships(tenant_id,user_id,role) VALUES($1,$2,'analyst')",[otherTenant,user]),/Closed account/);
  await assert.rejects(()=>withTenant(tenant,"closure-owner",c=>c.query("SELECT private.privacy_restore_state()")),/permission denied/);
  // Closure without erasure must preserve data, independently of the optional email-erasure scope.
  const retained=await reviewed("closure-other","closure-owner");
  assert.equal((await req(retained.p+"/approve-closure","closure-owner",{eraseEmail:false})).status,200);
  await new Promise(r=>setTimeout(r,1100));
  const retainedResult=await req(retained.p+"/execute-closure","closure-other",{eraseEmail:false});
  assert.equal(retainedResult.status,200);
  assert.equal((await retainedResult.json()).profileEmailErased,false);
  assert.deepEqual((await admin.query("SELECT status,email FROM users WHERE id=$1",[other])).rows[0],{status:"disabled",email:"other@example.invalid"});
  // Each organization requires its own independent approval, and each retains an active owner.
  const successor="97979797-1111-4111-8111-111111111111";
  await admin.query("INSERT INTO users(id,auth_subject,email) VALUES($1,'closure-successor','successor@example.invalid')",[successor]);
  await admin.query("INSERT INTO tenant_memberships(tenant_id,user_id,role) VALUES($1,$3,'owner'),($2,$3,'owner')",[tenant,otherTenant,successor]);
  const otherRoot="/v1/tenants/"+otherTenant+"/privacy/requests";
  const created=await req(otherRoot,"closure-multi",{requestType:"account_closure",details:"Close second organization account"});
  assert.equal(created.status,201);
  const p2=otherRoot+"/"+(await created.json()).id;
  assert.equal((await req(p2+"/decision","closure-successor",{action:"verify_identity",reason:"Begin verification"})).status,200);
  assert.equal((await req(p2+"/confirm-account","closure-multi",{})).status,200);
  assert.equal((await req(p2+"/decision","closure-successor",{action:"begin_review",reason:"Independent review"})).status,200);
  assert.equal((await req(p2+"/approve-closure","closure-successor",{eraseEmail:false})).status,200);
  await new Promise(r=>setTimeout(r,1100));
  const multiDone=await req(multiReq.p+"/execute-closure","closure-multi",{eraseEmail:false});
  assert.equal(multiDone.status,200);
  assert.equal((await admin.query("SELECT count(*)::int AS n FROM tenant_memberships WHERE user_id=$1 AND status='active'",[multi])).rows[0].n,0);
  // Previously ineligible owner becomes eligible only with a separate active successor.
  assert.equal((await req(ownerReq.p+"/approve-closure","closure-successor",{eraseEmail:false})).status,200);
  await new Promise(r=>setTimeout(r,1100));
  assert.equal((await req(ownerReq.p+"/execute-closure","closure-owner",{eraseEmail:false})).status,200);
  assert.equal((await req("/v1/me","closure-successor")).status,200);
  // Closed account session cleanup requires explicit policy across all memberships.
  await assert.rejects(()=>admin.query("SELECT private.cleanup_closed_sessions($1,'CI synthetic policy')",[user]),/Retention authorization/);
  await assert.rejects(()=>withTenant(tenant,"closure-successor",c=>c.query("SELECT private.cleanup_closed_sessions($1,'not authorized')",[user])),/permission denied/i);
  await admin.query("UPDATE private.privacy_retention_policies SET allow_expired_session_erasure=true,session_retention_days=30 WHERE tenant_id=$1",[tenant]);
  await admin.query("INSERT INTO private.auth_sessions(jti,subject,issued_at,expires_at,last_seen_at,revoked_at,revocation_reason) VALUES('synthetic-expired-session','closure-user',now()-interval '40 days',now()-interval '39 days',now()-interval '40 days',now()-interval '39 days','CI retained session')");
  await admin.query("INSERT INTO private.privacy_retention_holds(tenant_id,subject_user_id,authority_reference) VALUES($1,$2,'CI retained session hold')",[tenant,user]);
  await assert.rejects(()=>admin.query("SELECT private.cleanup_closed_sessions($1,'CI synthetic policy')",[user]),/hold/);
  await admin.query("DELETE FROM private.privacy_retention_holds WHERE tenant_id=$1 AND subject_user_id=$2",[tenant,user]);
  const cleaned=(await admin.query("SELECT private.cleanup_closed_sessions($1,'CI synthetic policy') AS result",[user])).rows[0].result;
  assert.equal(cleaned.removed,1);
  assert.equal((await admin.query("SELECT count(*)::int AS n FROM private.auth_sessions WHERE subject='closure-user' AND jti='synthetic-expired-session'")).rows[0].n,0);
  assert.ok((await admin.query("SELECT count(*)::int AS n FROM private.auth_sessions WHERE subject='closure-user'")).rows[0].n>0,"recent sessions retained");
  const state=(await admin.query("SELECT private.privacy_restore_state() AS state")).rows[0].state;
  assert.ok(state.markers.some(m=>m.kind==="session_cleanup"&&m.userId===user));
  assert.deepEqual(state.violations,[]);
  assert.equal(state.markers.find(m=>m.id===user).emailErased,true);
  const opts={key:"ef".repeat(32),deploymentId:"ci-closure",now:Date.now()};
  const manifest=signCheckpoint(state,opts);
  const verifyOpts={...opts,expectedDigest:checkpointDigest(manifest)};
  assert.equal(verifyCheckpoint(manifest,state,verifyOpts).verified,true);
  assert.throws(()=>verifyCheckpoint(manifest,before,verifyOpts),/missing or has changed/);
  assert.equal((await admin.query("SELECT is_valid FROM private.verify_audit_chain($1)",[tenant])).rows[0].is_valid,true);
  assert.equal((await admin.query("SELECT is_valid FROM private.verify_audit_chain($1)",[otherTenant])).rows[0].is_valid,true);
 }finally{
  await new Promise(r=>api.close(r));await pool.end();await admin.end();await new Promise(r=>jwks.close(r));
 }
});

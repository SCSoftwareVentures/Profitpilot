import test from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import pg from "pg";
import {sessionRequired} from "../server/auth.js";

test("session middleware fails closed on revocation and database failure",async()=>{
 for(const [check,expected] of [[async()=>true,200],[async()=>false,403],[async()=>{throw new Error("private details");},503]]){
  const result=await new Promise(resolve=>{
   const res={status(code){this.code=code;return this;},json(body){resolve({code:this.code,body});}};
   sessionRequired(check)({identity:{subject:"synthetic"}},res,()=>resolve({code:200}));
  });
  assert.equal(result.code,expected);assert.ok(!JSON.stringify(result).includes("private details"));
 }
});
test("session revocation rejects stale logins, refreshed stolen sessions and spoofed context",{skip:!process.env.TEST_APP_DATABASE_URL,timeout:30000},async()=>{
 const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
 process.env.NODE_ENV="test";process.env.DATABASE_URL=process.env.TEST_APP_DATABASE_URL;
 const {pool,withTenant,checkIdentitySession,sessionDigest}=await import("../server/db.js");
 const user=randomUUID(),subject="ci-session-"+user,tenant="33333333-3333-4333-8333-333333333333";
 const now=Math.floor(Date.now()/1000);
 const identity={subject,authTime:now-30,issuedAt:now,sessionId:"ci-one-"+user};
 const other={...identity,sessionId:"ci-two-"+user};
 try{
  await admin.query("INSERT INTO public.users(id,auth_subject,email,status) VALUES($1,$2,'session@example.invalid','active')",[user,subject]);
  await admin.query("INSERT INTO public.tenant_memberships(tenant_id,user_id,role,status) VALUES($1,$2,'analyst','active')",[tenant,user]);
  assert.equal(await checkIdentitySession(identity),true);
  assert.equal(await checkIdentitySession(other),true);
  assert.equal(await checkIdentitySession({...identity,sessionId:undefined}),false);
  assert.equal(await checkIdentitySession({...identity,authTime:identity.issuedAt+20}),false);
  assert.equal(await checkIdentitySession({...identity,subject:"unknown-subject"}),false);
  assert.equal((await withTenant(tenant.toUpperCase(),subject,c=>c.query("SELECT private.current_tenant_id() AS id"),identity)).rows[0].id,tenant);
  assert.equal((await pool.query("SELECT private.session_authorized($1,$2,$3,$4,$5,$6,$7,$8) AS allowed",[subject,now-30,now,sessionDigest(identity.sessionId),now+30,"a".repeat(32),"primary","a".repeat(64)])).rows[0].allowed,false);
  await assert.rejects(()=>pool.query("SELECT private.revoke_identity_access($1,'revoke_all','CI_DENIED',NULL)",[user]),/permission denied/i);
  await admin.query("SELECT private.revoke_identity_access($1,'revoke_session','CI_STOLEN_SESSION',$2)",[user,sessionDigest(identity.sessionId)]);
  assert.equal(await checkIdentitySession(identity),false);
  assert.equal(await checkIdentitySession({...identity,issuedAt:Math.floor(Date.now()/1000)}),false);
  assert.equal(await checkIdentitySession(other),true);
  await assert.rejects(()=>withTenant(tenant,subject,c=>c.query("SELECT 1"),identity),/Session revoked/);
  await admin.query("SELECT private.revoke_identity_access($1,'revoke_all','CI_GLOBAL_LOGOUT',NULL)",[user]);
  assert.equal(await checkIdentitySession(other),false);
  const newLogin=async()=>{
   const start=Date.now();while(Math.floor(Date.now()/1000)<=Math.floor(start/1000))await new Promise(resolve=>setTimeout(resolve,50));
   const time=Math.floor(Date.now()/1000);
   return {...other,authTime:time,issuedAt:time,sessionId:randomUUID()};
  };
  const fresh=await newLogin();
  assert.equal(await checkIdentitySession(fresh),true);
  await admin.query("UPDATE public.users SET status='disabled' WHERE id=$1",[user]);
  assert.equal(await checkIdentitySession(fresh),false);
  await admin.query("UPDATE public.users SET status='active' WHERE id=$1",[user]);
  assert.equal(await checkIdentitySession(fresh),false);
  assert.equal(await checkIdentitySession(await newLogin()),true);
  await assert.rejects(()=>pool.query("SELECT * FROM private.identity_security_events"),/permission denied/i);
  assert.equal((await admin.query("SELECT count(*)::int AS n FROM private.identity_security_events WHERE user_id=$1",[user])).rows[0].n,2);
 }finally{await Promise.all([pool.end(),admin.end()]);}
});

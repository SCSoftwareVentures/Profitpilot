import test from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import pg from "pg";
test("identity operators can provision and govern access but cannot directly modify accounts or replay recovery",{skip:!process.env.TEST_APP_DATABASE_URL,timeout:30000},async()=>{
 const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
 const app=new pg.Pool({connectionString:process.env.TEST_APP_DATABASE_URL});
 const operator=await admin.connect();
 const tenant=randomUUID(),subject="ci-provision-"+randomUUID(),other="ci-provision-"+randomUUID();
 try{
  await admin.query("INSERT INTO public.tenants(id,legal_name) VALUES($1,'Synthetic identity governance tenant')",[tenant]);
  await operator.query("SET ROLE profitpilot_identity_operator");
  const provision=async sub=>(await operator.query("SELECT private.provision_verified_identity($1,'synthetic@example.invalid','CI_PROVISION') AS id",[sub])).rows[0].id;
  await assert.rejects(()=>app.query("SELECT private.provision_verified_identity($1,'synthetic@example.invalid','CI_DENIED')",[subject]),/permission denied/i);
  await assert.rejects(()=>operator.query("SELECT * FROM public.users"),/permission denied/i);
  await assert.rejects(()=>operator.query("SELECT * FROM private.identity_admin_events"),/permission denied/i);
  const first=await provision(subject),second=await provision(other);
  await assert.rejects(()=>provision(subject),/duplicate key/i);
  const change=(user,role,action)=>operator.query("SELECT private.administer_membership($1,$2,$3,$4,'CI_MEMBERSHIP')",[tenant,user,role,action]);
  await change(first,"owner","grant");
  await assert.rejects(()=>change(first,"admin","grant"),/last active owner/i);
  await assert.rejects(()=>change(first,null,"revoke"),/last active owner/i);
  await change(second,"owner","grant");
  await change(first,"reviewer","grant");
  assert.equal((await admin.query("SELECT role FROM public.tenant_memberships WHERE tenant_id=$1 AND user_id=$2",[tenant,first])).rows[0].role,"reviewer");
  await change(first,null,"revoke");
  await change(first,"read_only","grant");
  assert.equal((await admin.query("SELECT status FROM public.tenant_memberships WHERE tenant_id=$1 AND user_id=$2",[tenant,first])).rows[0].status,"active");
  await assert.rejects(()=>operator.query("SELECT private.replay_identity_revocation($1,$2,1,NULL,false,'CI_DENIED')",[first,subject]),/permission denied/i);
  await assert.rejects(()=>admin.query("SELECT private.replay_identity_revocation($1,'wrong-subject',1,NULL,false,'CI_REPLAY')",[first]),/does not match/i);
  const before=(await admin.query("SELECT revoked_through FROM private.identity_session_cutoffs WHERE user_id=$1",[first])).rows[0].revoked_through;
  await admin.query("SELECT private.replay_identity_revocation($1,$2,1,NULL,false,'CI_REPLAY')",[first,subject]);
  assert.equal((await admin.query("SELECT revoked_through FROM private.identity_session_cutoffs WHERE user_id=$1",[first])).rows[0].revoked_through,before);
  await admin.query("SELECT private.replay_identity_revocation($1,$2,NULL,NULL,true,'CI_DISABLE')",[first,subject]);
  assert.equal((await admin.query("SELECT status FROM public.users WHERE id=$1",[first])).rows[0].status,"disabled");
  assert.equal((await admin.query("SELECT count(*)::int AS n FROM private.identity_admin_events WHERE user_id=$1",[first])).rows[0].n,7);
  await assert.rejects(()=>admin.query("DELETE FROM private.identity_admin_events WHERE user_id=$1",[first]),/append-only/i);
 }finally{await operator.query("RESET ROLE");operator.release();await Promise.all([admin.end(),app.end()]);}
});

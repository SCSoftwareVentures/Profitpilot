import test from "node:test";
import assert from "node:assert/strict";
import {randomBytes} from "node:crypto";
import pg from "pg";
const roles=["profitpilot_scanner","profitpilot_identity_operator","profitpilot_audit_reader","profitpilot_recovery_reader","profitpilot_incident_operator","profitpilot_incident_recovery","profitpilot_security_reader"];
const operations=[
 ["profitpilot_scanner","SELECT private.claim_quarantine_scan()"],
 ["profitpilot_identity_operator","SELECT private.provision_verified_identity(NULL,NULL,NULL)"],
 ["profitpilot_audit_reader","SELECT private.audit_checkpoint_heads()"],
 ["profitpilot_recovery_reader","SELECT private.privacy_recovery_inventory()"],
 ["profitpilot_incident_operator","SELECT private.activate_tenant_emergency(NULL,NULL,NULL,NULL)"],
 ["profitpilot_incident_recovery","SELECT private.release_tenant_emergency(NULL,NULL,NULL)"],
 ["profitpilot_security_reader","SELECT private.security_command_snapshot(1,NULL)"]
];
test("real restricted worker logins cannot assume other capabilities, see customer data or create objects",{skip:!process.env.TEST_APP_DATABASE_URL,timeout:60000},async()=>{
 const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL,max:1});
 try{
  for(const role of roles){
   const password=randomBytes(32).toString("hex");
   assert.equal((await admin.query("SELECT rolcanlogin FROM pg_roles WHERE rolname=$1",[role])).rows[0].rolcanlogin,false);
   // Only ephemeral synthetic CI. Never provision live worker credentials here.
   await admin.query("ALTER ROLE "+role+" LOGIN PASSWORD '"+password+"'");
   const url=new URL(process.env.TEST_ADMIN_DATABASE_URL);url.username=role;url.password=password;
   const worker=new pg.Pool({connectionString:url.href,max:1,statement_timeout:3000,connectionTimeoutMillis:3000});
   try{
    assert.deepEqual((await worker.query("SELECT current_user AS runtime,session_user AS login")).rows,[{runtime:role,login:role}]);
    for(const other of [...roles,"profitpilot_app","profitpilot_context_owner","profitpilot_admin"].filter(x=>x!==role))
     await assert.rejects(()=>worker.query("SET ROLE "+other),e=>e.code==="42501",role+" cannot assume "+other);
    for(const query of ["SELECT * FROM public.users","SELECT * FROM public.contracts","SELECT * FROM private.tenant_context_keys","SELECT * FROM private.tenant_emergency_incidents","CREATE TABLE public.worker_attack(x int)","CREATE TABLE private.worker_attack(x int)"])
     await assert.rejects(()=>worker.query(query),e=>e.code==="42501",role+" cannot use "+query);
    for(const [owner,query] of operations.filter(([owner])=>owner!==role))
     await assert.rejects(()=>worker.query(query),e=>e.code==="42501",role+" cannot exercise "+owner+" capability");
   }finally{await worker.end();await admin.query("ALTER ROLE "+role+" NOLOGIN PASSWORD NULL");}
  }
  assert.equal((await admin.query("SELECT private.verify_security_catalog() AS ok")).rows[0].ok,true);
 }finally{await admin.end();}
});

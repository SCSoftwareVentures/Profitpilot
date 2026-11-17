import test from "node:test";
import assert from "node:assert/strict";
import {randomBytes,randomUUID,createHash} from "node:crypto";
import pg from "pg";
import {quarantineConfig,sealQuarantine,openQuarantine,MAX_QUARANTINE_BYTES} from "../server/quarantine.js";
const config={id:"ci-file-key",secret:randomBytes(32).toString("hex")};
const plain=Buffer.from("invoice_id,amount\nSYNTHETIC,10.00\n");
const tenant="33333333-3333-4333-8333-333333333333",other="44444444-4444-4444-8444-444444444444";

test("quarantine is off by default and cannot be activated in production",()=>{
 assert.equal(quarantineConfig({}),null);
 assert.equal(quarantineConfig({NODE_ENV:"production",QUARANTINE_UPLOADS_ENABLED:"true"}),null);
 const env={NODE_ENV:"test",QUARANTINE_UPLOADS_ENABLED:"true",QUARANTINE_KEY_ID:config.id,QUARANTINE_ENCRYPTION_KEY:config.secret};
 assert.deepEqual(quarantineConfig(env),config);
 assert.throws(()=>quarantineConfig({...env,TENANT_CONTEXT_HMAC_SECRET:config.secret}));
 assert.throws(()=>quarantineConfig({...env,QUARANTINE_ENCRYPTION_KEY:"bad"}));
});
test("encrypted file bytes authenticate tenant, batch, digest and key identity",()=>{
 const batch=randomUUID(),e=sealQuarantine(plain,tenant,batch,config);
 assert.equal(e.sha,createHash("sha256").update(plain).digest("hex"));
 assert.notDeepEqual(e.ciphertext,plain);
 assert.notDeepEqual(sealQuarantine(plain,tenant,batch,config).nonce,e.nonce);
 assert.deepEqual(openQuarantine(e,tenant,batch,config),plain);
 assert.throws(()=>openQuarantine(e,other,batch,config));
 assert.throws(()=>openQuarantine(e,tenant,randomUUID(),config));
 assert.throws(()=>openQuarantine({...e,sha:"0".repeat(64)},tenant,batch,config));
 const altered=Buffer.from(e.ciphertext);altered[0]^=1;
 assert.throws(()=>openQuarantine({...e,ciphertext:altered},tenant,batch,config));
 assert.throws(()=>openQuarantine(e,tenant,batch,{...config,secret:randomBytes(32).toString("hex")}));
 for(const bad of [Buffer.alloc(0),Buffer.alloc(MAX_QUARANTINE_BYTES+1,65),Buffer.from([0xff]),Buffer.from([0]),Buffer.from(" ")])assert.throws(()=>sealQuarantine(bad,tenant,batch,config));
});

test("database quarantine restricts access, validates checksum, blocks ingestion and disposal",{skip:!process.env.TEST_APP_DATABASE_URL,timeout:30000},async()=>{
 const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
 process.env.NODE_ENV="test";process.env.DATABASE_URL=process.env.TEST_APP_DATABASE_URL;
 const {pool,withTenant}=await import("../server/db.js");
 const actor="55555555-5555-4555-8555-555555555555",subject="isolation-tenant-c",batch=randomUUID(),e=sealQuarantine(plain,tenant,batch,config);
 const args=[tenant,batch,e.sha,e.keyId,e.nonce,e.tag,e.ciphertext];
 const put=(who=subject,t=tenant,a=args)=>withTenant(t,who,c=>c.query("SELECT private.quarantine_invoice_file($1,$2,$3,$4,$5,$6,$7) AS receipt",a));
 try{
  await admin.query("INSERT INTO public.import_batches(id,tenant_id,source_type,permission_ref,status,file_sha256,file_name,created_by) VALUES($1,$2,'customer_invoice','CI synthetic authority','registered',$3,'synthetic.csv',$4)",[batch,tenant,e.sha,actor]);
  await assert.rejects(()=>put(),/authority denied/i);
  await assert.rejects(()=>put("isolation-tenant-d",other),/authority denied/i);
  await admin.query("UPDATE public.tenant_memberships SET role='admin' WHERE tenant_id=$1 AND user_id=$2",[tenant,actor]);
  try{
   const bad=[...args];bad[2]="0".repeat(64);
   await assert.rejects(()=>put(subject,tenant,bad),/not eligible/i);
   const receipt=(await put()).rows[0].receipt;
   assert.equal(receipt.batchId,batch);assert.equal(receipt.scanStatus,"pending");assert.equal(receipt.byteCount,plain.length);
   await assert.rejects(()=>put(),/already exists/i);
   await assert.rejects(()=>withTenant(tenant,subject,c=>c.query("SELECT * FROM private.quarantined_files")),/permission denied/i);
   await assert.rejects(()=>withTenant(tenant,subject,c=>c.query("INSERT INTO public.raw_import_rows(tenant_id,batch_id,row_number,payload) VALUES($1,$2,1,'{}')",[tenant,batch])),/not approved/i);
   const row=(await admin.query("SELECT * FROM private.quarantined_files WHERE tenant_id=$1 AND batch_id=$2",[tenant,batch])).rows[0];
   assert.deepEqual(openQuarantine({sha:row.file_sha256,keyId:row.key_id,nonce:row.nonce,tag:row.auth_tag,ciphertext:row.ciphertext},tenant,batch,config),plain);
   assert.equal((await withTenant(other,"isolation-tenant-d",c=>c.query("SELECT private.quarantine_status($1,$2) AS pending",[tenant,batch]))).rows[0].pending,false);
   assert.equal((await admin.query("SELECT count(*)::int AS n FROM public.audit_events WHERE object_id=$1 AND action='file_quarantined'",[batch])).rows[0].n,1);
   await admin.query("UPDATE public.import_batches SET status='failed' WHERE id=$1",[batch]);
   await admin.query("SELECT private.approve_import_disposal($1,$2,$3,$4)",[tenant,batch,new Date(0),"CI_FILE_DISPOSAL"]);
   await assert.rejects(()=>admin.query("SELECT private.execute_import_disposal($1,$2)",[tenant,batch]),/Referenced evidence|foreign key constraint/i);
   assert.equal((await admin.query("SELECT 1 FROM private.import_disposal_tombstones WHERE batch_id=$1",[batch])).rowCount,0);
  }finally{await admin.query("UPDATE public.tenant_memberships SET role='analyst' WHERE tenant_id=$1 AND user_id=$2",[tenant,actor]);}
 }finally{await Promise.all([admin.end(),pool.end()]);}
});

import test from "node:test";
import assert from "node:assert/strict";
import {randomBytes} from "node:crypto";
import pg from "pg";
import {sealQuarantine} from "../server/quarantine.js";

test("prepare an expired synthetic quarantine receipt for encrypted recovery",{skip:!process.env.TEST_APP_DATABASE_URL,timeout:30000},async()=>{
 const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
 const runtime=new pg.Pool({connectionString:process.env.TEST_APP_DATABASE_URL});
 const tenant="33333333-3333-4333-8333-333333333333",actor="55555555-5555-4555-8555-555555555555",batch="de2537ce-957d-478d-98bf-57c6ea37cd3c";
 const e=sealQuarantine(Buffer.from("synthetic recovery expiry fixture"),tenant,batch,{id:"ci-expiry-key",secret:randomBytes(32).toString("hex")});
 try{
  await admin.query("INSERT INTO public.import_batches(id,tenant_id,source_type,permission_ref,status,file_sha256,file_name,created_by) VALUES($1,$2,'customer_invoice','CI synthetic expiry','registered',$3,'fixture.csv',$4)",[batch,tenant,e.sha,actor]);
  await admin.query("INSERT INTO private.quarantined_files(tenant_id,batch_id,file_sha256,byte_count,key_id,nonce,auth_tag,ciphertext,uploaded_by,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,clock_timestamp()-interval '25 hours')",[tenant,batch,e.sha,e.ciphertext.length,e.keyId,e.nonce,e.tag,e.ciphertext,actor]);
  await assert.rejects(()=>runtime.query("SELECT private.replay_quarantine_expiry($1,$2,$3,now())",[tenant,batch,e.sha]),/permission denied/i);
  await assert.rejects(()=>runtime.query("SELECT * FROM private.quarantine_expiry_receipts"),/permission denied/i);
  assert.equal((await admin.query("SELECT scan_state FROM private.quarantined_files WHERE batch_id=$1",[batch])).rows[0].scan_state,"pending");
 }finally{await Promise.all([admin.end(),runtime.end()]);}
});

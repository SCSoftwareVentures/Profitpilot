import test from "node:test";
import assert from "node:assert/strict";
import {createServer} from "node:net";
import {mkdtemp,rm} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {randomUUID,randomBytes} from "node:crypto";
import pg from "pg";
import {scanClamav,signaturesFresh} from "../server/clamav.js";
import {sealQuarantine} from "../server/quarantine.js";
import {runQuarantineCycle} from "../scripts/quarantine-worker.js";

test("ClamAV protocol requires fresh definitions and explicit recognized verdict",async()=>{
 const dir=await mkdtemp(join(tmpdir(),"pp-clam-")),path=join(dir,"scan.sock"),now=Date.parse("2026-11-18T00:00:00Z");
 const fresh="ClamAV 1.4.3/12345/Tue Nov 17 12:00:00 2026";
 const old="ClamAV 1.4.3/12345/Sun Nov 15 00:00:00 2026";
 assert.equal(signaturesFresh(fresh,now),true);assert.equal(signaturesFresh(old,now),false);
 assert.equal(signaturesFresh("ClamAV 1.4.3",now),false);
 let version=fresh,response="stream: OK",scans=0;
 const input=Buffer.from("synthetic file");
 const server=createServer(socket=>{
  let received=Buffer.alloc(0);
  socket.on("data",chunk=>{
   received=Buffer.concat([received,chunk]);
   if(received.subarray(0,9).equals(Buffer.from("zVERSION\0")))socket.end(version+"\0");
   else if(received.length>=10+4+input.length+4){
    scans++;
    assert.equal(received.subarray(0,10).toString(),"zINSTREAM\0");
    assert.equal(received.readUInt32BE(10),input.length);
    assert.deepEqual(received.subarray(14,14+input.length),input);
    assert.equal(received.readUInt32BE(14+input.length),0);
    socket.end(response+"\0");
   }
  });
 });
 await new Promise(resolve=>server.listen(path,resolve));
 try{
  const options={socketPath:path,now:()=>now};
  assert.equal(await scanClamav(input,options),"clean");
  response="stream: Synthetic-Test FOUND";
  assert.equal(await scanClamav(input,options),"infected");
  response="stream: size limit exceeded ERROR";
  await assert.rejects(()=>scanClamav(input,options),/recognized verdict/);
  version=old;
  await assert.rejects(()=>scanClamav(input,options),/not current/);
  assert.equal(scans,3);
  await assert.rejects(()=>scanClamav(input,{socketPath:join(dir,"missing.sock")}),/unavailable/);
 }finally{await new Promise(resolve=>server.close(resolve));await rm(dir,{recursive:true,force:true});}
});

test("worker records failure instead of promoting unauthenticated data",async()=>{
 const tenant=randomUUID(),batch=randomUUID(),keyId="ci-key",secret=randomBytes(32).toString("hex");
 const e=sealQuarantine(Buffer.from("synthetic"),tenant,batch,{id:keyId,secret});
 const row={tenant_id:tenant,batch_id:batch,file_sha256:e.sha,key_id:keyId,nonce:e.nonce,auth_tag:e.tag,ciphertext:e.ciphertext,lease_id:randomUUID()};
 let claims=0,verdict,scanned=false;
 const db={query:async(sql,args)=>{
  if(sql.includes("claim"))return {rows:claims++===0?[row]:[]};
  verdict=args[3];return {rows:[{recorded:true}]};
 }};
 const result=await runQuarantineCycle(db,{keyId,secret:randomBytes(32).toString("hex"),scan:async()=>{scanned=true;return "clean";}});
 assert.equal(scanned,false);assert.equal(verdict,"error");assert.equal(result.error,1);
});

test("scanner database role enforces lease ownership, holds, expiry and permanent ingestion block",{skip:!process.env.TEST_ADMIN_DATABASE_URL||!process.env.TEST_APP_DATABASE_URL,timeout:30000},async()=>{
 const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
 const tenant="33333333-3333-4333-8333-333333333333",actor="55555555-5555-4555-8555-555555555555",batch=randomUUID();
 const keyId="ci-scan-key",secret=randomBytes(32).toString("hex");
 const e=sealQuarantine(Buffer.from("synthetic scan fixture"),tenant,batch,{id:keyId,secret});
 const scanner=await admin.connect();
 const app=new pg.Pool({connectionString:process.env.TEST_APP_DATABASE_URL});
 try{
  await admin.query("INSERT INTO public.import_batches(id,tenant_id,source_type,permission_ref,status,file_sha256,file_name,created_by) VALUES($1,$2,'customer_invoice','CI synthetic authority','registered',$3,'synthetic.csv',$4)",[batch,tenant,e.sha,actor]);
  await admin.query("INSERT INTO private.quarantined_files(tenant_id,batch_id,file_sha256,byte_count,key_id,nonce,auth_tag,ciphertext,uploaded_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",[tenant,batch,e.sha,e.ciphertext.length,keyId,e.nonce,e.tag,e.ciphertext,actor]);
  await scanner.query("SET ROLE profitpilot_scanner");
  await assert.rejects(()=>scanner.query("SELECT * FROM private.quarantined_files"),/permission denied/i);
  await assert.rejects(()=>scanner.query("SELECT * FROM public.users"),/permission denied/i);
  await assert.rejects(()=>app.query("SELECT private.claim_quarantine_scan()"),/permission denied/i);
  const claim=(await scanner.query("SELECT * FROM private.claim_quarantine_scan()")).rows[0];
  await assert.rejects(()=>scanner.query("SELECT private.finish_quarantine_scan($1,$2,$3,'clean')",[tenant,batch,claim.lease_id]),/permission denied/i);
  await assert.rejects(()=>scanner.query("SELECT private.finish_quarantine_scan_with_content($1,$2,$3,'infected','validated')",[tenant,batch,claim.lease_id]),/Invalid malware and content verdict/);
  assert.equal(claim.batch_id,batch);
  assert.equal((await scanner.query("SELECT private.finish_quarantine_scan_with_content($1,$2,$3,'clean','validated') AS ok",[tenant,batch,randomUUID()])).rows[0].ok,false);
  assert.equal((await scanner.query("SELECT private.finish_quarantine_scan_with_content($1,$2,$3,'infected','not_checked') AS ok",[tenant,batch,claim.lease_id])).rows[0].ok,true);
  assert.equal((await scanner.query("SELECT private.finish_quarantine_scan_with_content($1,$2,$3,'clean','validated') AS ok",[tenant,batch,claim.lease_id])).rows[0].ok,false);
  await admin.query("UPDATE private.quarantined_files SET created_at=clock_timestamp()-interval '25 hours' WHERE batch_id=$1",[batch]);
  await admin.query("SELECT private.set_import_disposal_hold($1,$2,true,'CI_SCAN_HOLD')",[tenant,batch]);
  await scanner.query("SELECT private.expire_quarantine_bytes()");
  assert.equal((await admin.query("SELECT scan_state FROM private.quarantined_files WHERE batch_id=$1",[batch])).rows[0].scan_state,"infected");
  await admin.query("SELECT private.set_import_disposal_hold($1,$2,false,'CI_SCAN_RELEASE')",[tenant,batch]);
  await scanner.query("SELECT private.expire_quarantine_bytes()");
  assert.deepEqual((await admin.query("SELECT scan_state,ciphertext FROM private.quarantined_files WHERE batch_id=$1",[batch])).rows[0],{scan_state:"disposed",ciphertext:null});
  await assert.rejects(()=>admin.query("INSERT INTO public.raw_import_rows(tenant_id,batch_id,row_number,payload) VALUES($1,$2,1,'{}')",[tenant,batch]),/not approved/i);
  assert.deepEqual((await admin.query("SELECT event_type FROM private.quarantine_lifecycle_events WHERE batch_id=$1 ORDER BY id",[batch])).rows.map(x=>x.event_type),["claimed","infected","disposed"]);
  for(const contentState of ["validated","rejected"]){
   const id=randomUUID(), envelope=sealQuarantine(Buffer.from("synthetic "+id),tenant,id,{id:keyId,secret});
   await admin.query("INSERT INTO public.import_batches(id,tenant_id,source_type,permission_ref,status,file_sha256,file_name,created_by) VALUES($1,$2,'customer_invoice','CI synthetic authority','registered',$3,'synthetic.csv',$4)",[id,tenant,envelope.sha,actor]);
   await admin.query("INSERT INTO private.quarantined_files(tenant_id,batch_id,file_sha256,byte_count,key_id,nonce,auth_tag,ciphertext,uploaded_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",[tenant,id,envelope.sha,envelope.ciphertext.length,keyId,envelope.nonce,envelope.tag,envelope.ciphertext,actor]);
   const claimed=(await scanner.query("SELECT * FROM private.claim_quarantine_scan()")).rows[0];
   assert.equal(claimed.batch_id,id);
   assert.equal((await scanner.query("SELECT private.finish_quarantine_scan_with_content($1,$2,$3,'clean',$4) AS ok",[tenant,id,claimed.lease_id,contentState])).rows[0].ok,true);
   assert.deepEqual((await admin.query("SELECT scan_state,content_state FROM private.quarantined_files WHERE batch_id=$1",[id])).rows[0],{scan_state:"clean",content_state:contentState});
   assert.deepEqual((await admin.query("SELECT event_type FROM private.quarantine_lifecycle_events WHERE batch_id=$1 ORDER BY id",[id])).rows.map(x=>x.event_type),["claimed","clean","content_"+contentState]);
   await assert.rejects(()=>admin.query("INSERT INTO public.raw_import_rows(tenant_id,batch_id,row_number,payload) VALUES($1,$2,1,'{}')",[tenant,id]),/not approved/i);
  }
 }finally{await scanner.query("RESET ROLE");scanner.release();await Promise.all([admin.end(),app.end()]);}
});

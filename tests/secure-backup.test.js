import test from "node:test";
import assert from "node:assert/strict";
import {randomBytes} from "node:crypto";
import {mkdtemp,readFile,writeFile,stat,rm,readdir} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {Readable} from "node:stream";
import {encryptBackup,decryptBackup} from "../scripts/secure-backup.js";

test("encrypted backups roundtrip, reject modification and preserve existing files",async()=>{
 const dir=await mkdtemp(join(tmpdir(),"pp-backup-test-"));
 const key=randomBytes(32).toString("hex"),plain=randomBytes(65537);
 const archive=join(dir,"archive.enc"),output=join(dir,"restore.dump"),modified=join(dir,"modified.enc"),rejected=join(dir,"rejected.dump");
 try{
  await encryptBackup(Readable.from([plain]),archive,key);
  assert.equal((await stat(archive)).mode&0o777,0o600);
  const bytes=await readFile(archive);
  assert.equal(bytes.includes(plain),false);
  await decryptBackup(archive,output,key);
  assert.deepEqual(await readFile(output),plain);
  assert.equal((await stat(output)).mode&0o777,0o600);
  await assert.rejects(()=>encryptBackup(Readable.from(["replacement"]),archive,key),/EEXIST/);
  assert.deepEqual(await readFile(archive),bytes);
  await assert.rejects(()=>decryptBackup(archive,rejected,randomBytes(32).toString("hex")));
  bytes[25]^=1;await writeFile(modified,bytes);
  await assert.rejects(()=>decryptBackup(modified,rejected,key));
  await assert.rejects(()=>stat(rejected),/ENOENT/);
  const failed=join(dir,"failed.enc");
  const producer=Promise.reject(new Error("dump failed"));void producer.catch(()=>{});
  await assert.rejects(()=>encryptBackup(Readable.from(["incomplete"]),failed,key,producer),/dump failed/);
  await assert.rejects(()=>stat(failed),/ENOENT/);
  assert.ok((await readdir(dir)).every(x=>!x.startsWith(".pp-backup-")));
 }finally{await rm(dir,{recursive:true,force:true});}
});

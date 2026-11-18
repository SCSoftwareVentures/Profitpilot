import test from "node:test";
import assert from "node:assert/strict";
import {createConnection} from "node:net";
import {scanClamav} from "../server/clamav.js";
const path=process.env.CLAMAV_TEST_SOCKET;
function wire(command){
 return new Promise((resolve,reject)=>{
  const s=createConnection({path});let result=Buffer.alloc(0);
  s.setTimeout(5000,()=>s.destroy(Error("Timeout")));
  s.on("connect",()=>s.write(command));s.on("data",b=>{result=Buffer.concat([result,b]);if(result.length>1024)s.destroy(Error("Invalid response"));else if(result.includes(0)){s.destroy();resolve(result.subarray(0,result.indexOf(0)).toString());}});
  s.on("error",reject);s.on("end",()=>reject(Error("Incomplete response")));
 });
}
function frame(text){const b=Buffer.from(text),n=Buffer.alloc(4);n.writeUInt32BE(b.length);return Buffer.concat([Buffer.from("zINSTREAM\0"),n,b,Buffer.alloc(4)]);}
test("real ClamAV daemon detects synthetic control and application denies stale or unversioned definitions",{skip:!path,timeout:15000},async()=>{
 assert.match(await wire(Buffer.from("zVERSION\0")),/^ClamAV /);
 assert.equal(await wire(frame("ProfitPilot permitted clean synthetic control")),"stream: OK");
 assert.match(await wire(frame("ProfitPilot disposable scanner detection control 2026")),/^stream: .* FOUND$/);
 await assert.rejects(()=>scanClamav(Buffer.from("ProfitPilot clean"),{socketPath:path}),/definitions are not current/);
});

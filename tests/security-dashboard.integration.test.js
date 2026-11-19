import test from "node:test";
import assert from "node:assert/strict";
import {randomBytes} from "node:crypto";
import {createServer,request} from "node:https";
import {readFileSync} from "node:fs";
import {once} from "node:events";
import pg from "pg";
import {securityReaderConfig} from "../scripts/security-command-centre.js";
import {checkedSecuritySnapshot,dashboardHandler} from "../scripts/security-dashboard.js";
test("live dashboard reads current restricted snapshot through verified database and dashboard TLS",{skip:!process.env.TEST_DASHBOARD_TLS_KEY,timeout:30000},async()=>{
 const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL,max:1});
 const password=randomBytes(32).toString("hex"),token=randomBytes(32).toString("hex");
 const ca=process.env.DATABASE_SSL_CA,cert=readFileSync(process.env.TEST_DASHBOARD_TLS_CERT),tlsKey=readFileSync(process.env.TEST_DASHBOARD_TLS_KEY);
 let pool,server,enabled=false;
 try{
  await admin.query("ALTER ROLE profitpilot_security_reader LOGIN PASSWORD '"+password+"'");enabled=true;
  const url=new URL(process.env.TEST_ADMIN_DATABASE_URL);url.username="profitpilot_security_reader";url.password=password;url.hostname="127.0.0.1";
  pool=new pg.Pool(securityReaderConfig({SECURITY_READER_DATABASE_URL:url.href,SECURITY_READER_DATABASE_CA:ca}));
  const actual=await checkedSecuritySnapshot(pool,{limit:50,cursor:null});assert.equal(actual.catalogVerified,true);
  // Allocate loopback port first; only expose the handler once bound.
  let handler;
  server=createServer({key:tlsKey,cert,minVersion:"TLSv1.2"},(req,res)=>handler(req,res));
  server.listen(0,"127.0.0.1");await once(server,"listening");
  const port=server.address().port,authority="localhost:"+port;
  handler=dashboardHandler({token,authority,snapshot:p=>checkedSecuritySnapshot(pool,p)});
  const query=(authorized,trust=ca)=>new Promise((resolve,reject)=>{
   const req=request({hostname:"127.0.0.1",port,path:"/snapshot?limit=50",method:"GET",ca:trust,rejectUnauthorized:true,headers:{Host:authority,...(authorized?{Authorization:"Bearer "+token}:{})}},res=>{
    let body="";res.on("data",b=>{body+=b;});res.on("end",()=>resolve({status:res.statusCode,report:JSON.parse(body)}));res.on("error",reject);
   });req.on("error",reject);req.end();
  });
  assert.equal((await query(false)).status,401);
  await assert.rejects(()=>query(true,[]));
  const good=await query(true);assert.equal(good.status,200);assert.equal(good.report.catalogVerified,true);
  assert.deepEqual(good.report.counts,actual.counts);
  assert.ok(!JSON.stringify(good).includes(password));
 }finally{
  if(server){server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
  if(pool)await pool.end();
  try{if(enabled)await admin.query("ALTER ROLE profitpilot_security_reader NOLOGIN PASSWORD NULL");}finally{await admin.end();}
 }
});

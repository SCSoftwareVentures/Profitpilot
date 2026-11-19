import test from "node:test";
import assert from "node:assert/strict";
import {createConnection} from "node:net";
import {createBoundedServer} from "../server/network-boundary.js";

function exchange(port,raw){
 return new Promise((resolve,reject)=>{
  const chunks=[];
  const s=createConnection({host:"127.0.0.1",port});
  s.setTimeout(4000,()=>s.destroy(new Error("HTTP boundary test socket timed out")));
  s.on("connect",()=>s.write(raw));
  s.on("data",value=>chunks.push(value));
  s.on("error",reject);
  s.on("close",hadError=>{if(!hadError)resolve(Buffer.concat(chunks).toString("utf8"));});
 });
}
const request=(method="GET",path="/health",headers=[],body="")=>
 [method+" "+path+" HTTP/1.1","Host: localhost","Connection: close",...headers,"",body].join("\r\n");
const responseStatus=response=>Number(/^HTTP\/1\.[01] (\d{3}) /.exec(response)?.[1]);

test("raw HTTP boundary rejects ambiguous framing, excessive headers and unsupported requests before application execution",{timeout:45000},async()=>{
 let handled=0;
 const s=createBoundedServer((req,res)=>{
  handled++;req.resume();req.on("end",()=>res.end("ok"));
 });
 await new Promise(resolve=>s.listen(0,"127.0.0.1",resolve));
 const port=s.address().port;
 try{
  for(const good of [request(),request("POST","/v1/test",["Content-Length: 2","Content-Type: application/json"],"{}"),request("POST","/v1/test",["Transfer-Encoding: chunked"],"2\r\n{}\r\n0\r\n\r\n")]){
   assert.equal(responseStatus(await exchange(port,good)),200);
  }
  assert.equal(handled,3);
  const failures=[
   [request("GET","/health",["Host: second.invalid"]),400],
   [request("GET","/health",["Authorization: Bearer first","authorization: Bearer second"]),400],
   [request("GET","/health",["X-Forwarded-For: 192.0.2.1","x-forwarded-for: 192.0.2.2"]),400],
   [request("POST","/v1/test",["Content-Type: application/json","content-type: text/csv","Content-Length: 0"]),400],
   [request("POST","/v1/test",["Content-Length: 0","Transfer-Encoding: chunked"]),400],
   [request("POST","/v1/test",["Content-Length: 0","Content-Length: 0"]),400],
   [request("POST","/v1/test",["Transfer-Encoding: gzip, chunked"]),400],
   [request("POST","/v1/test",["Expect: 100-continue","Content-Length: 2"]),417],
   [request("POST","/v1/test",["Expect: custom","Content-Length: 0"]),417],
   [request("POST","/v1/test",["Content-Length: 102401"]),413],
   [request("GET","/health",["Content-Length: 2"],"{}"),400],
   [request("GET","/health",["Trailer: Authorization"]),400],
   [request("PUT","/v1/test"),405],
   [request("GET","http://localhost/health"),400],
   [request("GET","//localhost/health"),400],
   [request("GET","/"+ "a".repeat(4096)),414],
   [request("GET","/health",Array.from({length:63},(_,i)=>"X-"+i+": a")),431],
   [request("GET","/health",["X-Large: "+"a".repeat(17000)]),431]
  ];
  for(const [raw,status] of failures){
   assert.equal(responseStatus(await exchange(port,raw)),status,raw.slice(0,100));
   assert.equal(handled,3);
  }
  const pipelined=request("GET","/health",["Authorization: Bearer first","Authorization: Bearer second"]).replace("Connection: close","Connection: keep-alive")+request();
  assert.equal(responseStatus(await exchange(port,pipelined)),400);
  assert.equal(handled,3);
  for(const raw of ["CONNECT localhost:443 HTTP/1.1\r\nHost: localhost\r\n\r\n","GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"]){
   assert.equal(await exchange(port,raw),"");
   assert.equal(handled,3);
  }
  assert.equal(responseStatus(await exchange(port,request())),200);
  assert.equal(handled,4);
 }finally{await new Promise(resolve=>s.close(resolve));}
});

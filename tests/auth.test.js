import test from "node:test";
import assert from "node:assert/strict";
import {createServer} from "node:http";
import {generateKeyPair,exportJWK,SignJWT} from "jose";
import {authRequired} from "../server/auth.js";

test("JWT validation requires expiry, issued-at, bounded age and supports JWKS key rotation",async()=>{
 const issuer="https://profitpilot-auth-test.invalid/";
 const audience="profitpilot-api";
 const first=await generateKeyPair("RS256");
 const second=await generateKeyPair("RS256");
 const firstJwk=await exportJWK(first.publicKey);
 Object.assign(firstJwk,{kid:"key-one",use:"sig",alg:"RS256"});
 const secondJwk=await exportJWK(second.publicKey);
 Object.assign(secondJwk,{kid:"key-two",use:"sig",alg:"RS256"});
 let published=[firstJwk];
 const server=createServer((req,res)=>{
  if(req.url!=="/jwks"){res.writeHead(404).end();return;}
  res.writeHead(200,{"content-type":"application/json","cache-control":"no-store"});
  res.end(JSON.stringify({keys:published}));
 });
 await new Promise(resolve=>server.listen(0,"127.0.0.1",resolve));
 const address=server.address();
 process.env.NODE_ENV="test";
 process.env.AUTH_ISSUER=issuer;
 process.env.AUTH_AUDIENCE=audience;
 process.env.AUTH_JWKS_URL=`http://127.0.0.1:${address.port}/jwks`;
 const middleware=authRequired();
 async function signed(key,kid,{exp="5m",iat=true}={}){
  let jwt=new SignJWT({});
  jwt=jwt.setProtectedHeader({alg:"RS256",kid}).setIssuer(issuer).setAudience(audience).setSubject("subject-1");
  if(iat)jwt=jwt.setIssuedAt();
  if(exp!==null)jwt=jwt.setExpirationTime(exp);
  return jwt.sign(key);
 }
 async function verify(token){
  return new Promise(resolve=>{
   const req={headers:{authorization:"Bearer "+token}};
   const res={status(code){this.code=code;return this;},json(body){resolve({status:this.code,body});}};
   middleware(req,res,()=>resolve({status:200,identity:req.identity}));
  });
 }
 try{
  assert.equal((await verify(await signed(first.privateKey,"key-one"))).status,200);
  assert.equal((await verify(await signed(first.privateKey,"key-one",{exp:"-10s"}))).status,401,"expired access tokens must be rejected");
  assert.equal((await verify(await signed(first.privateKey,"key-one",{exp:null}))).status,401,"tokens without exp must be rejected");
  assert.equal((await verify(await signed(first.privateKey,"key-one",{iat:false}))).status,401,"tokens without iat must be rejected");
  assert.equal((await verify(await signed(first.privateKey,"key-one",{exp:"1h"}))).status,200,"a long expiry must still be bounded by maxTokenAge only if iat is old");
  const oldIssued=new SignJWT({}).setProtectedHeader({alg:"RS256",kid:"key-one"}).setIssuer(issuer).setAudience(audience).setSubject("subject-1").setIssuedAt(Math.floor(Date.now()/1000)-3600).setExpirationTime("1h").sign(first.privateKey);
  assert.equal((await verify(await oldIssued)).status,401,"tokens older than the configured maximum age must be rejected");
  published=[firstJwk,secondJwk];
  const rotated=await verify(await signed(second.privateKey,"key-two"));
  assert.equal(rotated.status,200,"a newly published signing key must be accepted without restarting the API");
 }finally{
  await new Promise(resolve=>server.close(resolve));
 }
});

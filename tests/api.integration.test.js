import test from "node:test";
import assert from "node:assert/strict";
import {createServer} from "node:http";
import {generateKeyPair,exportJWK,SignJWT} from "jose";
import pg from "pg";

const enabled=Boolean(process.env.TEST_ADMIN_DATABASE_URL);
test("authenticated API enforces tenant membership, role permissions and import idempotency",{skip:!enabled},async()=>{
  const issuer="https://profitpilot-ci.invalid/";
  const audience="profitpilot-api";
  const tenantA="11111111-1111-4111-8111-111111111111";
  const tenantB="22222222-2222-4222-8222-222222222222";
  const userA="33333333-3333-4333-8333-333333333333";
  const userB="44444444-4444-4444-8444-444444444444";
  const businessA="55555555-5555-4555-8555-555555555555";
  const contractA="66666666-6666-4666-8666-666666666666";
  const {publicKey,privateKey}=await generateKeyPair("RS256");
  const jwk=await exportJWK(publicKey);
  jwk.kid="profitpilot-ci-key";
  jwk.use="sig";
  jwk.alg="RS256";
  const jwksServer=createServer((req,res)=>{
    if(req.url!=="/.well-known/jwks.json"){res.writeHead(404).end();return;}
    res.writeHead(200,{"content-type":"application/json","cache-control":"no-store"});
    res.end(JSON.stringify({keys:[jwk]}));
  });
  await new Promise(resolve=>jwksServer.listen(0,"127.0.0.1",resolve));
  const jwksAddress=jwksServer.address();
  process.env.NODE_ENV="test";
  process.env.DATABASE_URL=process.env.TEST_APP_DATABASE_URL;
  process.env.AUTH_ISSUER=issuer;
  process.env.AUTH_AUDIENCE=audience;
  process.env.AUTH_JWKS_URL=`http://127.0.0.1:${jwksAddress.port}/.well-known/jwks.json`;
  const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
  const [{default:app},{pool:appPool}]=await Promise.all([import("../server/index.js"),import("../server/db.js")]);
  const api=createServer(app);
  await new Promise(resolve=>api.listen(0,"127.0.0.1",resolve));
  const apiAddress=api.address();
  const base=`http://127.0.0.1:${apiAddress.port}`;
  async function token(subject){
    return new SignJWT({email:subject+"@example.invalid"})
      .setProtectedHeader({alg:"RS256",kid:jwk.kid})
      .setIssuer(issuer).setAudience(audience).setSubject(subject)
      .setIssuedAt().setExpirationTime("5m").sign(privateKey);
  }
  async function request(path,{subject,method="GET",body}={}){
    const headers={};
    if(subject)headers.authorization="Bearer "+await token(subject);
    if(body!==undefined)headers["content-type"]="application/json";
    return fetch(base+path,{method,headers,body:body===undefined?undefined:JSON.stringify(body)});
  }
  try{
    await admin.query("INSERT INTO users(id,auth_subject,email,status) VALUES ($1,'ci-api-analyst','analyst@example.invalid','active'),($2,'ci-api-reader','reader@example.invalid','active') ON CONFLICT(auth_subject) DO UPDATE SET status='active'",[userA,userB]);
    await admin.query("INSERT INTO tenant_memberships(tenant_id,user_id,role,status) VALUES ($1,$2,'analyst','active'),($1,$3,'read_only','active') ON CONFLICT(tenant_id,user_id) DO UPDATE SET role=EXCLUDED.role,status='active'",[tenantA,userA,userB]);
    await admin.query("INSERT INTO businesses(id,tenant_id,name) VALUES ($1,$2,'CI Business A') ON CONFLICT(id) DO NOTHING",[businessA,tenantA]);
    await admin.query("INSERT INTO contracts(id,tenant_id,business_id,customer_name,status) VALUES ($1,$2,$3,'CI Customer A','active') ON CONFLICT(id) DO NOTHING",[contractA,tenantA,businessA]);

    const noToken=await request("/v1/me");
    assert.equal(noToken.status,401,"requests without a bearer token must be rejected");

    const own=await request(`/v1/tenants/${tenantA}/contracts`,{subject:"ci-api-analyst"});
    assert.equal(own.status,200);
    const ownBody=await own.json();
    assert.equal(ownBody.items.length,1);
    assert.equal(ownBody.items[0].id,contractA);

    const otherTenant=await request(`/v1/tenants/${tenantB}/contracts`,{subject:"ci-api-analyst"});
    assert.equal(otherTenant.status,403,"a tenant A member must not access tenant B");

    const invalidTenant=await request("/v1/tenants/not-a-uuid/contracts",{subject:"ci-api-analyst"});
    assert.equal(invalidTenant.status,400);

    const invalidDate=await request(`/v1/tenants/${tenantA}/imports`,{
      subject:"ci-api-analyst",method:"POST",
      body:{sourceType:"payroll",fileName:"payroll.csv",sha256:"a".repeat(64),permissionReference:"CI permission",periodStart:"2026-02-31",periodEnd:"2026-03-01"}
    });
    assert.equal(invalidDate.status,400,"impossible calendar dates must be rejected");

    const importBody={sourceType:"payroll",fileName:"payroll.csv",sha256:"b".repeat(64),permissionReference:"CI permission",periodStart:"2026-02-01",periodEnd:"2026-02-28"};
    const created=await request(`/v1/tenants/${tenantA}/imports`,{subject:"ci-api-analyst",method:"POST",body:importBody});
    assert.equal(created.status,201);
    const duplicate=await request(`/v1/tenants/${tenantA}/imports`,{subject:"ci-api-analyst",method:"POST",body:importBody});
    assert.equal(duplicate.status,200);
    assert.equal((await duplicate.json()).idempotent,true);

    const readerWrite=await request(`/v1/tenants/${tenantA}/imports`,{
      subject:"ci-api-reader",method:"POST",
      body:{...importBody,sha256:"c".repeat(64)}
    });
    assert.equal(readerWrite.status,403,"read_only members must not create imports");
  }finally{
    await new Promise(resolve=>api.close(resolve));
    await admin.end();
    await appPool.end();
    await new Promise(resolve=>jwksServer.close(resolve));
  }
});

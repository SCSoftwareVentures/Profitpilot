import test from "node:test";
import assert from "node:assert/strict";
import {createServer} from "node:http";
import {createHmac,randomBytes} from "node:crypto";
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
  const userC="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const businessA="55555555-5555-4555-8555-555555555555";
  const contractA="66666666-6666-4666-8666-666666666666";
  const businessB="77777777-7777-4777-8777-777777777777";
  const contractB="88888888-8888-4888-8888-888888888888";
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
  if(!process.env.TENANT_CONTEXT_HMAC_SECRET)throw new Error("CI tenant context signing key is required");
  const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
  const [{default:app},{pool:appPool,withTenant}]=await Promise.all([import("../server/index.js"),import("../server/db.js")]);
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
    await admin.query("INSERT INTO users(id,auth_subject,email,status) VALUES ($1,'ci-api-analyst','analyst@example.invalid','active'),($2,'ci-api-reader','reader@example.invalid','active'),($3,'ci-api-tenant-b-only','tenant-b@example.invalid','active') ON CONFLICT(auth_subject) DO UPDATE SET status='active'",[userA,userB,userC]);
    await admin.query("INSERT INTO tenant_memberships(tenant_id,user_id,role,status) VALUES ($1,$2,'analyst','active'),($1,$3,'read_only','active') ON CONFLICT(tenant_id,user_id) DO UPDATE SET role=EXCLUDED.role,status='active'",[tenantA,userA,userB]);
    await admin.query("INSERT INTO tenant_memberships(tenant_id,user_id,role,status) VALUES ($1,$2,'analyst','active') ON CONFLICT(tenant_id,user_id) DO UPDATE SET role=EXCLUDED.role,status='active'",[tenantB,userC]);
    await admin.query("INSERT INTO businesses(id,tenant_id,name) VALUES ($1,$2,'CI Business A') ON CONFLICT(id) DO NOTHING",[businessA,tenantA]);
    await admin.query("INSERT INTO contracts(id,tenant_id,business_id,customer_name,status) VALUES ($1,$2,$3,'CI Customer A','active') ON CONFLICT(id) DO NOTHING",[contractA,tenantA,businessA]);
    await admin.query("INSERT INTO businesses(id,tenant_id,name) VALUES ($1,$2,'CI Business B') ON CONFLICT(id) DO NOTHING",[businessB,tenantB]);
    await admin.query("INSERT INTO contracts(id,tenant_id,business_id,customer_name,status) VALUES ($1,$2,$3,'CI Customer B','active') ON CONFLICT(id) DO NOTHING",[contractB,tenantB,businessB]);
    await assert.rejects(()=>admin.query("INSERT INTO import_batches(id,tenant_id,source_type,permission_ref,status,file_sha256,file_name,created_by) VALUES ($1,$2,'payroll','CI permission','uploaded',$3,'cross-tenant.csv',$4)",["bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",tenantA,"d".repeat(64),userC]),/foreign key constraint/i,"a user who belongs only to tenant B must not be recorded as the creator of a tenant A import");


    // Populate every tenant-owned table with a real tenant B record. This avoids
    // vacuous cross-tenant assertions against empty tables.
    async function insertB(sql,values){return (await admin.query(sql+" RETURNING id",values)).rows[0].id;}
    const siteB=await insertB("INSERT INTO sites(tenant_id,business_id,name) VALUES ($1,$2,'CI Site B')",[tenantB,businessB]);
    await insertB("INSERT INTO contract_versions(tenant_id,contract_id,version_no,effective_from,price,billing_basis,approved_by,approved_at) VALUES ($1,$2,1,'2026-02-01',100,'monthly',$3,now())",[tenantB,contractB,userC]);
    const batchB=await insertB("INSERT INTO import_batches(tenant_id,source_type,permission_ref,status,file_sha256,file_name,created_by) VALUES ($1,'customer_invoice','CI synthetic fixture','uploaded',$2,'tenant-b.csv',$3)",[tenantB,"e".repeat(64),userC]);
    const rawB=await insertB("INSERT INTO raw_import_rows(tenant_id,batch_id,row_number,payload) VALUES ($1,$2,1,'{}')",[tenantB,batchB]);
    await insertB("INSERT INTO mapping_decisions(tenant_id,raw_row_id,target_type,decision,method_version) VALUES ($1,$2,'invoice_row','candidate','ci')",[tenantB,rawB]);
    const payrollB=await insertB("INSERT INTO payroll_pools(tenant_id,batch_id,period_start,period_end,total_amount,source_ref) VALUES ($1,$2,'2026-02-01','2026-02-28',50,'ci')",[tenantB,batchB]);
    const allocationB=await insertB("INSERT INTO allocation_runs(tenant_id,payroll_pool_id,method_version,status,residual_amount) VALUES ($1,$2,'ci','draft',50)",[tenantB,payrollB]);
    await insertB("INSERT INTO allocation_lines(tenant_id,allocation_run_id,site_id,bucket_type,amount) VALUES ($1,$2,$3,'direct',50)",[tenantB,allocationB,siteB]);
    const invoiceB=await insertB("INSERT INTO invoices(tenant_id,direction,invoice_number,invoice_date,total_amount,tax_basis,source_ref) VALUES ($1,'customer','CI-B','2026-02-01',100,'gst_exclusive','ci')",[tenantB]);
    const lineB=await insertB("INSERT INTO invoice_lines(tenant_id,invoice_id,line_number,description,amount,source_row_id) VALUES ($1,$2,1,'CI line',100,$3)",[tenantB,invoiceB,rawB]);
    const matchB=await insertB("INSERT INTO match_reviews(tenant_id,invoice_line_id,contract_id,site_id,confidence,decision) VALUES ($1,$2,$3,$4,'LOW','candidate')",[tenantB,lineB,contractB,siteB]);
    await insertB("INSERT INTO variations(tenant_id,contract_id,site_id,description,status) VALUES ($1,$2,$3,'CI variation','observed')",[tenantB,contractB,siteB]);
    const runB=await insertB("INSERT INTO calculation_runs(tenant_id,contract_id,site_id,period_start,period_end,formula_version,inputs,outputs,completeness,created_by) VALUES ($1,$2,$3,'2026-02-01','2026-02-28','ci','{}','{}','incomplete',$4)",[tenantB,contractB,siteB,userC]);
    await insertB("INSERT INTO audit_events(tenant_id,actor_user_id,action,object_type) VALUES ($1,$2,'ci','fixture')",[tenantB,userC]);

    // Automatically include every current public tenant-owned table (plus tenants)
    // and require its fixture, forced RLS, and both positive and negative visibility.
    const catalog=await admin.query("SELECT c.relname AS name,c.relrowsecurity AS rls,c.relforcerowsecurity AS forced FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='r' AND (c.relname='tenants' OR EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attname='tenant_id' AND NOT a.attisdropped)) ORDER BY c.relname");
    assert.ok(catalog.rowCount>=18,"tenant table inventory must not silently shrink");
    for(const {name,rls,forced} of catalog.rows){
      assert.match(name,/^[a-z_]+$/);
      assert.ok(rls&&forced,name+" must have forced RLS");
    }
    async function visibility(client,expected){
      for(const {name} of catalog.rows){
        const column=name==="tenants"?"id":"tenant_id";
        const result=await client.query(`SELECT DISTINCT ${column} AS tenant FROM "${name}"`);
        if(expected===tenantB)assert.deepEqual(result.rows.map(r=>r.tenant),[tenantB],name+" needs a visible tenant B fixture");
        else if(expected===tenantA)assert.ok(result.rows.every(r=>r.tenant===tenantA),name+" exposed another tenant");
        else assert.equal(result.rowCount,0,name+" exposed rows without signed context");
      }
    }
    await withTenant(tenantB,"ci-api-tenant-b-only",client=>visibility(client,tenantB));
    await withTenant(tenantA,"ci-api-analyst",client=>visibility(client,tenantA));
    await visibility(appPool,null);

    // Role grants are checked on the actual runtime connection. A valid signed
    // context must not turn an analyst into an owner or permit evidence rewrites.
    const denied=[
      "UPDATE tenant_memberships SET role='owner'",
      "DELETE FROM tenant_memberships",
      "INSERT INTO tenant_memberships(tenant_id,user_id,role) SELECT tenant_id,user_id,'owner' FROM tenant_memberships",
      "UPDATE tenants SET status='closed'",
      "UPDATE contracts SET customer_name='tampered'",
      "UPDATE import_batches SET file_sha256='tampered'",
      "UPDATE raw_import_rows SET payload='{}'",
      "DELETE FROM raw_import_rows",
      "UPDATE calculation_runs SET outputs='{}'",
      "DELETE FROM calculation_runs",
      "UPDATE audit_events SET reason='tampered'",
      "DELETE FROM audit_events",
      "TRUNCATE audit_events",
      "UPDATE match_reviews SET evidence='{}'",
      "UPDATE mapping_decisions SET method_version='tampered'"
    ];
    for(const sql of denied){
      await assert.rejects(()=>withTenant(tenantB,"ci-api-tenant-b-only",client=>client.query(sql)),err=>err.code==="42501",sql+" must be denied by runtime grants");
    }
    // Foreign object IDs inside an authorised path must not reveal or mutate B.
    for(const [path,method,body,expected] of [
      [`/v1/tenants/${tenantA}/imports/${batchB}/rows`,"POST",{rows:[{description:"CI"}]},404],
      [`/v1/tenants/${tenantA}/imports/${batchB}/validate`,"POST",{},404],
      [`/v1/tenants/${tenantA}/calculations/${runB}`,"GET",undefined,404],
      [`/v1/tenants/${tenantA}/calculations`,"POST",{contractId:contractB,siteId:siteB,periodStart:"2026-02-01",periodEnd:"2026-02-28"},422]
    ]){
      const response=await request(path,{subject:"ci-api-analyst",method,body});
      assert.equal(response.status,expected,path+" must not expose tenant B objects");
    }
    await admin.query("UPDATE tenant_memberships SET role='reviewer' WHERE tenant_id=$1 AND user_id=$2",[tenantA,userA]);
    try{
      const foreignDecision=await request(`/v1/tenants/${tenantA}/matches/${matchB}/decision`,{subject:"ci-api-analyst",method:"POST",body:{decision:"confirmed",reason:"CI cross tenant probe"}});
      assert.equal(foreignDecision.status,404);
      const unchanged=await admin.query("SELECT decision FROM match_reviews WHERE id=$1",[matchB]);
      assert.equal(unchanged.rows[0].decision,"candidate");
    }finally{
      await admin.query("UPDATE tenant_memberships SET role='analyst' WHERE tenant_id=$1 AND user_id=$2",[tenantA,userA]);
    }

    const noToken=await request("/v1/me");
    assert.equal(noToken.status,401,"requests without a bearer token must be rejected");

    const own=await request(`/v1/tenants/${tenantA}/contracts`,{subject:"ci-api-analyst"});
    assert.equal(own.status,200);
    const ownBody=await own.json();
    assert.equal(ownBody.items.length,1);
    assert.equal(ownBody.items[0].id,contractA);
    const scopedRows=await withTenant(tenantA,"ci-api-analyst",client=>client.query("SELECT id FROM contracts ORDER BY id"));
    assert.deepEqual(scopedRows.rows.map(row=>row.id),[contractA],"database RLS must hide tenant B contract rows even from a tenant A scoped connection");
    const ownIdentityRows=await withTenant(tenantA,"ci-api-analyst",client=>client.query("SELECT auth_subject FROM users ORDER BY auth_subject"));
    assert.deepEqual(ownIdentityRows.rows.map(row=>row.auth_subject),["ci-api-analyst"],"a signed subject may read only its own global identity row");
    const unscopedIdentityRows=await appPool.query("SELECT auth_subject FROM users");
    assert.equal(unscopedIdentityRows.rowCount,0,"the runtime role must not enumerate global identities without signed context");
    await assert.rejects(()=>withTenant(tenantA,"ci-api-analyst",client=>client.query("UPDATE users SET email='changed@example.invalid' WHERE auth_subject='ci-api-analyst'")),/permission denied/i,"the runtime role must not update identity records");
    const rawClient=await appPool.connect();
    try{
      await rawClient.query("BEGIN");
      await rawClient.query("SELECT set_config('app.tenant_id',$1,true)",[tenantB]);
      const forged=await rawClient.query("SELECT id FROM contracts");
      assert.equal(forged.rowCount,0,"a raw custom GUC must not grant tenant access without a valid server HMAC");
      await rawClient.query("ROLLBACK");
    }finally{rawClient.release();}
    async function assertContextDenied({tenantId,subject,expires,nonce,signatureOverride}){
      const keyId="primary";
      const payload=[tenantId,subject,expires,nonce,keyId].join("\n");
      const signature=signatureOverride||createHmac("sha256",Buffer.from(process.env.TENANT_CONTEXT_HMAC_SECRET,"hex")).update(payload).digest("hex");
      const client=await appPool.connect();
      try{
        await client.query("BEGIN");
        await client.query("SELECT set_config('app.tenant_id',$1,true),set_config('app.tenant_subject',$2,true),set_config('app.tenant_expires',$3,true),set_config('app.tenant_nonce',$4,true),set_config('app.tenant_key_id',$5,true),set_config('app.tenant_signature',$6,true)",[tenantId,subject,expires,nonce,keyId,signature]);
        const result=await client.query("SELECT id FROM contracts");
        assert.equal(result.rowCount,0,"invalid tenant context must return no protected rows");
        await client.query("ROLLBACK");
      }finally{client.release();}
    }
    const future=String(Math.floor(Date.now()/1000)+30);
    const past=String(Math.floor(Date.now()/1000)-5);
    await assertContextDenied({tenantId:tenantA,subject:"ci-api-analyst",expires:future,nonce:randomBytes(16).toString("hex"),signatureOverride:"0".repeat(64)});
    await assertContextDenied({tenantId:tenantA,subject:"ci-api-analyst",expires:past,nonce:randomBytes(16).toString("hex")});
    await assertContextDenied({tenantId:tenantA,subject:"ci-api-nonmember",expires:future,nonce:randomBytes(16).toString("hex")});
    await assert.rejects(()=>withTenant(tenantA,"ci-api-analyst",client=>client.query("SELECT secret FROM private.tenant_context_keys")),/permission denied/i,"runtime role must not read the tenant signing key");
    const roleAudit=await admin.query("SELECT rolbypassrls,rolsuper,rolcanlogin FROM pg_roles WHERE rolname='profitpilot_app'");
    assert.deepEqual(roleAudit.rows[0],{rolbypassrls:false,rolsuper:false,rolcanlogin:true},"runtime role must remain login-capable but must not bypass RLS or be superuser");
    const primarySecret=process.env.TENANT_CONTEXT_HMAC_SECRET;
    const primaryKeyId=process.env.TENANT_CONTEXT_HMAC_KEY_ID||"primary";
    const secondarySecret=randomBytes(32).toString("hex");
    await admin.query("INSERT INTO private.tenant_context_keys(key_id,secret,active) VALUES ('rotation-next',decode($1,'hex'),true)",[secondarySecret]);
    const primaryDuringOverlap=await withTenant(tenantA,"ci-api-analyst",client=>client.query("SELECT id FROM contracts"));
    assert.equal(primaryDuringOverlap.rowCount,1,"the original key must remain valid during the overlap window");
    process.env.TENANT_CONTEXT_HMAC_SECRET=secondarySecret;
    process.env.TENANT_CONTEXT_HMAC_KEY_ID="rotation-next";
    const secondaryDuringOverlap=await withTenant(tenantA,"ci-api-analyst",client=>client.query("SELECT id FROM contracts"));
    assert.equal(secondaryDuringOverlap.rowCount,1,"the replacement key must work before revoking the original");
    await admin.query("UPDATE private.tenant_context_keys SET active=false WHERE key_id=$1",[primaryKeyId]);
    process.env.TENANT_CONTEXT_HMAC_SECRET=primarySecret;
    process.env.TENANT_CONTEXT_HMAC_KEY_ID=primaryKeyId;
    const revokedPrimary=await withTenant(tenantA,"ci-api-analyst",client=>client.query("SELECT id FROM contracts"));
    assert.equal(revokedPrimary.rowCount,0,"a revoked signing key must no longer authorise tenant rows");
    process.env.TENANT_CONTEXT_HMAC_SECRET=secondarySecret;
    process.env.TENANT_CONTEXT_HMAC_KEY_ID="rotation-next";
    const activeSecondary=await withTenant(tenantA,"ci-api-analyst",client=>client.query("SELECT id FROM contracts"));
    assert.equal(activeSecondary.rowCount,1,"the replacement key must remain valid after old-key revocation");
    const afterCommit=await appPool.query("SELECT current_setting('app.tenant_id',true) AS tenant_id");
    assert.ok(afterCommit.rows[0].tenant_id===null||afterCommit.rows[0].tenant_id==="","tenant context must not leak after a transaction returns its pooled connection");
    await assert.rejects(()=>withTenant(tenantA,"ci-api-analyst",client=>client.query("INSERT INTO import_batches(tenant_id,source_type,permission_ref,status,file_sha256,file_name,created_by) VALUES ($1,'payroll','CI probe','uploaded',$2,'probe.csv',$3)",[tenantB,"f".repeat(64),userC])),/row-level security/i,"RLS WITH CHECK must reject cross-tenant writes on an insert-enabled table");

    const otherTenant=await request(`/v1/tenants/${tenantB}/contracts`,{subject:"ci-api-analyst"});
    assert.equal(otherTenant.status,403,"a tenant A member must not access tenant B");

    const invalidTenant=await request("/v1/tenants/not-a-uuid/contracts",{subject:"ci-api-analyst"});
    assert.equal(invalidTenant.status,400);

    const invalidDate=await request(`/v1/tenants/${tenantA}/imports`,{
      subject:"ci-api-analyst",method:"POST",
      body:{sourceType:"payroll",fileName:"payroll.csv",sha256:"a".repeat(64),permissionReference:"CI permission",periodStart:"2026-02-31",periodEnd:"2026-03-01"}
    });
    assert.equal(invalidDate.status,400,"impossible calendar dates must be rejected");

    const importBody={sourceType:"payroll",fileName:"payroll.csv",sha256:"b".repeat(64),permissionReference:"CI permission",periodStart:"2026-02-01",periodEnd:"2026-02-28",tenantId:tenantB};
    const created=await request(`/v1/tenants/${tenantA}/imports`,{subject:"ci-api-analyst",method:"POST",body:importBody});
    assert.equal(created.status,201);
    const createdBody=await created.json();
    const storedBatch=await admin.query("SELECT tenant_id FROM import_batches WHERE id=$1",[createdBody.batch.id]);
    assert.equal(storedBatch.rows[0].tenant_id,tenantA,"client-supplied tenant identifiers must not override the authenticated path tenant");
    const duplicate=await request(`/v1/tenants/${tenantA}/imports`,{subject:"ci-api-analyst",method:"POST",body:importBody});
    assert.equal(duplicate.status,200);
    assert.equal((await duplicate.json()).idempotent,true);

    const readerWrite=await request(`/v1/tenants/${tenantA}/imports`,{
      subject:"ci-api-reader",method:"POST",
      body:{...importBody,sha256:"c".repeat(64)}
    });
    assert.equal(readerWrite.status,403,"read_only members must not create imports");

    await admin.query("UPDATE tenant_memberships SET status='revoked' WHERE tenant_id=$1 AND user_id=$2",[tenantA,userA]);
    const revoked=await request(`/v1/tenants/${tenantA}/contracts`,{subject:"ci-api-analyst"});
    assert.equal(revoked.status,403,"revoked memberships must lose access immediately");
  }finally{
    await new Promise(resolve=>api.close(resolve));
    await admin.end();
    await appPool.end();
    await new Promise(resolve=>jwksServer.close(resolve));
  }
});

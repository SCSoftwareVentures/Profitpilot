import test from "node:test";
import assert from "node:assert/strict";
import {createServer} from "node:http";
import {createHash,createHmac,randomBytes} from "node:crypto";
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
  const [{default:app,requestLimiter},{pool:appPool,withTenant}]=await Promise.all([import("../server/index.js"),import("../server/db.js")]);
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
    await insertB("INSERT INTO payroll_source_records(tenant_id,raw_row_id,payroll_pool_id,source_ref,amount) VALUES ($1,$2,$3,'CI-B:source',50)",[tenantB,rawB,payrollB]);
    const allocationB=await insertB("INSERT INTO allocation_runs(tenant_id,payroll_pool_id,method_version,status,residual_amount) VALUES ($1,$2,'ci','draft',50)",[tenantB,payrollB]);
    await insertB("INSERT INTO allocation_lines(tenant_id,allocation_run_id,site_id,bucket_type,amount) VALUES ($1,$2,$3,'direct',50)",[tenantB,allocationB,siteB]);
    const invoiceB=await insertB("INSERT INTO invoices(tenant_id,direction,invoice_number,invoice_date,total_amount,tax_basis,source_ref) VALUES ($1,'customer','CI-B','2026-02-01',100,'gst_exclusive','ci')",[tenantB]);
    const lineB=await insertB("INSERT INTO invoice_lines(tenant_id,invoice_id,line_number,description,amount,source_row_id) VALUES ($1,$2,1,'CI line',100,$3)",[tenantB,invoiceB,rawB]);
    const matchB=await insertB("INSERT INTO match_reviews(tenant_id,invoice_line_id,contract_id,site_id,confidence,decision) VALUES ($1,$2,$3,$4,'LOW','candidate')",[tenantB,lineB,contractB,siteB]);
    await insertB("INSERT INTO variations(tenant_id,contract_id,site_id,description,status) VALUES ($1,$2,$3,'CI variation','observed')",[tenantB,contractB,siteB]);
    const runB=await insertB("INSERT INTO calculation_runs(tenant_id,contract_id,site_id,period_start,period_end,formula_version,inputs,outputs,completeness,created_by) VALUES ($1,$2,$3,'2026-02-01','2026-02-28','ci','{}','{}','incomplete',$4)",[tenantB,contractB,siteB,userC]);
    await insertB("INSERT INTO audit_events(tenant_id,actor_user_id,action,object_type) VALUES ($1,$2,'ci','fixture')",[tenantB,userC]);

    const fixtureBytes=Buffer.from("invoice_id,site,date,amount\nCI-B,Site B,2026-02-01,10.00\n");
    const fixtureHash=createHash("sha256").update(fixtureBytes).digest("hex");
    const verifiedB=await insertB("INSERT INTO import_batches(tenant_id,source_type,source_period_start,source_period_end,permission_ref,status,file_sha256,file_name,created_by) VALUES ($1,'customer_invoice','2026-02-01','2026-02-28','CI','uploaded',$2,'verified-b.csv',$3)",[tenantB,fixtureHash,userC]);
    await admin.query("INSERT INTO raw_import_rows(tenant_id,batch_id,row_number,payload) VALUES($1,$2,1,$3)",[tenantB,verifiedB,JSON.stringify({invoice_id:"CI-B",site:"Site B",date:"2026-02-01",amount:"10.00"})]);
    await admin.query("INSERT INTO import_source_receipts(tenant_id,batch_id,sha256,byte_count,row_count,parser_version,original_bytes,received_by) VALUES($1,$2,$3,$4,1,'strict-csv-0.1.0',$5,$6)",[tenantB,verifiedB,fixtureHash,fixtureBytes.length,fixtureBytes,userC]);

    const verifiedRawB=(await admin.query("SELECT id FROM raw_import_rows WHERE tenant_id=$1 AND batch_id=$2 AND row_number=1",[tenantB,verifiedB])).rows[0].id;
    await admin.query("INSERT INTO mapping_decisions(tenant_id,raw_row_id,target_type,decision,method_version) VALUES($1,$2,'invoice_row','candidate','invoice-validator-0.1.0')",[tenantB,verifiedRawB]);
    await admin.query("UPDATE import_batches SET status='review' WHERE id=$1",[verifiedB]);
    const claimB=await insertB("INSERT INTO invoice_identity_claims(tenant_id,raw_row_id,direction,issuer_key,invoice_reference,source_integrity,reviewer_id,evidence_reference,reason) VALUES($1,$2,'customer','ci.issuer-a','CI-B','byte_verified',$3,'CI fixture','CI reviewed fixture')",[tenantB,verifiedRawB,userC]);

    await admin.query("UPDATE tenants SET invoice_rehearsal_enabled=true WHERE id=$1",[tenantB]);
    await admin.query("UPDATE tenant_memberships SET role='reviewer' WHERE tenant_id=$1 AND user_id=$2",[tenantB,userC]);
    const rehearsalB=await insertB("INSERT INTO invoice_confirmation_rehearsals(tenant_id,claim_id,contract_id,site_id,reviewer_id,service_start,service_end,currency,tax_basis,cost_kind,evidence_reference) VALUES($1,$2,$3,$4,$5,'2026-02-01','2026-02-28','AUD','gst_exclusive','revenue','CI.fixture')",[tenantB,claimB,contractB,siteB,userC]);
    await admin.query("UPDATE tenant_memberships SET role='analyst' WHERE tenant_id=$1 AND user_id=$2",[tenantB,userC]);
    await admin.query("UPDATE tenant_memberships SET role='reviewer' WHERE tenant_id=$1 AND user_id=$2",[tenantB,userC]);
    const payrollBatchB=await insertB("INSERT INTO import_batches(tenant_id,source_type,source_period_start,source_period_end,permission_ref,status,file_sha256,file_name,created_by) VALUES($1,'payroll','2026-02-01','2026-02-28','CI','uploaded',$2,'rehearsal-payroll-b.csv',$3)",[tenantB,"8".repeat(64),userC]);
    const payrollRawB=await insertB("INSERT INTO raw_import_rows(tenant_id,batch_id,row_number,payload) VALUES($1,$2,1,$3)",[tenantB,payrollBatchB,JSON.stringify({source_ref:"CI-B:rehearsal-pay",amount:"20.00",currency:"AUD",period_start:"2026-02-01",period_end:"2026-02-28"})]);
    await insertB("INSERT INTO mapping_decisions(tenant_id,raw_row_id,target_type,decision,method_version) VALUES($1,$2,'payroll_row','candidate','payroll-validator-0.1.0')",[tenantB,payrollRawB]);
    await admin.query("UPDATE import_batches SET status='review' WHERE id=$1",[payrollBatchB]);
    const rehearsalPoolB=await insertB("INSERT INTO payroll_pools(tenant_id,batch_id,period_start,period_end,total_amount,currency,source_ref) VALUES($1,$2,'2026-02-01','2026-02-28',20,'AUD','reconciled:CI-rehearsal-b')",[tenantB,payrollBatchB]);
    const rehearsalRunB=await insertB("INSERT INTO allocation_runs(tenant_id,payroll_pool_id,method_version,status,direct_amount,residual_amount,reviewer_id) VALUES($1,$2,'payroll-source-row-0.2.0','draft',20,0,$3)",[tenantB,rehearsalPoolB,userC]);
    const rehearsalSourceB=await insertB("INSERT INTO payroll_source_records(tenant_id,raw_row_id,payroll_pool_id,source_ref,amount) VALUES($1,$2,$3,'CI-B:rehearsal-pay',20)",[tenantB,payrollRawB,rehearsalPoolB]);
    const rehearsalLineB=await insertB("INSERT INTO allocation_lines(tenant_id,allocation_run_id,site_id,bucket_type,amount,source_ref,source_record_id) VALUES($1,$2,$3,'direct',20,'CI-B:rehearsal-pay',$4)",[tenantB,rehearsalRunB,siteB,rehearsalSourceB]);
    await admin.query("UPDATE allocation_runs SET status='confirmed' WHERE id=$1",[rehearsalRunB]);
    await admin.query("UPDATE import_batches SET status='accepted' WHERE id=$1",[payrollBatchB]);
    await insertB("INSERT INTO payroll_contract_rehearsals(tenant_id,allocation_line_id,contract_id,reviewer_id,evidence_reference) VALUES($1,$2,$3,$4,'CI.B.attribution')",[tenantB,rehearsalLineB,contractB,userC]);
    await admin.query("UPDATE tenant_memberships SET role='analyst' WHERE tenant_id=$1 AND user_id=$2",[tenantB,userC]);
    const fixturePrivacy=await insertB("INSERT INTO privacy_requests(tenant_id,requester_id,client_request_id,request_type) VALUES($1,$2,gen_random_uuid(),'access')",[tenantB,userC]);
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
    const blockedMatch=await withTenant(tenantB,"ci-api-tenant-b-only",c=>c.query("UPDATE match_reviews SET decision='confirmed',reviewer_id=$1,reviewed_at=now() WHERE id=$2",[userC,matchB]));
    assert.equal(blockedMatch.rowCount,0,"database must deny analyst match confirmation");
    await assert.rejects(()=>withTenant(tenantB,"ci-api-tenant-b-only",c=>c.query("UPDATE mapping_decisions SET decision='accepted' WHERE raw_row_id=$1",[rawB])),e=>e.code==="42501");

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
      "SELECT original_bytes FROM import_source_receipts",
      "UPDATE import_source_receipts SET sha256='tampered'",
      "DELETE FROM import_source_receipts",
      "DELETE FROM payroll_source_records",
      "UPDATE payroll_pools SET total_amount=0",
      "UPDATE allocation_lines SET amount=0",
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

    // Synthetic identity preview must never approve or persist financial data.
    const previewPath=`/v1/tenants/${tenantA}/prototype/invoice-identity-preview`;
    const previewBody={synthetic:true,rows:[
      {direction:"supplier",issuerKey:"A",invoiceReference:"001"},
      {direction:"supplier",issuerKey:"A",invoiceReference:"001"},
      {direction:"supplier",issuerKey:"B",invoiceReference:"001"},
      {direction:"supplier",issuerKey:"",invoiceReference:"001"}
    ]};
    const snapshot=async()=> (await admin.query("SELECT (SELECT count(*) FROM invoices WHERE tenant_id=$1) AS invoices,(SELECT count(*) FROM mapping_decisions WHERE tenant_id=$1) AS mappings,(SELECT count(*) FROM match_reviews WHERE tenant_id=$1) AS matches",[tenantA])).rows[0];
    const beforePreview=await snapshot();
    const preview=await request(previewPath,{subject:"ci-api-analyst",method:"POST",body:previewBody});
    assert.equal(preview.status,200);
    assert.equal(preview.headers.get("cache-control"),"no-store");
    const previewResult=await preview.json();
    assert.equal(previewResult.automaticallyAccepted,0);
    assert.equal(previewResult.issuerAuthenticated,false);
    assert.deepEqual(previewResult.items.map(x=>x.status),["held","held","candidate","held"]);
    const reversed=await request(previewPath,{subject:"ci-api-analyst",method:"POST",body:{...previewBody,rows:[...previewBody.rows].reverse()}});
    assert.equal(reversed.status,200);
    assert.deepEqual((await reversed.json()).items.map(({status,reason})=>({status,reason})).reverse(),previewResult.items.map(({status,reason})=>({status,reason})));
    for(const [subject,body,status] of [
      [undefined,previewBody,401],
      ["ci-api-reader",previewBody,403],
      ["ci-api-tenant-b-only",previewBody,403],
      ["ci-api-analyst",{...previewBody,synthetic:false},400],
      ["ci-api-analyst",{synthetic:true,rows:[{...previewBody.rows[0],amount:100}]},400],
      ["ci-api-analyst",{synthetic:true,rows:Array(201).fill(previewBody.rows[0])},400]
    ]){
      assert.equal((await request(previewPath,{subject,method:"POST",body})).status,status);
    }
    assert.deepEqual(await snapshot(),beforePreview,"preview must not persist financial or mapping records");

    // HTTP authentication rejects missing expiry, excessive lifetime and malformed subject.
    const rawJwt=async({subject="ci-api-analyst",expiry,issued=true}={})=>{
      let jwt=new SignJWT({}).setProtectedHeader({alg:"RS256",kid:jwk.kid}).setIssuer(issuer).setAudience(audience).setSubject(subject);
      if(issued)jwt=jwt.setIssuedAt();if(expiry!==undefined)jwt=jwt.setExpirationTime(expiry);
      return jwt.sign(privateKey);
    };
    for(const jwt of [await rawJwt(),await rawJwt({expiry:"2h"}),await rawJwt({expiry:"5m",issued:false}),await rawJwt({expiry:"5m",subject:"bad\nsubject"}),await rawJwt({expiry:Math.floor(Date.now()/1000)-60})]){
      const denial=await fetch(base+"/v1/me",{headers:{authorization:"Bearer "+jwt}});
      assert.equal(denial.status,401);assert.equal(denial.headers.get("cache-control"),"no-store");
    }
    const noToken=await request("/v1/me");
    assert.equal(noToken.status,401,"requests without a bearer token must be rejected");

    const own=await request(`/v1/tenants/${tenantA}/contracts`,{subject:"ci-api-analyst"});
    assert.equal(own.status,200);
    assert.equal(own.headers.get("cache-control"),"no-store");
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
    await assert.rejects(()=>withTenant(tenantA,"ci-api-analyst",c=>c.query("INSERT INTO audit_events(tenant_id,actor_user_id,action,object_type) VALUES($1,$2,'forged','fixture')",[tenantA,userB])),e=>e.code==="42501");
    // An authenticated analyst must not forge action names, fabricate a source
    // verification, or create audit entries for another tenant's objects.
    const forgeAudit=(action,kind,id=createdBody.batch.id)=>withTenant(tenantA,"ci-api-analyst",
      c=>c.query("INSERT INTO audit_events(tenant_id,actor_user_id,action,object_type,object_id,metadata) VALUES($1,$2,$3,$4,$5,'{}')",[tenantA,userA,action,kind,id]));
    await assert.rejects(()=>forgeAudit("fake_verified","import_batch"),e=>e.code==="23514");
    await assert.rejects(()=>forgeAudit("source_file_verified","import_batch"),e=>e.code==="23514");
    await assert.rejects(()=>forgeAudit("source_file_verified","fixture"),e=>e.code==="23514");
    await assert.rejects(()=>forgeAudit("source_file_verified","import_batch",batchB),e=>e.code==="23514");
    await assert.rejects(()=>withTenant(tenantA,"ci-api-reader",c=>c.query("INSERT INTO raw_import_rows(tenant_id,batch_id,row_number,payload) VALUES($1,$2,1,'{}')",[tenantA,createdBody.batch.id])),e=>e.code==="42501");
    const storedBatch=await admin.query("SELECT tenant_id FROM import_batches WHERE id=$1",[createdBody.batch.id]);
    assert.equal(storedBatch.rows[0].tenant_id,tenantA,"client-supplied tenant identifiers must not override the authenticated path tenant");
    const duplicate=await request(`/v1/tenants/${tenantA}/imports`,{subject:"ci-api-analyst",method:"POST",body:importBody});
    assert.equal(duplicate.status,200);
    assert.equal((await duplicate.json()).idempotent,true);


    const differentMetadata=await request(`/v1/tenants/${tenantA}/imports`,{subject:"ci-api-analyst",method:"POST",body:{...importBody,permissionReference:"different"}});
    assert.equal(differentMetadata.status,409,"source hash must not silently accept different metadata");
    const inv=await request(`/v1/tenants/${tenantA}/imports`,{subject:"ci-api-analyst",method:"POST",body:{...importBody,sourceType:"customer_invoice",fileName:"invoice.csv",sha256:"1".repeat(64)}});
    assert.equal(inv.status,201);
    const batchId=(await inv.json()).batch.id;
    const path=`/v1/tenants/${tenantA}/imports/${batchId}`;
    const row1={invoice_id:"CI-1",site:"CI site",date:"2026-02-01",amount:"100.00"};
    const row2={...row1,invoice_id:"CI-2"};
    const row3={...row1,invoice_id:"CI-3"};
    const post=(suffix,body)=>request(path+suffix,{subject:"ci-api-analyst",method:"POST",body});
    assert.equal((await post("/rows",{startRow:2,rows:[row2]})).status,409,"gaps rejected");
    assert.equal((await post("/rows",{rows:[{...row1,employee_name:"CI unwanted personal data"}]})).status,422);
    assert.equal((await post("/rows",{rows:[{...row1,site:{name:"CI unwanted nested data"}}]})).status,422);
    assert.equal((await admin.query("SELECT count(*)::int AS n FROM raw_import_rows WHERE batch_id=$1",[batchId])).rows[0].n,0);
    await assert.rejects(()=>withTenant(tenantA,"ci-api-analyst",c=>c.query("INSERT INTO raw_import_rows(tenant_id,batch_id,row_number,payload) VALUES($1,$2,1,$3)",[tenantA,batchId,JSON.stringify({...row1,employee_name:"CI forbidden field"})])),e=>e.code==="23514");
    await assert.rejects(()=>withTenant(tenantA,"ci-api-analyst",c=>c.query("INSERT INTO raw_import_rows(tenant_id,batch_id,row_number,payload) VALUES($1,$2,1,$3)",[tenantA,batchId,JSON.stringify({...row1,site:"CI\u202eprivate"})])),e=>e.code==="23514","direct SQL cannot bypass Unicode bidi privacy controls");
    const first=await post("/rows",{rows:[row1]});
    assert.equal(first.status,201);
    assert.equal((await first.json()).inserted,1);
    const retry=await post("/rows",{rows:[row1]});
    assert.equal(retry.status,200);
    assert.equal((await retry.json()).duplicates,1);
    assert.equal((await post("/rows",{rows:[{...row1,amount:"999"},row2]})).status,409,"conflicting overlap rolls back entire chunk");
    assert.equal((await admin.query("SELECT count(*)::int AS n FROM raw_import_rows WHERE batch_id=$1",[batchId])).rows[0].n,1);
    const concurrent=await Promise.all([post("/rows",{startRow:2,rows:[row2,row3]}),post("/rows",{startRow:2,rows:[row2,row3]})]);
    assert.deepEqual(concurrent.map(r=>r.status).sort(),[200,201],"only one concurrent append creates rows");
    const persisted=await admin.query("SELECT row_number,payload FROM raw_import_rows WHERE batch_id=$1 ORDER BY row_number",[batchId]);
    assert.deepEqual(persisted.rows.map(r=>r.row_number),[1,2,3]);
    assert.deepEqual(persisted.rows.map(r=>r.payload),[row1,row2,row3]);
    const validation=await post("/validate",{});
    assert.equal(validation.status,200);
    assert.equal((await validation.json()).validCandidateRows,3);
    await admin.query("UPDATE mapping_decisions SET decision='accepted',reason='CI human review' WHERE raw_row_id=(SELECT id FROM raw_import_rows WHERE batch_id=$1 AND row_number=1)",[batchId]);
    assert.equal((await post("/validate",{})).status,200);
    const decisions=await admin.query("SELECT m.decision,m.reason FROM mapping_decisions m JOIN raw_import_rows r ON r.id=m.raw_row_id WHERE r.batch_id=$1 ORDER BY r.row_number",[batchId]);
    assert.equal(decisions.rowCount,3);
    assert.deepEqual(decisions.rows[0],{decision:"accepted",reason:"CI human review"});
    assert.equal((await post("/rows",{startRow:4,rows:[row3]})).status,409,"validation seals rows");
    assert.equal((await post("/rows",{startRow:1,rows:[row1]})).status,200,"exact retry remains safe after sealing");
    assert.equal((await request(`/v1/tenants/${tenantA}/imports/not-a-uuid/rows`,{subject:"ci-api-analyst",method:"POST",body:{rows:[row1]}})).status,400);



    // Persistent invoice claims: independent cross-batch conflicts and reviewer-only reservations.
    const duplicateBatch=(await admin.query("INSERT INTO import_batches(tenant_id,source_type,permission_ref,status,file_sha256,file_name,created_by) VALUES($1,'customer_invoice','CI','review',$2,'duplicate-review.csv',$3) RETURNING id",[tenantA,"8".repeat(64),userA])).rows[0].id;
    const cloneRow=(await admin.query("INSERT INTO raw_import_rows(tenant_id,batch_id,row_number,payload) VALUES($1,$2,1,$3) RETURNING id",[tenantA,duplicateBatch,JSON.stringify({...row2,invoice_id:"ci-2"})])).rows[0].id;
    await admin.query("INSERT INTO mapping_decisions(tenant_id,raw_row_id,target_type,decision,method_version) VALUES($1,$2,'invoice_row','candidate','invoice-validator-0.1.0')",[tenantA,cloneRow]);
    const identityPath=path+"/invoice-identities";
    const dupPath=`/v1/tenants/${tenantA}/imports/${duplicateBatch}/invoice-identities`;
    const claimBody={rowNumber:2,issuerKey:"ci.issuer-a",evidenceReference:"CI synthetic issuer register",reason:"CI reviewed identity"};
    const reviewList=await request(identityPath,{subject:"ci-api-analyst"});
    assert.equal(reviewList.status,200);
    assert.equal((await reviewList.json()).items[1].other_batch_count,1);
    assert.equal((await request(identityPath,{subject:"ci-api-reader"})).status,403);
    assert.equal((await request(identityPath,{subject:"ci-api-analyst",method:"POST",body:claimBody})).status,403);
    const realRaw=(await admin.query("SELECT id FROM raw_import_rows WHERE batch_id=$1 AND row_number=2",[batchId])).rows[0].id;
    await assert.rejects(()=>withTenant(tenantA,"ci-api-analyst",c=>c.query("INSERT INTO invoice_identity_claims(tenant_id,raw_row_id,direction,issuer_key,invoice_reference,source_integrity,reviewer_id,evidence_reference,reason) VALUES($1,$2,'customer','ci.issuer-a','CI-2','client_declared',$3,'CI source','CI review')",[tenantA,realRaw,userA])),e=>e.code==="42501");
    await admin.query("UPDATE tenant_memberships SET role='reviewer' WHERE tenant_id=$1 AND user_id=$2",[tenantA,userA]);
    try{
      const reserve=(url,body)=>request(url,{subject:"ci-api-analyst",method:"POST",body});
      const claim=await reserve(identityPath,claimBody);
      assert.equal(claim.status,201);
      const claimed=await claim.json();
      assert.equal(claimed.financialInclusionAuthorized,false);
      assert.equal(claimed.issuerAuthenticated,false);
      assert.equal(claimed.claim.source_integrity,"client_declared");
      assert.equal((await reserve(identityPath,claimBody)).status,200);
      assert.equal((await reserve(dupPath,{...claimBody,rowNumber:1})).status,409);
      assert.equal((await reserve(dupPath,{...claimBody,rowNumber:1,issuerKey:"ci.issuer-b"})).status,201);
      await assert.rejects(()=>withTenant(tenantA,"ci-api-analyst",c=>c.query("UPDATE invoice_identity_claims SET reason='changed' WHERE id=$1",[claimed.claim.id])),e=>e.code==="42501");
      const cross=await withTenant(tenantB,"ci-api-tenant-b-only",c=>c.query("SELECT id FROM invoice_identity_claims"));
      assert.deepEqual(cross.rows.map(r=>r.id),[claimB]);
      assert.equal((await admin.query("SELECT count(*)::int AS n FROM invoice_identity_claims WHERE tenant_id=$1",[tenantA])).rows[0].n,2);
      assert.equal((await admin.query("SELECT count(*)::int AS n FROM audit_events WHERE tenant_id=$1 AND action='invoice_identity_reserved'",[tenantA])).rows[0].n,2);
    }finally{await admin.query("UPDATE tenant_memberships SET role='analyst' WHERE tenant_id=$1 AND user_id=$2",[tenantA,userA]);}

    // Calculation success and fail-closed period/currency checks.
    async function insertFixture(sql,values){return (await admin.query(sql+" RETURNING id",values)).rows[0].id;}
    const siteA=await insertFixture("INSERT INTO sites(tenant_id,business_id,name) VALUES ($1,$2,'CI reconciliation site')",[tenantA,businessA]);
    const versionA=await insertFixture("INSERT INTO contract_versions(tenant_id,contract_id,version_no,effective_from,effective_to,price,billing_basis,approved_by,approved_at) VALUES ($1,$2,1,'2026-02-05','2026-02-28',100,'monthly',$3,now())",[tenantA,contractA,userA]);
    const poolA=await insertFixture("INSERT INTO payroll_pools(tenant_id,batch_id,period_start,period_end,total_amount,currency,source_ref) VALUES ($1,$2,'2026-02-01','2026-02-28',50,'USD','ci')",[tenantA,createdBody.batch.id]);
    const allocationA=await insertFixture("INSERT INTO allocation_runs(tenant_id,payroll_pool_id,method_version,status,direct_amount,residual_amount) VALUES ($1,$2,'ci','confirmed',50,0)",[tenantA,poolA]);
    const allocationLineA=await insertFixture("INSERT INTO allocation_lines(tenant_id,allocation_run_id,site_id,bucket_type,amount) VALUES ($1,$2,$3,'direct',50)",[tenantA,allocationA,siteA]);
    const invoiceA=await insertFixture("INSERT INTO invoices(tenant_id,direction,invoice_number,invoice_date,total_amount,tax_basis,source_ref) VALUES ($1,'customer','CI-A','2026-02-14',100,'gst_exclusive','ci')",[tenantA]);
    const lineA=await insertFixture("INSERT INTO invoice_lines(tenant_id,invoice_id,line_number,description,amount) VALUES ($1,$2,1,'CI line',100)",[tenantA,invoiceA]);
    const matchA=await insertFixture("INSERT INTO match_reviews(tenant_id,invoice_line_id,contract_id,site_id,service_period_start,service_period_end,confidence,decision,reviewer_id,reviewed_at) VALUES ($1,$2,$3,$4,'2026-02-01','2026-02-28','HIGH','confirmed',$5,now())",[tenantA,lineA,contractA,siteA,userA]);
    const calculate=()=>request(`/v1/tenants/${tenantA}/calculations`,{subject:"ci-api-analyst",method:"POST",body:{contractId:contractA,siteId:siteA,periodStart:"2026-02-01",periodEnd:"2026-02-28"}});
    const partial=await calculate();
    assert.equal(partial.status,422);
    assert.match((await partial.json()).error,/entire requested period/);
    await admin.query("UPDATE contract_versions SET effective_from='2026-02-01' WHERE id=$1",[versionA]);
    const mixed=await calculate();
    assert.equal(mixed.status,422);
    assert.match((await mixed.json()).error,/Payroll currency/);
    await admin.query("UPDATE payroll_pools SET currency='AUD' WHERE id=$1",[poolA]);
    const overlapping=await insertFixture("INSERT INTO contract_versions(tenant_id,contract_id,version_no,effective_from,effective_to,price,billing_basis,approved_by,approved_at) VALUES ($1,$2,2,'2026-02-15','2026-02-28',100,'monthly',$3,now())",[tenantA,contractA,userA]);
    const ambiguous=await calculate();
    assert.equal(ambiguous.status,422);
    assert.match((await ambiguous.json()).error,/Overlapping contract versions/);
    await admin.query("DELETE FROM contract_versions WHERE id=$1",[overlapping]);
    const validRun=await calculate();
    assert.equal(validRun.status,201);
    const validRunBody=await validRun.json();
    assert.equal(validRunBody.outputs.revenue,100);
    assert.equal(validRunBody.outputs.deliveryCost,50);
    assert.equal(validRunBody.outputs.contribution,50);
    assert.equal(validRunBody.outputs.marginPercent,50);
    const storedRun=await admin.query("SELECT completeness,formula_version,inputs,outputs FROM calculation_runs WHERE id=$1",[validRunBody.id]);
    assert.equal(storedRun.rows[0].completeness,"incomplete","limited contribution must not claim full financial completeness");
    const {snapshotDigest}=await import("../src/financial-calculation.js");
    const stored=storedRun.rows[0];assert.equal(stored.formula_version,"0.2.0");
    assert.deepEqual(stored.outputs.exact,{revenue:"100.00",deliveryCost:"50.00",contribution:"50.00",marginPercent:"50.00"});
    assert.equal(stored.inputs.snapshot.contractVersion.id,versionA);
    assert.equal(stored.inputs.snapshot.invoiceLines[0].match_id,matchA);
    assert.equal(stored.inputs.snapshot.invoiceLines[0].invoice_line_id,lineA);
    assert.equal(stored.inputs.snapshot.allocationLines[0].allocation_line_id,allocationLineA);
    assert.equal(snapshotDigest(stored.inputs.snapshot),stored.outputs.evidenceSha256);
    assert.equal(stored.inputs.evidenceSha256,stored.outputs.evidenceSha256);
    await admin.query("UPDATE match_reviews SET service_period_start='2026-01-31' WHERE id=$1",[matchA]);
    try{const misaligned=await calculate();assert.equal(misaligned.status,422);assert.match((await misaligned.json()).error,/service period/);}
    finally{await admin.query("UPDATE match_reviews SET service_period_start='2026-02-01' WHERE id=$1",[matchA]);}
    assert.equal((await admin.query("SELECT inputs FROM calculation_runs WHERE id=$1",[validRunBody.id])).rows[0].inputs.snapshot.invoiceLines[0].service_period_start,"2026-02-01");


    // Canonical invoice rehearsal remains segregated from the financial ledger.
    const existingCount=(await admin.query("SELECT count(*)::int n FROM invoices WHERE tenant_id=$1",[tenantA])).rows[0].n;
    const claimA=await admin.query("SELECT id FROM invoice_identity_claims WHERE tenant_id=$1 AND raw_row_id=$2",[tenantA,realRaw]);
    const confirmSql="INSERT INTO invoice_confirmation_rehearsals(tenant_id,claim_id,contract_id,site_id,reviewer_id,service_start,service_end,currency,tax_basis,cost_kind,evidence_reference) VALUES($1,$2,$3,$4,private.payroll_reviewer_id(),'2026-02-01','2026-02-28','AUD','gst_exclusive',$5,'CI.fixture') RETURNING id,amount::text";
    const confirm=(claim,kind,site=siteA)=>withTenant(tenantA,"ci-api-analyst",c=>c.query(confirmSql,[tenantA,claim,contractA,site,kind]));
    await admin.query("UPDATE tenant_memberships SET role='reviewer' WHERE tenant_id=$1 AND user_id=$2",[tenantA,userA]);
    try{
     await assert.rejects(()=>confirm(claimA.rows[0].id,"revenue"),e=>e.code==="23514");
     await admin.query("UPDATE tenants SET invoice_rehearsal_enabled=true WHERE id=$1",[tenantA]);
     await assert.rejects(()=>confirm(claimB,"revenue"),e=>e.code==="23514");
     await assert.rejects(()=>confirm(claimA.rows[0].id,"revenue",siteB),e=>e.code==="23514");
     await assert.rejects(()=>confirm(claimA.rows[0].id,"supplier"),e=>e.code==="23514");
     const r=await confirm(claimA.rows[0].id,"revenue");
     assert.equal(r.rowCount,1);
     await assert.rejects(()=>confirm(claimA.rows[0].id,"revenue"),e=>e.code==="23505");
     await assert.rejects(()=>withTenant(tenantA,"ci-api-analyst",c=>c.query("UPDATE invoice_confirmation_rehearsals SET amount=0")),e=>e.code==="42501");
     assert.equal((await admin.query("SELECT count(*)::int n FROM audit_events WHERE tenant_id=$1 AND object_id=$2 AND action='invoice_confirmation_rehearsed'",[tenantA,r.rows[0].id])).rows[0].n,1);
     assert.equal((await admin.query("SELECT count(*)::int n FROM invoices WHERE tenant_id=$1",[tenantA])).rows[0].n,existingCount);
     const bridge=await request(`/v1/tenants/${tenantA}/prototype/invoice-cost-bridge`,{subject:"ci-api-analyst",method:"POST",body:{synthetic:true,contractId:contractA,siteId:siteA,periodStart:"2026-02-01",periodEnd:"2026-02-28"}});
     assert.equal(bridge.status,200);const out=await bridge.json();assert.equal(out.financialInclusionAuthorized,false);assert.equal(out.bridge.revenue,r.rows[0].amount);assert.equal(out.bridge.payrollIncluded,false);
    }finally{await admin.query("UPDATE tenant_memberships SET role='analyst' WHERE tenant_id=$1 AND user_id=$2",[tenantA,userA]);await admin.query("UPDATE tenants SET invoice_rehearsal_enabled=false WHERE id=$1",[tenantA]);}
    const pr1={source_ref:"ci-ledger:pay-001",amount:"40.01",currency:"AUD",period_start:"2026-02-01",period_end:"2026-02-28"};
    const pr2={...pr1,source_ref:"ci-ledger:pay-002",amount:"9.99"};
    const newPayroll=async hash=>{
      const resp=await request(`/v1/tenants/${tenantA}/imports`,{subject:"ci-api-analyst",method:"POST",body:{...importBody,sha256:hash.repeat(64)}});
      assert.equal(resp.status,201);
      const id=(await resp.json()).batch.id;
      const path=`/v1/tenants/${tenantA}/imports/${id}`;
      assert.equal((await request(path+"/rows",{subject:"ci-api-analyst",method:"POST",body:{rows:[pr1,pr2]}})).status,201);
      const validate=await request(path+"/validate",{subject:"ci-api-analyst",method:"POST",body:{}});
      assert.equal(validate.status,200);
      assert.equal((await validate.json()).validCandidateRows,2);
      return {id,path};
    };
    const p1=await newPayroll("2");
    const reviewBody={controlTotal:"50.00",currency:"AUD",controlReference:"CI export total",reason:"CI reviewer verified control",assignments:[{rowNumber:1,bucket:"direct",siteId:siteA,amount:"30.01",reason:"CI verified site code"},{rowNumber:1,bucket:"non_site",amount:"5.00",reason:"CI shared cost"}]};
    const review=(p,body)=>request(p.path+"/reconcile-payroll",{subject:"ci-api-analyst",method:"POST",body});
    assert.equal((await review(p1,reviewBody)).status,403);
    await admin.query("UPDATE tenant_memberships SET role='reviewer' WHERE tenant_id=$1 AND user_id=$2",[tenantA,userA]);
    try{
      assert.equal((await review(p1,{...reviewBody,controlTotal:"49.99"})).status,422);
      assert.equal((await review(p1,{...reviewBody,assignments:[{...reviewBody.assignments[0],siteId:siteB}]})).status,422);
      assert.equal((await admin.query("SELECT count(*)::int AS n FROM payroll_pools WHERE batch_id=$1",[p1.id])).rows[0].n,0);
      const reviewed=await review(p1,reviewBody);
      assert.equal(reviewed.status,201);
      const result=await reviewed.json();
      assert.deepEqual(result.buckets,{direct:"30.01",approved_allocated:"0.00",non_site:"5.00",excluded:"0.00",unallocated:"14.99"});
      const lines=await admin.query("SELECT sum(amount)::text AS total FROM allocation_lines WHERE allocation_run_id=$1",[result.runId]);
      assert.equal(lines.rows[0].total,"50.00");
      assert.equal(result.sourceRows,2);assert.equal(result.allocationLines,4);
      const linked=await admin.query("SELECT count(*)::int AS n FROM allocation_lines WHERE allocation_run_id=$1 AND source_record_id IS NOT NULL",[result.runId]);
      assert.equal(linked.rows[0].n,4);
      // Source-linked payroll attribution and unified contribution rehearsal.
      const directLine=(await admin.query("SELECT id FROM allocation_lines WHERE allocation_run_id=$1 AND bucket_type='direct'",[result.runId])).rows[0].id;
      const attribSql="INSERT INTO payroll_contract_rehearsals(tenant_id,allocation_line_id,contract_id,reviewer_id,evidence_reference) VALUES($1,$2,$3,private.payroll_reviewer_id(),'CI.attribution') RETURNING id,amount::text";
      const attrib=(line,contract=contractA)=>withTenant(tenantA,"ci-api-analyst",c=>c.query(attribSql,[tenantA,line,contract]));
      await assert.rejects(()=>attrib(directLine),e=>e.code==="23514");
      await admin.query("UPDATE tenants SET invoice_rehearsal_enabled=true WHERE id=$1",[tenantA]);
      try{
       await assert.rejects(()=>attrib(rehearsalLineB),e=>e.code==="23514");
       await assert.rejects(()=>attrib(directLine,contractB),e=>e.code==="23514");
       const unifiedRequest=()=>request(`/v1/tenants/${tenantA}/prototype/unified-contribution`,{subject:"ci-api-analyst",method:"POST",body:{synthetic:true,contractId:contractA,siteId:siteA,periodStart:"2026-02-01",periodEnd:"2026-02-28"}});
       const held=await unifiedRequest();assert.equal(held.status,422);assert.match((await held.json()).error,/Unattributed/);
       const attributed=await attrib(directLine);assert.equal(attributed.rows[0].amount,"30.01");
       await assert.rejects(()=>attrib(directLine),e=>e.code==="23505");
       await assert.rejects(()=>withTenant(tenantA,"ci-api-analyst",c=>c.query("UPDATE payroll_contract_rehearsals SET amount=0")),e=>e.code==="42501");
       const unified=await unifiedRequest();assert.equal(unified.status,200);const u=await unified.json();
       assert.equal(u.contribution.revenue,"100.00");assert.equal(u.contribution.labourCost,"30.01");assert.equal(u.contribution.contribution,"69.99");
       assert.equal(u.contribution.completeness,"incomplete");assert.equal(u.persisted,false);assert.equal(u.financialInclusionAuthorized,false);
       assert.equal(u.evidence.excludedLegacyPayroll.length,1);assert.equal(snapshotDigest(u.evidence),u.evidenceSha256);
       assert.equal((await admin.query("SELECT count(*)::int n FROM audit_events WHERE object_id=$1 AND action='payroll_contract_rehearsed'",[attributed.rows[0].id])).rows[0].n,1);
      }finally{await admin.query("UPDATE tenants SET invoice_rehearsal_enabled=false WHERE id=$1",[tenantA]);}
      const sr=await admin.query("SELECT id,source_ref FROM payroll_source_records WHERE payroll_pool_id=$1 ORDER BY source_ref",[result.poolId]);
      await assert.rejects(()=>withTenant(tenantA,"ci-api-analyst",client=>client.query("INSERT INTO allocation_lines(tenant_id,allocation_run_id,site_id,bucket_type,amount,source_ref,source_record_id) VALUES($1,$2,$3,'direct',1,$4,$5)",[tenantA,result.runId,siteA,sr.rows[0].source_ref,sr.rows[0].id])),err=>["42501","23514"].includes(err.code),"confirmed allocation must reject later additions");
      // Admin fixture tests the confirmation invariant independently of HTTP.
      const tempPool=await admin.query("INSERT INTO payroll_pools(tenant_id,batch_id,period_start,period_end,total_amount,currency,source_ref) VALUES($1,$2,'2026-02-01','2026-02-28',50,'AUD','CI invariant fixture') RETURNING id",[tenantA,p1.id]);
      const tempRun=await admin.query("INSERT INTO allocation_runs(tenant_id,payroll_pool_id,method_version,status,residual_amount,reviewer_id) VALUES($1,$2,'payroll-source-row-0.2.0','draft',50,$3) RETURNING id",[tenantA,tempPool.rows[0].id,userA]);
      await assert.rejects(()=>admin.query("UPDATE allocation_runs SET status='confirmed' WHERE id=$1",[tempRun.rows[0].id]),err=>err.code==="23514","database must reject confirmation without source and allocation coverage");
      await admin.query("DELETE FROM allocation_runs WHERE id=$1",[tempRun.rows[0].id]);
      await admin.query("DELETE FROM payroll_pools WHERE id=$1",[tempPool.rows[0].id]);
      assert.equal((await review(p1,reviewBody)).status,409);
    }finally{await admin.query("UPDATE tenant_memberships SET role='analyst' WHERE tenant_id=$1 AND user_id=$2",[tenantA,userA]);}
    const p2=await newPayroll("3");
    await admin.query("UPDATE tenant_memberships SET role='reviewer' WHERE tenant_id=$1 AND user_id=$2",[tenantA,userA]);
    try{
      assert.equal((await review(p2,reviewBody)).status,409);
      assert.equal((await admin.query("SELECT count(*)::int AS n FROM payroll_pools WHERE batch_id=$1",[p2.id])).rows[0].n,0);
      assert.equal((await admin.query("SELECT status FROM import_batches WHERE id=$1",[p2.id])).rows[0].status,"review");
    }finally{await admin.query("UPDATE tenant_memberships SET role='analyst' WHERE tenant_id=$1 AND user_id=$2",[tenantA,userA]);}


    const sourceBytes=Buffer.from("invoice_id,site,date,amount\r\nCI-verified,CI site,2026-02-01,12.34\r\n");
    const sourceHash=createHash("sha256").update(sourceBytes).digest("hex");
    const sourceBatch=await request(`/v1/tenants/${tenantA}/imports`,{subject:"ci-api-analyst",method:"POST",body:{...importBody,sourceType:"customer_invoice",fileName:"verified.csv",sha256:sourceHash}});
    assert.equal(sourceBatch.status,201);
    const sourceBatchId=(await sourceBatch.json()).batch.id;
    const sourcePath=`/v1/tenants/${tenantA}/imports/${sourceBatchId}`;
    async function upload(path,bytes,subject="ci-api-analyst",type="text/csv",extra={}){
      return fetch(base+path+"/file",{method:"POST",headers:{authorization:"Bearer "+await token(subject),"content-type":type,...extra},body:bytes});
    }
    assert.equal((await upload(sourcePath,sourceBytes,"ci-api-reader")).status,403);
    assert.equal((await upload(sourcePath,sourceBytes,"ci-api-analyst","application/zip")).status,415);
    assert.equal((await upload(sourcePath,sourceBytes,"ci-api-analyst","text/csv",{"content-encoding":"gzip"})).status,415);
    assert.equal((await upload(sourcePath,Buffer.alloc(524289,65))).status,413);
    assert.equal((await upload(sourcePath,Buffer.from("invoice_id,site,date,amount\nCI-other,CI site,2026-02-01,12.34\n"))).status,422);
    assert.equal((await admin.query("SELECT count(*)::int AS n FROM raw_import_rows WHERE batch_id=$1",[sourceBatchId])).rows[0].n,0);
    const beforeSource=await request(sourcePath+"/source",{subject:"ci-api-analyst"});
    assert.equal((await beforeSource.json()).sourceIntegrity,"client_declared");
    const sourceConcurrent=await Promise.all([upload(sourcePath,sourceBytes),upload(sourcePath,sourceBytes)]);
    assert.deepEqual(sourceConcurrent.map(x=>x.status).sort(),[200,201]);
    const storedSource=await admin.query("SELECT sha256,original_bytes,row_count FROM import_source_receipts WHERE batch_id=$1",[sourceBatchId]);
    assert.equal(storedSource.rows[0].sha256,sourceHash);
    assert.deepEqual(storedSource.rows[0].original_bytes,sourceBytes);
    const sourceInfo=await request(sourcePath+"/source",{subject:"ci-api-reader"});
    const sourceInfoBody=await sourceInfo.json();
    assert.equal(sourceInfoBody.sourceIntegrity,"byte_verified");
    assert.equal(sourceInfoBody.receipt.scan_status,"not_configured");
    assert.equal(sourceInfoBody.issuerAuthenticated,false);
    assert.ok(!JSON.stringify(sourceInfoBody).includes("original_bytes"));
    assert.equal((await request(`/v1/tenants/${tenantA}/imports/${verifiedB}/source`,{subject:"ci-api-analyst"})).status,404);
    assert.equal((await upload(`/v1/tenants/${tenantA}/imports/${verifiedB}`,fixtureBytes)).status,404);
    assert.equal((await request(sourcePath+"/rows",{subject:"ci-api-analyst",method:"POST",body:{startRow:2,rows:[row1]}})).status,409);
    await assert.rejects(()=>withTenant(tenantA,"ci-api-analyst",c=>c.query("INSERT INTO raw_import_rows(tenant_id,batch_id,row_number,payload) VALUES($1,$2,2,'{}')",[tenantA,sourceBatchId])),e=>e.code==="23514");
    const validateSource=await request(sourcePath+"/validate",{subject:"ci-api-analyst",method:"POST",body:{}});
    assert.equal(validateSource.status,200);
    assert.equal((await validateSource.json()).sourceIntegrity,"byte_verified");
    const wrongReceipt=await admin.query("INSERT INTO import_batches(tenant_id,source_type,permission_ref,status,file_sha256,file_name,created_by) VALUES($1,'customer_invoice','CI','uploaded',$2,'wrong.csv',$3) RETURNING id",[tenantA,"9".repeat(64),userA]);
    const wrongId=wrongReceipt.rows[0].id;
    await admin.query("INSERT INTO raw_import_rows(tenant_id,batch_id,row_number,payload) VALUES($1,$2,1,'{}')",[tenantA,wrongId]);
    await assert.rejects(()=>admin.query("INSERT INTO import_source_receipts(tenant_id,batch_id,sha256,byte_count,row_count,parser_version,original_bytes,received_by) VALUES($1,$2,$3,$4,1,'strict-csv-0.1.0',$5,$6)",[tenantA,wrongId,"9".repeat(64),sourceBytes.length,sourceBytes,userA]),e=>e.code==="23514");

    // Reset only the isolated integration process's limiter between test phases.
    await requestLimiter.resetKey("127.0.0.1");
    const privacyPath=`/v1/tenants/${tenantA}/privacy-requests`;
    const privacyBody={clientRequestId:"99999999-9999-4999-8999-999999999999",requestType:"erasure"};
    const createPrivacy=()=>request(privacyPath,{subject:"ci-api-reader",method:"POST",body:privacyBody});
    const privacyCreated=await createPrivacy();assert.equal(privacyCreated.status,201);
    const privacyItem=await privacyCreated.json();assert.equal(privacyItem.automatedErasure,false);
    assert.equal((await createPrivacy()).status,200);
    assert.equal((await request(privacyPath,{subject:"ci-api-reader",method:"POST",body:{...privacyBody,requestType:"access"}})).status,409);
    assert.equal((await request(privacyPath,{subject:"ci-api-reader",method:"POST",body:{...privacyBody,details:"unnecessary"}})).status,400);
    assert.equal((await (await request(privacyPath,{subject:"ci-api-analyst"})).json()).items.length,0);
    assert.equal((await (await request(privacyPath,{subject:"ci-api-reader"})).json()).items[0].id,privacyItem.item.id);
    const reviewPath=privacyPath+"/"+privacyItem.item.id+"/review";
    const privacyReview=(status,reviewReference="CI.case.1")=>request(reviewPath,{subject:"ci-api-analyst",method:"POST",body:{status,reviewReference}});
    assert.equal((await privacyReview("reviewing")).status,403);
    const independentReviewer="cccccccc-cccc-4ccc-8ccc-cccccccccccc";
    await admin.query("INSERT INTO users(id,auth_subject,email,status) VALUES ($1,'ci-api-privacy-closer','privacy-closer@example.invalid','active') ON CONFLICT(id) DO UPDATE SET status='active'",[independentReviewer]);
    await admin.query("INSERT INTO tenant_memberships(tenant_id,user_id,role,status) VALUES($1,$2,'admin','active') ON CONFLICT(tenant_id,user_id) DO UPDATE SET role='admin',status='active'",[tenantA,independentReviewer]);
    await admin.query("UPDATE tenant_memberships SET role='admin' WHERE tenant_id=$1 AND user_id=$2",[tenantA,userA]);
    try{
      assert.equal((await privacyReview("closed_attested")).status,409);
      assert.equal((await privacyReview("reviewing")).status,200);
      const premature=await privacyReview("closed_attested");assert.equal(premature.status,409,"initiating reviewer cannot close own case");
      await assert.rejects(()=>withTenant(tenantA,"ci-api-analyst",c=>c.query("UPDATE privacy_requests SET review_started_by=$1 WHERE tenant_id=$2 AND id=$3",[independentReviewer,tenantA,privacyItem.item.id])),e=>e.code==="42501","review initiator is immutable to the runtime role");
      const evidencePath=privacyPath+"/"+privacyItem.item.id+"/evidence";
      const withoutProof=await request(reviewPath,{subject:"ci-api-privacy-closer",method:"POST",body:{status:"closed_attested",reviewReference:"CI.closure.2"}});
      assert.equal(withoutProof.status,409,"closure must fail without five scoped operator attestations");
      for(const scope of ["identity","primary","backups","processors","logs"]){
       await admin.query("INSERT INTO private.privacy_case_evidence(tenant_id,case_id,scope,outcome,evidence_reference,recorded_by) VALUES($1,$2,$3,'fulfilled',$4,$5)",[tenantA,privacyItem.item.id,scope,"CI."+scope,independentReviewer]);
      }
      await assert.rejects(()=>withTenant(tenantA,"ci-api-analyst",c=>c.query("INSERT INTO private.privacy_case_evidence(tenant_id,case_id,scope,outcome,evidence_reference,recorded_by) VALUES($1,$2,'decision','lawful_exception','CI.unauthorised',$3)",[tenantA,privacyItem.item.id,userA])),e=>e.code==="42501","runtime role may not declare external fulfilment");
      const evidence=await request(evidencePath,{subject:"ci-api-reader"});assert.equal(evidence.status,200);
      const evidenceData=await evidence.json();assert.equal(evidenceData.items.length,5);assert.equal(evidenceData.externalFulfilmentVerified,false);
      assert.equal((await request(evidencePath,{subject:"ci-api-tenant-b-only"})).status,403);
      const closed=await request(reviewPath,{subject:"ci-api-privacy-closer",method:"POST",body:{status:"closed_attested",reviewReference:"CI.closure.2"}});assert.equal(closed.status,200);
      assert.equal((await closed.json()).externalFulfilmentVerified,false);
      assert.equal((await privacyReview("reviewing")).status,409);
      assert.equal((await admin.query("SELECT count(*)::int AS n FROM audit_events WHERE tenant_id=$1 AND object_id=$2 AND action='privacy_request_review'",[tenantA,privacyItem.item.id])).rows[0].n,2);
      const foreign=await request(privacyPath+"/"+fixturePrivacy+"/review",{subject:"ci-api-analyst",method:"POST",body:{status:"reviewing",reviewReference:"CI.case.2"}});assert.equal(foreign.status,409);
    }finally{await admin.query("UPDATE tenant_memberships SET role='analyst' WHERE tenant_id=$1 AND user_id=$2",[tenantA,userA]);}
    await assert.rejects(()=>withTenant(tenantA,"ci-api-reader",c=>c.query("DELETE FROM privacy_requests")),e=>e.code==="42501");
    const analystEvidence=await withTenant(tenantA,"ci-api-analyst",c=>c.query("SELECT id FROM private.privacy_case_evidence WHERE case_id=$1",[privacyItem.item.id]));
    assert.equal(analystEvidence.rowCount,0);
    const ownEvidence=await withTenant(tenantA,"ci-api-reader",c=>c.query("SELECT id FROM private.privacy_case_evidence WHERE case_id=$1",[privacyItem.item.id]));
    assert.equal(ownEvidence.rowCount,5);
    const accessPath=`/v1/tenants/${tenantA}/privacy/self-access`;
    const selfAccess=await request(accessPath,{subject:"ci-api-reader"});
    assert.equal(selfAccess.status,200);assert.equal(selfAccess.headers.get("cache-control"),"no-store");
    const ownExport=await selfAccess.json();
    assert.equal(ownExport.identity.id,userB);assert.equal(ownExport.identity.email,"reader@example.invalid");
    assert.equal(ownExport.completeDataSubjectExport,false);
    assert.equal(ownExport.privacyRequests[0].id,privacyItem.item.id);
    assert.equal((await request(accessPath,{subject:"ci-api-tenant-b-only"})).status,403);
    assert.equal((await (await request(accessPath,{subject:"ci-api-analyst"})).json()).privacyRequests.length,0);
    // Metadata-rich operational audit events are not a tenant-wide read-only feed.
    const readerAudit=await withTenant(tenantA,"ci-api-reader",c=>c.query("SELECT id FROM audit_events WHERE action='source_file_verified' AND object_id=$1",[sourceBatchId]));
    assert.equal(readerAudit.rowCount,0,"read_only must not see others' ingestion metadata");
    const actorAudit=await withTenant(tenantA,"ci-api-analyst",c=>c.query("SELECT id FROM audit_events WHERE action='source_file_verified' AND object_id=$1",[sourceBatchId]));
    assert.equal(actorAudit.rowCount,1,"analyst may see their own upload audit event");
    const privateAudit=await withTenant(tenantA,"ci-api-analyst",c=>c.query("SELECT id FROM audit_events WHERE object_type='privacy_request' AND object_id=$1",[privacyItem.item.id]));
    assert.equal(privateAudit.rowCount,0);
    const ownAudit=await withTenant(tenantA,"ci-api-reader",c=>c.query("SELECT id FROM audit_events WHERE object_type='privacy_request' AND object_id=$1",[privacyItem.item.id]));
    assert.equal(ownAudit.rowCount,7,"two privacy decisions plus five operator evidence records");
    await admin.query("INSERT INTO privacy_requests(tenant_id,requester_id,client_request_id,request_type) SELECT $1,$2,gen_random_uuid(),'access' FROM generate_series(1,201)",[tenantA,userB]);
    const page1=await (await request(accessPath,{subject:"ci-api-reader"})).json();
    assert.equal(page1.privacyRequests.length,200);assert.equal(page1.additionalRequests,true);
    const page2=await (await request(accessPath+"?cursor="+page1.nextCursor,{subject:"ci-api-reader"})).json();
    assert.equal(page2.privacyRequests.length,2);assert.equal(page2.nextCursor,null);
    assert.equal(new Set([...page1.privacyRequests,...page2.privacyRequests].map(r=>r.id)).size,202);
    const queue1=await (await request(privacyPath,{subject:"ci-api-reader"})).json();
    assert.equal(queue1.items.length,200);assert.equal(queue1.additionalRequests,true);
    const queue2=await (await request(privacyPath+"?cursor="+queue1.nextCursor,{subject:"ci-api-reader"})).json();
    assert.equal(queue2.items.length,2);assert.equal(queue2.nextCursor,null);
    assert.equal(new Set([...queue1.items,...queue2.items].map(r=>r.id)).size,202);
    assert.ok(queue1.items.every(r=>r.requester_id===userB));
    assert.equal((await request(privacyPath+"?cursor="+fixturePrivacy,{subject:"ci-api-reader"})).status,404);
    assert.equal((await request(privacyPath+"?cursor=invalid",{subject:"ci-api-reader"})).status,400);
    const adminQueue1=await (await request(privacyPath,{subject:"ci-api-privacy-closer"})).json();
    assert.equal(adminQueue1.items.length,200);assert.equal(adminQueue1.additionalRequests,true);
    const adminQueue2=await (await request(privacyPath+"?cursor="+adminQueue1.nextCursor,{subject:"ci-api-privacy-closer"})).json();
    assert.equal(adminQueue2.items.length,2);assert.equal(adminQueue2.nextCursor,null);
    assert.equal((await request(accessPath+"?cursor="+page1.nextCursor,{subject:"ci-api-analyst"})).status,404);
    assert.equal((await request(accessPath+"?cursor=bad",{subject:"ci-api-reader"})).status,400);
    // Scoped, independently reviewed erasure of an unused client-declared import; synthetic database only.
    const disposalCase=(await admin.query("INSERT INTO privacy_requests(tenant_id,requester_id,client_request_id,request_type) VALUES($1,$2,gen_random_uuid(),'erasure') RETURNING id",[tenantA,userA])).rows[0].id;
    const disposable=(await admin.query("INSERT INTO import_batches(tenant_id,source_type,permission_ref,status,file_sha256,file_name,created_by) VALUES($1,'customer_invoice','CI','uploaded',$2,'unused-privacy.csv',$3) RETURNING id",[tenantA,"7".repeat(64),userA])).rows[0].id;
    await admin.query("INSERT INTO raw_import_rows(tenant_id,batch_id,row_number,payload) VALUES($1,$2,1,$3)",[tenantA,disposable,JSON.stringify({invoice_id:"CI-privacy-marker"})]);
    const dispose=(batch=disposable,policy="CI.policy")=>admin.query("SELECT private.dispose_unused_import($1,$2,$3,$4) AS removed",[tenantA,batch,disposalCase,policy]);
    await assert.rejects(()=>dispose(),e=>e.code==="23514");
    await admin.query("UPDATE tenant_memberships SET role='admin' WHERE tenant_id=$1 AND user_id=$2",[tenantA,userB]);
    try{
     await admin.query("UPDATE privacy_requests SET status='reviewing',reviewed_by=$1,reviewed_at=now(),review_reference='CI.policy' WHERE id=$2",[userB,disposalCase]);
     await assert.rejects(()=>dispose(),e=>e.code==="23514");
     await admin.query("UPDATE import_batches SET retention_hold=false,retention_release_reference='CI.policy' WHERE id=$1",[disposable]);
     await assert.rejects(()=>dispose(disposable,"CI.wrong"),e=>e.code==="23514");
     await assert.rejects(()=>dispose(verifiedB),e=>e.code==="23514");
     await assert.rejects(()=>dispose(sourceBatchId),e=>e.code==="23514");
     await assert.rejects(()=>withTenant(tenantA,"ci-api-reader",c=>c.query("SELECT private.dispose_unused_import($1,$2,$3,$4)",[tenantA,disposable,disposalCase,"CI.policy"])),e=>e.code==="42501");
     await assert.rejects(()=>withTenant(tenantA,"ci-api-reader",c=>c.query("UPDATE import_batches SET retention_hold=false WHERE id=$1",[disposable])),e=>e.code==="42501");
     assert.equal((await dispose()).rows[0].removed,1);
     assert.equal((await admin.query("SELECT count(*)::int AS n FROM import_batches WHERE id=$1",[disposable])).rows[0].n,0);
     assert.equal((await admin.query("SELECT count(*)::int AS n FROM raw_import_rows WHERE batch_id=$1",[disposable])).rows[0].n,0);
     assert.equal((await admin.query("SELECT count(*)::int AS n FROM audit_events WHERE tenant_id=$1 AND object_id=$2 AND action='unused_import_disposed'",[tenantA,disposalCase])).rows[0].n,1);
     await assert.rejects(()=>dispose(),e=>e.code==="23514");
    }finally{await admin.query("UPDATE tenant_memberships SET role='read_only' WHERE tenant_id=$1 AND user_id=$2",[tenantA,userB]);}
    const readerWrite=await request(`/v1/tenants/${tenantA}/imports`,{
      subject:"ci-api-reader",method:"POST",
      body:{...importBody,sha256:"c".repeat(64)}
    });
    assert.equal(readerWrite.status,403,"read_only members must not create imports");

    await admin.query("UPDATE tenant_memberships SET status='revoked' WHERE tenant_id=$1 AND user_id=$2",[tenantA,userA]);
    const revoked=await request(`/v1/tenants/${tenantA}/contracts`,{subject:"ci-api-analyst"});
    assert.equal(revoked.status,403,"revoked memberships must lose access immediately");
    // Exercise the real production-configured throttle with unauthenticated requests:
    // no database or JWT work is necessary, and malformed JSON must not reach parsing.
    await requestLimiter.resetKey("127.0.0.1");
    const malformed=()=>fetch(base+"/v1/me",{method:"POST",headers:{"content-type":"application/json"},body:"{"});
    for(let n=0;n<100;n++){const response=await malformed();assert.equal(response.status,401);await response.arrayBuffer();}
    const throttled=await malformed();assert.equal(throttled.status,429);await throttled.arrayBuffer();
    await requestLimiter.resetKey("127.0.0.1");
  }finally{
    await new Promise(resolve=>api.close(resolve));
    await admin.end();
    await appPool.end();
    await new Promise(resolve=>jwksServer.close(resolve));
  }
});

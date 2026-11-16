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
    const importB="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    await admin.query("INSERT INTO import_batches(id,tenant_id,source_type,permission_ref,status,file_sha256,file_name,created_by) VALUES ($1,$2,'payroll','CI tenant B permission','registered',$3,'tenant-b.csv',$4) ON CONFLICT(id) DO NOTHING",[importB,tenantB,"e".repeat(64),userC]);
    await admin.query("INSERT INTO businesses(id,tenant_id,name) VALUES ($1,$2,'CI Business A') ON CONFLICT(id) DO NOTHING",[businessA,tenantA]);
    await admin.query("INSERT INTO contracts(id,tenant_id,business_id,customer_name,status) VALUES ($1,$2,$3,'CI Customer A','active') ON CONFLICT(id) DO NOTHING",[contractA,tenantA,businessA]);
    await admin.query("INSERT INTO businesses(id,tenant_id,name) VALUES ($1,$2,'CI Business B') ON CONFLICT(id) DO NOTHING",[businessB,tenantB]);
    await admin.query("INSERT INTO contracts(id,tenant_id,business_id,customer_name,status) VALUES ($1,$2,$3,'CI Customer B','active') ON CONFLICT(id) DO NOTHING",[contractB,tenantB,businessB]);
    const partialSite="abababab-abab-4bab-8bab-abababababab";
    await admin.query("INSERT INTO sites(id,tenant_id,business_id,name) VALUES ($1,$2,$3,'CI partial-period site') ON CONFLICT(id) DO NOTHING",[partialSite,tenantA,businessA]);
    await admin.query("INSERT INTO contract_versions(id,tenant_id,contract_id,version_no,effective_from,price,currency,billing_basis,approved_by,approved_at) VALUES ('acacacac-acac-4cac-8cac-acacacacacac',$1,$2,1,'2026-02-15',100,'AUD','monthly',$3,now()) ON CONFLICT(id) DO NOTHING",[tenantA,contractA,userA]);
    await assert.rejects(()=>admin.query("INSERT INTO import_batches(id,tenant_id,source_type,permission_ref,status,file_sha256,file_name,created_by) VALUES ($1,$2,'payroll','CI permission','registered',$3,'cross-tenant.csv',$4)",["cccccccc-cccc-4ccc-8ccc-cccccccccccc",tenantA,"d".repeat(64),userC]),/foreign key constraint/i,"a user who belongs only to tenant B must not be recorded as the creator of a tenant A import");

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
    const protectedTables=await admin.query(`
      SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='public' AND c.relkind IN ('r','p')
        AND (c.relname IN ('tenants','users') OR EXISTS (
          SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attname='tenant_id' AND a.attnum>0 AND NOT a.attisdropped
        ))
      ORDER BY c.relname
    `);
    assert.equal(protectedTables.rowCount,20,"the exhaustive fixture must cover every tenant-owned/root identity and payroll evidence table");
    for(const {relname} of protectedTables.rows){
      const tableQuery=`SELECT count(*)::int AS count FROM public."${relname.replaceAll('"','""')}"`;
      const tenantCCount=await withTenant("33333333-3333-4333-8333-333333333333","isolation-tenant-c",client=>client.query(tableQuery));
      const tenantDCount=await withTenant("44444444-4444-4444-8444-444444444444","isolation-tenant-d",client=>client.query(tableQuery));
      assert.equal(tenantCCount.rows[0].count,["tenant_memberships","import_batches","raw_import_rows"].includes(relname)?2:1,`tenant C must see only its own fixture rows in ${relname}`);
      assert.equal(tenantDCount.rows[0].count,["import_batches","raw_import_rows"].includes(relname)?2:1,`tenant D must see only its own fixture row in ${relname}`);
    }
    const sourceLedger=await withTenant("33333333-3333-4333-8333-333333333333","isolation-tenant-c",client=>client.query("SELECT amount,currency FROM payroll_source_rows"));
    assert.equal(sourceLedger.rowCount,1,"tenant-scoped payroll source-row ledger must be visible to its own tenant");
    assert.equal(sourceLedger.rows[0].amount,"100.00");
    assert.equal(sourceLedger.rows[0].currency,"AUD");
    await assert.rejects(()=>withTenant("33333333-3333-4333-8333-333333333333","isolation-tenant-c",client=>client.query("INSERT INTO payroll_source_rows(tenant_id,payroll_pool_id,raw_import_row_id,source_row_key,row_sha256,amount,currency) VALUES ($1,$2,$3,'runtime-attempt',$4,1,'AUD')",["33333333-3333-4333-8333-333333333333","16161616-1616-4616-8616-161616161616","18181818-1818-4818-8818-181818181818","a".repeat(64)])),/permission denied/i,"runtime role must not write payroll source evidence");
    await assert.rejects(()=>admin.query("UPDATE payroll_source_rows SET amount=99 WHERE id='30303030-3030-4030-8030-303030303030'"),/immutable/i,"payroll source rows must be immutable");
    await assert.rejects(()=>admin.query("INSERT INTO payroll_source_rows(tenant_id,payroll_pool_id,raw_import_row_id,source_row_key,row_sha256,amount,currency) VALUES ('33333333-3333-4333-8333-333333333333','16161616-1616-4616-8616-161616161616','14141414-1414-4414-8414-141414141414','invoice-row-link',repeat('6',64),0,'AUD')"),/same payroll pool import batch/i,"payroll source evidence must not reference a customer-invoice import row");
    await assert.rejects(()=>admin.query("INSERT INTO payroll_source_rows(tenant_id,payroll_pool_id,raw_import_row_id,source_row_key,row_sha256,amount,currency) VALUES ('33333333-3333-4333-8333-333333333333','16161616-1616-4616-8616-161616161616','18181818-1818-4818-8818-181818181818','bad key',repeat('6',64),0,'AUD')"),/check constraint/i,"payroll source-row keys must be opaque, bounded and safe");
    await assert.rejects(()=>admin.query("INSERT INTO allocation_lines(tenant_id,allocation_run_id,site_id,bucket_type,amount,source_ref,payroll_source_row_id) VALUES ('33333333-3333-4333-8333-333333333333','18181818-1818-4818-8818-181818181818','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','direct',0.01,'over-allocation-test','30303030-3030-4030-8030-303030303030')"),/exceeds source payroll row amount/i,"source-row allocations must never exceed the original row amount");

    const invalidRunBefore=await admin.query("SELECT id,status,direct_amount,allocated_amount,non_site_amount,excluded_amount,residual_amount FROM allocation_runs WHERE id='18181818-1818-4818-8818-181818181818'");
    assert.equal(invalidRunBefore.rowCount,1,"the invalid payroll confirmation fixture must exist");
    assert.equal(invalidRunBefore.rows[0].status,"draft","the invalid payroll confirmation fixture must begin as draft");
    const confirmationTrigger=await admin.query("SELECT t.tgenabled,pg_get_triggerdef(t.oid) AS definition FROM pg_trigger t WHERE t.tgrelid='public.allocation_runs'::regclass AND t.tgname='allocation_runs_validate_confirmation' AND NOT t.tgisinternal");
    assert.equal(confirmationTrigger.rowCount,1,"payroll confirmation integrity trigger must be installed");
    assert.equal(confirmationTrigger.rows[0].tgenabled,"O","payroll confirmation integrity trigger must be enabled");
    assert.match(confirmationTrigger.rows[0].definition,/BEFORE INSERT OR UPDATE/i,"payroll confirmation integrity trigger must cover inserts and all updates");
    await assert.rejects(()=>admin.query("UPDATE allocation_runs SET status='confirmed' WHERE id='18181818-1818-4818-8818-181818181818'"),/Allocation line totals do not reconcile|residual is non-zero/i,"a payroll run with non-zero residual or mismatched summary must not be confirmed");
    await admin.query("INSERT INTO payroll_source_rows(tenant_id,payroll_pool_id,raw_import_row_id,source_row_key,row_sha256,amount,currency) VALUES ('44444444-4444-4444-8444-444444444444','17171717-1717-4717-8717-171717171717','19191919-1919-4919-8919-191919191919','fixture-D-wrong-currency',repeat('5',64),0,'USD')");
    await assert.rejects(()=>admin.query("UPDATE allocation_runs SET direct_amount=100,residual_amount=0,reviewer_id='66666666-6666-4666-8666-666666666666',status='confirmed' WHERE id='19191919-1919-4919-8919-191919191919'"),/currency does not match/i,"source rows with a currency different from the payroll pool must block confirmation");
    await assert.rejects(()=>admin.query("UPDATE allocation_runs SET direct_amount=100,residual_amount=0,status='confirmed' WHERE id='18181818-1818-4818-8818-181818181818'"),/reviewer, admin or owner/i,"payroll confirmation must require an authorised reviewer");
    await admin.query("UPDATE allocation_runs SET direct_amount=100,residual_amount=0,reviewer_id='77777777-7777-4777-8777-777777777777' WHERE id='18181818-1818-4818-8818-181818181818'");
    await admin.query("UPDATE allocation_runs SET status='confirmed' WHERE id='18181818-1818-4818-8818-181818181818'");
    const confirmedRun=await admin.query("SELECT status,direct_amount,residual_amount FROM allocation_runs WHERE id='18181818-1818-4818-8818-181818181818'");
    assert.deepEqual(confirmedRun.rows[0],{status:"confirmed",direct_amount:"100.00",residual_amount:"0.00"},"valid reviewer-authorised confirmation must persist the updated run");
    await assert.rejects(()=>admin.query("UPDATE allocation_runs SET direct_amount=99 WHERE id='18181818-1818-4818-8818-181818181818'"),/Confirmed payroll allocation runs are immutable/i,"confirmed payroll run summaries must be immutable");
    await assert.rejects(()=>admin.query("DELETE FROM allocation_runs WHERE id='18181818-1818-4818-8818-181818181818'"),/Confirmed payroll allocation runs are immutable/i,"confirmed payroll runs must not be deleted");
    await admin.query("INSERT INTO allocation_runs(id,tenant_id,payroll_pool_id,method_version,status,direct_amount,residual_amount,reviewer_id) VALUES ('31313131-3131-4131-8131-313131313131','33333333-3333-4333-8333-333333333333','16161616-1616-4616-8616-161616161616','fixture-legacy-unlinked','draft',100,0,'77777777-7777-4777-8777-777777777777')");
    await admin.query("ALTER TABLE allocation_lines DISABLE TRIGGER allocation_lines_validate_source");
    await admin.query("INSERT INTO allocation_lines(tenant_id,allocation_run_id,site_id,bucket_type,amount,source_ref) VALUES ('33333333-3333-4333-8333-333333333333','31313131-3131-4131-8131-313131313131','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','direct',100,'legacy-unlinked-fixture')");
    await admin.query("ALTER TABLE allocation_lines ENABLE TRIGGER allocation_lines_validate_source");
    await admin.query("INSERT INTO allocation_lines(tenant_id,allocation_run_id,site_id,bucket_type,amount,source_ref,payroll_source_row_id) VALUES ('33333333-3333-4333-8333-333333333333','31313131-3131-4131-8131-313131313131','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','direct',100,'fixture-source-linked-companion','30303030-3030-4030-8030-303030303030')");
    await assert.rejects(()=>admin.query("UPDATE allocation_runs SET status='confirmed' WHERE id='31313131-3131-4131-8131-313131313131'"),/source-linked and total exactly/i,"legacy allocation lines without immutable source-row provenance must not be confirmed");
    await admin.query("INSERT INTO allocation_runs(id,tenant_id,payroll_pool_id,method_version,status,direct_amount,residual_amount,reviewer_id) VALUES ('32323232-3232-4232-8232-323232323232','33333333-3333-4333-8333-333333333333','16161616-1616-4616-8616-161616161616','fixture-duplicate','draft',100,0,'77777777-7777-4777-8777-777777777777')");
    await admin.query("INSERT INTO allocation_lines(tenant_id,allocation_run_id,site_id,bucket_type,amount,source_ref,payroll_source_row_id) VALUES ('33333333-3333-4333-8333-333333333333','32323232-3232-4232-8232-323232323232','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','direct',100,'fixture-duplicate-line','30303030-3030-4030-8030-303030303030')");
    await assert.rejects(()=>admin.query("UPDATE allocation_runs SET status='confirmed' WHERE id='32323232-3232-4232-8232-323232323232'"),/duplicate key|one_confirmed_allocation_run_per_payroll_pool/i,"a payroll pool must not have two confirmed allocation runs");
    await assert.rejects(()=>admin.query("INSERT INTO allocation_runs(id,tenant_id,payroll_pool_id,method_version,status,direct_amount,residual_amount,reviewer_id) VALUES ('34343434-3434-4434-8434-343434343434','33333333-3333-4333-8333-333333333333','16161616-1616-4616-8616-161616161616','fixture-insert-confirmed','confirmed',0,0,'77777777-7777-4777-8777-777777777777')"),/Every payroll source row must be fully represented|line totals do not reconcile/i,"a run inserted directly as confirmed must still pass the confirmation gate");

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
    await assert.rejects(()=>withTenant(tenantA,"ci-api-analyst",client=>client.query("UPDATE tenant_memberships SET role='owner' WHERE tenant_id=$1 AND user_id=$2",[tenantA,userA])),/permission denied/i,"ordinary API runtime sessions must not be able to self-promote or alter tenant memberships");
    await assert.rejects(()=>withTenant(tenantA,"ci-api-analyst",client=>client.query("UPDATE tenants SET legal_name='tampered' WHERE id=$1",[tenantA])),/permission denied/i,"ordinary API runtime sessions must not alter tenant ownership records");
    await assert.rejects(()=>withTenant(tenantA,"ci-api-analyst",client=>client.query("DELETE FROM import_batches WHERE tenant_id=$1",[tenantA])),/permission denied/i,"the runtime role must not delete source import records");
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
    await assert.rejects(()=>withTenant(tenantA,"ci-api-analyst",client=>client.query("INSERT INTO contracts(id,tenant_id,business_id,customer_name,status) VALUES ($1,$2,$3,'unauthorised write','active')",["99999999-9999-4999-8999-999999999999",tenantB,businessB])),/permission denied/i,"the runtime role must not write to unimplemented contract administration tables");
    await assert.rejects(()=>withTenant(tenantA,"ci-api-analyst",client=>client.query("INSERT INTO raw_import_rows(tenant_id,batch_id,row_number,payload) VALUES ($1,$2,1,'{}'::jsonb)",[tenantB,importB])),/row-level security/i,"RLS WITH CHECK must reject cross-tenant writes on an API-writable table");

    const otherTenant=await request(`/v1/tenants/${tenantB}/contracts`,{subject:"ci-api-analyst"});
    assert.equal(otherTenant.status,403,"a tenant A member must not access tenant B");
    const crossTenantCalculation=await request("/v1/tenants/33333333-3333-4333-8333-333333333333/calculations/29292929-2929-4929-8929-292929292929",{subject:"isolation-tenant-c"});
    assert.equal(crossTenantCalculation.status,404,"a tenant member must not retrieve another tenant's calculation object by ID");
    const crossTenantBatch=await request("/v1/tenants/33333333-3333-4333-8333-333333333333/imports/13131313-1313-4313-8313-131313131313/rows",{subject:"isolation-tenant-c",method:"POST",body:{rows:[{invoice_id:"D-1"}]}});
    assert.equal(crossTenantBatch.status,404,"a tenant member must not append rows to another tenant's import batch");
    const crossTenantValidate=await request("/v1/tenants/33333333-3333-4333-8333-333333333333/imports/13131313-1313-4313-8313-131313131313/validate",{subject:"isolation-tenant-c",method:"POST"});
    assert.equal(crossTenantValidate.status,404,"a tenant member must not validate another tenant's import batch");
    const crossTenantCalculationCreate=await request("/v1/tenants/33333333-3333-4333-8333-333333333333/calculations",{subject:"isolation-tenant-c",method:"POST",body:{contractId:"dddddddd-dddd-4ddd-8ddd-dddddddddddd",siteId:"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",periodStart:"2026-01-01",periodEnd:"2026-01-31"}});
    assert.equal(crossTenantCalculationCreate.status,422,"a tenant member must not create a calculation using another tenant's contract/site IDs");
    const crossTenantMatch=await request("/v1/tenants/33333333-3333-4333-8333-333333333333/matches/25252525-2525-4525-8525-252525252525/decision",{subject:"isolation-reviewer-c",method:"POST",body:{decision:"confirmed",reason:"cross-tenant object test"}});
    assert.equal(crossTenantMatch.status,404,"a reviewer must not decide another tenant's match object by ID");
    const analystDecision=await request("/v1/tenants/33333333-3333-4333-8333-333333333333/matches/24242424-2424-4424-8424-242424242424/decision",{subject:"isolation-tenant-c",method:"POST",body:{decision:"confirmed",reason:"analyst role escalation test"}});
    assert.equal(analystDecision.status,403,"an analyst must not exercise reviewer-only invoice decision authority");
    const analystDirectDecision=await withTenant("33333333-3333-4333-8333-333333333333","isolation-tenant-c",client=>client.query("UPDATE match_reviews SET decision='confirmed',reviewer_id='55555555-5555-4555-8555-555555555555' WHERE id='24242424-2424-4424-8424-242424242424' RETURNING id"));
    assert.equal(analystDirectDecision.rowCount,0,"database RLS must block analyst direct-SQL invoice decision even if the application route is bypassed");
    const reviewerDirectDecision=await withTenant("33333333-3333-4333-8333-333333333333","isolation-reviewer-c",async client=>{
      await client.query("SELECT set_config('app.audit_reason',$1,true)",["Synthetic direct SQL reviewer acceptance test"]);
      return client.query("UPDATE match_reviews SET decision='confirmed',reviewer_id='77777777-7777-4777-8777-777777777777',reviewed_at=now() WHERE id='24242424-2424-4424-8424-242424242424' RETURNING id");
    });
    assert.equal(reviewerDirectDecision.rowCount,1,"database RLS must permit an authenticated tenant reviewer to decide an invoice match");
    const decisionAudit=await withTenant("33333333-3333-4333-8333-333333333333","isolation-reviewer-c",client=>client.query("SELECT action,reason,metadata FROM audit_events WHERE tenant_id=$1 AND object_id=$2 AND action='invoice_match_decision' ORDER BY created_at DESC LIMIT 1",["33333333-3333-4333-8333-333333333333","24242424-2424-4424-8424-242424242424"]));
    assert.equal(decisionAudit.rows[0]?.reason,"Synthetic direct SQL reviewer acceptance test","database trigger must create an audit event atomically");
    assert.equal(decisionAudit.rows[0]?.metadata?.decision,"confirmed");
    await assert.rejects(()=>withTenant("33333333-3333-4333-8333-333333333333","isolation-reviewer-c",client=>client.query("UPDATE match_reviews SET decision='rejected',reviewer_id='77777777-7777-4777-8777-777777777777',reviewed_at=now() WHERE id='24242424-2424-4424-8424-242424242424'")),/Finalised invoice match decisions are immutable/);
    await assert.rejects(()=>withTenant("33333333-3333-4333-8333-333333333333","isolation-reviewer-c",client=>client.query("UPDATE match_reviews SET evidence='{\"tampered\":true}'::jsonb WHERE id='24242424-2424-4424-8424-242424242424'")),/Finalised invoice match decisions are immutable/);
    await admin.query("INSERT INTO match_reviews(id,tenant_id,invoice_line_id,contract_id,site_id,confidence,decision,evidence) VALUES ('36363636-3636-4636-8636-363636363636','33333333-3333-4333-8333-333333333333','22222222-2222-4222-8222-222222222222','cccccccc-cccc-4ccc-8ccc-cccccccccccc','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','MEDIUM','candidate','{}'::jsonb)");
    await assert.rejects(()=>withTenant("33333333-3333-4333-8333-333333333333","isolation-reviewer-c",client=>client.query("UPDATE match_reviews SET decision='confirmed',reviewer_id='55555555-5555-4555-8555-555555555555',reviewed_at=now() WHERE id='36363636-3636-4636-8636-363636363636'")),/authenticated signed tenant actor/,"a reviewer cannot attribute a decision to another tenant member");
    await assert.rejects(()=>withTenant("33333333-3333-4333-8333-333333333333","isolation-reviewer-c",client=>client.query("UPDATE match_reviews SET evidence='{\"tampered\":true}'::jsonb WHERE id='36363636-3636-4636-8636-363636363636'")),/evidence and identity fields are immutable/,"a reviewer cannot rewrite candidate evidence");
    await assert.rejects(()=>withTenant("33333333-3333-4333-8333-333333333333","isolation-reviewer-c",client=>client.query("UPDATE match_reviews SET decision='confirmed',reviewer_id='77777777-7777-4777-8777-777777777777',reviewed_at=now() WHERE id='36363636-3636-4636-8636-363636363636'")),/audit reason of 3 to 2000 characters/);
    const actorGuardRun="35353535-3535-4535-8535-353535353535";
    await admin.query("INSERT INTO allocation_runs(id,tenant_id,payroll_pool_id,method_version,status,direct_amount,residual_amount,reviewer_id) VALUES ($1,'33333333-3333-4333-8333-333333333333','16161616-1616-4616-8616-161616161616','actor-binding-test','draft',0,100,'55555555-5555-4555-8555-555555555555')",[actorGuardRun]);
    await admin.query("GRANT UPDATE ON allocation_runs TO profitpilot_app");
    try {
      await assert.rejects(()=>withTenant("33333333-3333-4333-8333-333333333333","isolation-tenant-c",client=>client.query("UPDATE allocation_runs SET status='confirmed',reviewer_id='55555555-5555-4555-8555-555555555555' WHERE id=$1",[actorGuardRun])),/authenticated signed tenant actor/i,"an analyst cannot confirm payroll even when the runtime SQL privilege is temporarily granted");
      await assert.rejects(()=>withTenant("33333333-3333-4333-8333-333333333333","isolation-reviewer-c",client=>client.query("UPDATE allocation_runs SET status='confirmed',reviewer_id='55555555-5555-4555-8555-555555555555' WHERE id=$1",[actorGuardRun])),/authenticated signed tenant actor/i,"a reviewer cannot submit another member's reviewer identity to the payroll confirmation trigger");
    } finally {
      await admin.query("REVOKE UPDATE ON allocation_runs FROM profitpilot_app");
    }

    const invalidTenant=await request("/v1/tenants/not-a-uuid/contracts",{subject:"ci-api-analyst"});
    assert.equal(invalidTenant.status,400);
    const partialContractPeriod=await request(`/v1/tenants/${tenantA}/calculations`,{subject:"ci-api-analyst",method:"POST",body:{contractId:contractA,siteId:partialSite,periodStart:"2026-02-01",periodEnd:"2026-02-28"}});
    assert.equal(partialContractPeriod.status,422);
    assert.match((await partialContractPeriod.json()).error,/No matching contract\/site and effective contract version/,"a contract version that starts mid-period must not be treated as covering the full calculation period");

    const invalidDate=await request(`/v1/tenants/${tenantA}/imports`,{
      subject:"ci-api-analyst",method:"POST",
      body:{sourceType:"payroll",fileName:"payroll.csv",sha256:"a".repeat(64),permissionReference:"CI permission",periodStart:"2026-02-31",periodEnd:"2026-03-01"}
    });
    assert.equal(invalidDate.status,400,"impossible calendar dates must be rejected");

    // Complete synthetic source evidence proves contract tax-basis mismatch is
    // blocked only after both revenue and payroll inputs are otherwise present.
    const reviewerUser="abababab-abab-4bab-8bab-abababababac";
    const calculationSite="cdcdcdcd-cdcd-4cdc-8cdc-cdcdcdcdcdcd";
    await admin.query("INSERT INTO users(id,auth_subject,email,status) VALUES ($1,'ci-api-reviewer','reviewer@example.invalid','active') ON CONFLICT(id) DO NOTHING",[reviewerUser]);
    await admin.query("INSERT INTO tenant_memberships(tenant_id,user_id,role,status) VALUES ($1,$2,'reviewer','active') ON CONFLICT(tenant_id,user_id) DO UPDATE SET role='reviewer',status='active'",[tenantA,reviewerUser]);
    await admin.query("UPDATE contract_versions SET effective_to='2026-02-28' WHERE id='acacacac-acac-4cac-8cac-acacacacacac'");
    await admin.query("INSERT INTO sites(id,tenant_id,business_id,name) VALUES ($1,$2,$3,'CI tax-basis site') ON CONFLICT(id) DO NOTHING",[calculationSite,tenantA,businessA]);
    await admin.query("INSERT INTO contract_versions(id,tenant_id,contract_id,version_no,effective_from,effective_to,price,currency,tax_basis,billing_basis,approved_by,approved_at) VALUES ('dededede-dede-4ded-8ded-dededededede',$1,$2,2,'2026-03-01','2026-03-31',100,'AUD','gst_exclusive','monthly',$3,now()) ON CONFLICT(id) DO NOTHING",[tenantA,contractA,reviewerUser]);
    const taxEvidenceInvoiceBatch="eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
    const payrollBatch="f0f0f0f0-f0f0-40f0-80f0-f0f0f0f0f0f0";
    await admin.query("INSERT INTO import_batches(id,tenant_id,source_type,source_period_start,source_period_end,permission_ref,status,file_sha256,file_name,created_by) VALUES ($1,$2,'customer_invoice','2026-03-01','2026-03-31','CI synthetic permission','review',$3,'tax-invoice.csv',$4),($5,$2,'payroll','2026-03-01','2026-03-31','CI synthetic permission','registered',$6,'tax-payroll.csv',$4) ON CONFLICT(id) DO NOTHING",[taxEvidenceInvoiceBatch,tenantA,"1".repeat(64),userA,payrollBatch,"2".repeat(64)]);
    const invoiceRaw="f1f1f1f1-f1f1-41f1-81f1-f1f1f1f1f1f1";
    const payrollRaw="f2f2f2f2-f2f2-42f2-82f2-f2f2f2f2f2f2";
    await admin.query("INSERT INTO raw_import_rows(id,tenant_id,batch_id,row_number,payload) VALUES ($1,$2,$3,1,'{}'::jsonb),($4,$2,$5,1,'{}'::jsonb) ON CONFLICT(id) DO NOTHING",[invoiceRaw,tenantA,taxEvidenceInvoiceBatch,payrollRaw,payrollBatch]);
    const payrollPool="f3f3f3f3-f3f3-43f3-83f3-f3f3f3f3f3f3";
    const payrollSource="f4f4f4f4-f4f4-44f4-84f4-f4f4f4f4f4f4";
    const allocationRun="f5f5f5f5-f5f5-45f5-85f5-f5f5f5f5f5f5";
    await admin.query("INSERT INTO payroll_pools(id,tenant_id,batch_id,period_start,period_end,total_amount,currency,source_ref) VALUES ($1,$2,$3,'2026-03-01','2026-03-31',50,'AUD','CI payroll pool') ON CONFLICT(id) DO NOTHING",[payrollPool,tenantA,payrollBatch]);
    await admin.query("INSERT INTO payroll_source_rows(id,tenant_id,payroll_pool_id,raw_import_row_id,source_row_key,row_sha256,amount,currency) VALUES ($1,$2,$3,$4,'march-payroll-row',repeat('a',64),50,'AUD') ON CONFLICT(id) DO NOTHING",[payrollSource,tenantA,payrollPool,payrollRaw]);
    await admin.query("INSERT INTO invoices(id,tenant_id,direction,invoice_number,invoice_date,total_amount,currency,tax_basis,source_ref) VALUES ('f6f6f6f6-f6f6-46f6-86f6-f6f6f6f6f6f6',$1,'customer','CI-TAX-1','2026-03-15',100,'AUD','gst_inclusive','CI invoice') ON CONFLICT(id) DO NOTHING",[tenantA]);
    await admin.query("INSERT INTO invoice_lines(id,tenant_id,invoice_id,line_number,description,amount,source_row_id) VALUES ('f7f7f7f7-f7f7-47f7-87f7-f7f7f7f7f7f7',$1,'f6f6f6f6-f6f6-46f6-86f6-f6f6f6f6f6f6',1,'March service',100,$2) ON CONFLICT(id) DO NOTHING",[tenantA,invoiceRaw]);
    await admin.query("INSERT INTO match_reviews(id,tenant_id,invoice_line_id,contract_id,site_id,service_period_start,service_period_end,confidence,decision,evidence) VALUES ('f8f8f8f8-f8f8-48f8-88f8-f8f8f8f8f8f8',$1,'f7f7f7f7-f7f7-47f7-87f7-f7f7f7f7f7f7',$2,$3,'2026-03-01','2026-03-31','HIGH','confirmed','{}'::jsonb) ON CONFLICT(id) DO NOTHING",[tenantA,contractA,calculationSite]);
    await admin.query("INSERT INTO allocation_runs(id,tenant_id,payroll_pool_id,method_version,status,direct_amount,allocated_amount,non_site_amount,excluded_amount,residual_amount,reviewer_id) VALUES ($1,$2,$3,'CI-currency-gate','draft',50,0,0,0,0,$4) ON CONFLICT(id) DO NOTHING",[allocationRun,tenantA,payrollPool,reviewerUser]);
    await admin.query("INSERT INTO allocation_lines(tenant_id,allocation_run_id,site_id,bucket_type,amount,source_ref,payroll_source_row_id) VALUES ($1,$2,$3,'direct',50,'CI source row',$4)",[tenantA,allocationRun,calculationSite,payrollSource]);
    await admin.query("UPDATE allocation_runs SET status='confirmed' WHERE id=$1",[allocationRun]);
    const mismatchedTaxCalculation=await request(`/v1/tenants/${tenantA}/calculations`,{subject:"ci-api-analyst",method:"POST",body:{contractId:contractA,siteId:calculationSite,periodStart:"2026-03-01",periodEnd:"2026-03-31"}});
    assert.equal(mismatchedTaxCalculation.status,422);
    assert.match((await mismatchedTaxCalculation.json()).error,/contract-mismatched invoice tax\/currency basis/,"otherwise complete inputs with invoice tax basis different from the approved contract version must be blocked");

    const payrollRawUsd="f9f9f9f9-f9f9-49f9-89f9-f9f9f9f9f9f9";
    const payrollPoolUsd="abababab-abab-4bab-8bab-abababababab";
    const payrollSourceUsd="acacacac-acac-4cac-8cac-acacacacacac";
    const allocationRunUsd="adadadad-adad-4dad-8dad-adadadadadad";
    await admin.query("INSERT INTO raw_import_rows(id,tenant_id,batch_id,row_number,payload) VALUES ($1,$2,$3,2,'{}'::jsonb) ON CONFLICT(id) DO NOTHING",[payrollRawUsd,tenantA,payrollBatch]);
    await admin.query("INSERT INTO payroll_pools(id,tenant_id,batch_id,period_start,period_end,total_amount,currency,source_ref) VALUES ($1,$2,$3,'2026-03-01','2026-03-31',10,'USD','CI mismatched currency pool') ON CONFLICT(id) DO NOTHING",[payrollPoolUsd,tenantA,payrollBatch]);
    await admin.query("INSERT INTO payroll_source_rows(id,tenant_id,payroll_pool_id,raw_import_row_id,source_row_key,row_sha256,amount,currency) VALUES ($1,$2,$3,$4,'march-payroll-usd',repeat('b',64),10,'USD') ON CONFLICT(id) DO NOTHING",[payrollSourceUsd,tenantA,payrollPoolUsd,payrollRawUsd]);
    await admin.query("INSERT INTO allocation_runs(id,tenant_id,payroll_pool_id,method_version,status,direct_amount,allocated_amount,non_site_amount,excluded_amount,residual_amount,reviewer_id) VALUES ($1,$2,$3,'CI-currency-gate-usd','draft',10,0,0,0,0,$4) ON CONFLICT(id) DO NOTHING",[allocationRunUsd,tenantA,payrollPoolUsd,reviewerUser]);
    await admin.query("INSERT INTO allocation_lines(tenant_id,allocation_run_id,site_id,bucket_type,amount,source_ref,payroll_source_row_id) VALUES ($1,$2,$3,'direct',10,'CI USD source row',$4)",[tenantA,allocationRunUsd,calculationSite,payrollSourceUsd]);
    await admin.query("UPDATE allocation_runs SET status='confirmed' WHERE id=$1",[allocationRunUsd]);
    const mismatchedPayrollCurrency=await request(`/v1/tenants/${tenantA}/calculations`,{subject:"ci-api-analyst",method:"POST",body:{contractId:contractA,siteId:calculationSite,periodStart:"2026-03-01",periodEnd:"2026-03-31"}});
    assert.equal(mismatchedPayrollCurrency.status,422);
    assert.match((await mismatchedPayrollCurrency.json()).error,/payroll allocation currency/,"payroll source currency must match the contract currency before aggregation");

    const importBody={sourceType:"payroll",fileName:"payroll.csv",sha256:"b".repeat(64),permissionReference:"CI permission",periodStart:"2026-02-01",periodEnd:"2026-02-28",tenantId:tenantB};
    const created=await request(`/v1/tenants/${tenantA}/imports`,{subject:"ci-api-analyst",method:"POST",body:importBody});
    assert.equal(created.status,201);
    const createdBody=await created.json();
    assert.equal(createdBody.batch.status,"registered","metadata-only import registration must not claim the binary file was uploaded or stored");
    const blockedPayrollRows=await request(`/v1/tenants/${tenantA}/imports/${createdBody.batch.id}/rows`,{subject:"ci-api-analyst",method:"POST",body:{rows:[{source_row_key:"synthetic-row",amount:"100.00",currency:"AUD"}]}});
    assert.equal(blockedPayrollRows.status,422,"payroll row ingestion must remain blocked until privacy-safe mapping and reviewer workflow are implemented");
    const payrollRowsPersisted=await admin.query("SELECT count(*)::int AS count FROM raw_import_rows WHERE batch_id=$1",[createdBody.batch.id]);
    assert.equal(payrollRowsPersisted.rows[0].count,0,"blocked payroll rows must not be persisted in the generic raw-row table");
    const storedBatch=await admin.query("SELECT tenant_id FROM import_batches WHERE id=$1",[createdBody.batch.id]);
    assert.equal(storedBatch.rows[0].tenant_id,tenantA,"client-supplied tenant identifiers must not override the authenticated path tenant");
    const duplicate=await request(`/v1/tenants/${tenantA}/imports`,{subject:"ci-api-analyst",method:"POST",body:importBody});
    assert.equal(duplicate.status,200);
    assert.equal((await duplicate.json()).idempotent,true);

    const conflictingMetadata=await request(`/v1/tenants/${tenantA}/imports`,{subject:"ci-api-analyst",method:"POST",body:{...importBody,fileName:"different-name.csv"}});
    assert.equal(conflictingMetadata.status,409,"a repeated checksum with changed metadata must not be silently treated as the original registration");

    const invoiceImport=await request(`/v1/tenants/${tenantA}/imports`,{subject:"ci-api-analyst",method:"POST",body:{...importBody,sourceType:"customer_invoice",fileName:"invoices.csv",sha256:"d".repeat(64)}});
    assert.equal(invoiceImport.status,201);
    const invoiceBatch=(await invoiceImport.json()).batch.id;
    const firstRows=await request(`/v1/tenants/${tenantA}/imports/${invoiceBatch}/rows`,{subject:"ci-api-analyst",method:"POST",body:{rows:[{invoice_id:"INV-1",site:"Site A",date:"2026-02-10",amount:"100.00"}]}});
    assert.equal(firstRows.status,201);
    const identicalReplay=await request(`/v1/tenants/${tenantA}/imports/${invoiceBatch}/rows`,{subject:"ci-api-analyst",method:"POST",body:{rows:[{invoice_id:"INV-1",site:"Site A",date:"2026-02-10",amount:"100.00"}]}});
    assert.equal(identicalReplay.status,201);
    assert.equal((await identicalReplay.json()).inserted,0,"identical source-row retries must be idempotent");
    const conflictingReplay=await request(`/v1/tenants/${tenantA}/imports/${invoiceBatch}/rows`,{subject:"ci-api-analyst",method:"POST",body:{rows:[{invoice_id:"INV-1",site:"Site A",date:"2026-02-10",amount:"900.00"}]}});
    assert.equal(conflictingReplay.status,409,"a changed payload at an existing source row number must be rejected");
    const persistedInvoiceRow=await admin.query("SELECT payload->>'amount' AS amount FROM raw_import_rows WHERE batch_id=$1 AND row_number=1",[invoiceBatch]);
    assert.equal(persistedInvoiceRow.rows[0].amount,"100.00","a conflicting replay must not overwrite or replace original source evidence");

    const secondChunk=await request(`/v1/tenants/${tenantA}/imports/${invoiceBatch}/rows`,{subject:"ci-api-analyst",method:"POST",body:{startRowNumber:2,rows:[{invoice_id:"INV-2",site:"Site A",date:"2026-02-11",amount:"50.00"}]}});
    assert.equal(secondChunk.status,201,"subsequent import chunks must preserve original source row numbers");
    const secondChunkRow=await admin.query("SELECT row_number FROM raw_import_rows WHERE batch_id=$1 AND payload->>'invoice_id'='INV-2'",[invoiceBatch]);
    assert.equal(secondChunkRow.rows[0].row_number,2);
    const invalidStartRow=await request(`/v1/tenants/${tenantA}/imports/${invoiceBatch}/rows`,{subject:"ci-api-analyst",method:"POST",body:{startRowNumber:0,rows:[{invoice_id:"INV-3"}]}});
    assert.equal(invalidStartRow.status,400);

    const readerWrite=await request(`/v1/tenants/${tenantA}/imports`,{
      subject:"ci-api-reader",method:"POST",
      body:{...importBody,sha256:"c".repeat(64)}
    });
    assert.equal(readerWrite.status,403,"read_only members must not create imports");

    await admin.query("UPDATE tenant_memberships SET status='revoked' WHERE tenant_id=$1 AND user_id=$2",[tenantA,userA]);
    const revoked=await request(`/v1/tenants/${tenantA}/contracts`,{subject:"ci-api-analyst"});
    assert.equal(revoked.status,403,"revoked memberships must lose access immediately");
    let rateLimited=false;
    for(let i=0;i<105&&!rateLimited;i++){
      const response=await request("/v1/me");
      rateLimited=response.status===429;
    }
    assert.equal(rateLimited,true,"the API must enforce its configured per-client request limit");
  }finally{
    await new Promise(resolve=>api.close(resolve));
    await admin.end();
    await appPool.end();
    await new Promise(resolve=>jwksServer.close(resolve));
  }
});

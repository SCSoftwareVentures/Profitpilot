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
  process.env.AUTH_STEP_UP_ACR="urn:profitpilot:step-up";
  process.env.AUTH_JWKS_URL=`http://127.0.0.1:${jwksAddress.port}/.well-known/jwks.json`;
  if(!process.env.TENANT_CONTEXT_HMAC_SECRET)throw new Error("CI tenant context signing key is required");
  const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
  const [{default:app},{pool:appPool,withTenant}]=await Promise.all([import("../server/index.js"),import("../server/db.js")]);
  const api=createServer(app);
  await new Promise(resolve=>api.listen(0,"127.0.0.1",resolve));
  const apiAddress=api.address();
  const base=`http://127.0.0.1:${apiAddress.port}`;
  async function token(subject){
    return new SignJWT({email:subject+"@example.invalid",auth_time:Math.floor(Date.now()/1000),acr:"urn:profitpilot:step-up"})
      .setProtectedHeader({alg:"RS256",kid:jwk.kid})
      .setIssuer(issuer).setAudience(audience).setSubject(subject)
      .setIssuedAt().setExpirationTime("5m").setJti(randomBytes(16).toString("hex")).sign(privateKey);
  }
  async function customToken(subject,{issuedAt=Math.floor(Date.now()/1000),expiresAt=Math.floor(Date.now()/1000)+300,includeIssuedAt=true,includeExpiry=true,authTime,acr}={}){
    const claims={email:subject+"@example.invalid"};if(authTime!==undefined)claims.auth_time=authTime;if(acr!==undefined)claims.acr=acr;
    let jwt=new SignJWT(claims).setProtectedHeader({alg:"RS256",kid:jwk.kid}).setIssuer(issuer).setAudience(audience).setSubject(subject);
    if(includeIssuedAt)jwt=jwt.setIssuedAt(issuedAt);
    if(includeExpiry)jwt=jwt.setExpirationTime(expiresAt);
    jwt=jwt.setJti(randomBytes(16).toString("hex"));
    return jwt.sign(privateKey);
  }
  async function request(path,{subject,method="GET",body}={}){
    const headers={};
    if(subject)headers.authorization="Bearer "+await token(subject);
    if(body!==undefined)headers["content-type"]="application/json";
    return fetch(base+path,{method,headers,body:body===undefined?undefined:JSON.stringify(body)});
  }
  try{
    const userD="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    const userE="cccccccc-cccc-4ccc-8ccc-cccccccccccc";
    await admin.query("INSERT INTO users(id,auth_subject,email,status) VALUES ($1,'ci-api-analyst','analyst@example.invalid','active'),($2,'ci-api-reader','reader@example.invalid','active'),($3,'ci-api-tenant-b-only','tenant-b@example.invalid','active'),($4,'ci-api-reviewer','reviewer@example.invalid','active'),($5,'ci-api-owner','owner@example.invalid','active') ON CONFLICT(auth_subject) DO UPDATE SET status='active'",[userA,userB,userC,userD,userE]);
    await admin.query("INSERT INTO tenant_memberships(tenant_id,user_id,role,status) VALUES ($1,$2,'analyst','active'),($1,$3,'read_only','active') ON CONFLICT(tenant_id,user_id) DO UPDATE SET role=EXCLUDED.role,status='active'",[tenantA,userA,userB]);
    await admin.query("INSERT INTO tenant_memberships(tenant_id,user_id,role,status) VALUES ($1,$2,'analyst','active') ON CONFLICT(tenant_id,user_id) DO UPDATE SET role=EXCLUDED.role,status='active'",[tenantB,userC]);
    await admin.query("INSERT INTO tenant_memberships(tenant_id,user_id,role,status) VALUES ($1,$2,'reviewer','active') ON CONFLICT(tenant_id,user_id) DO UPDATE SET role=EXCLUDED.role,status='active'",[tenantA,userD]);
    await admin.query("INSERT INTO tenant_memberships(tenant_id,user_id,role,status) VALUES ($1,$2,'owner','active') ON CONFLICT(tenant_id,user_id) DO UPDATE SET role=EXCLUDED.role,status='active'",[tenantA,userE]);
    await admin.query("INSERT INTO businesses(id,tenant_id,name) VALUES ($1,$2,'CI Business A') ON CONFLICT(id) DO NOTHING",[businessA,tenantA]);
    await admin.query("INSERT INTO contracts(id,tenant_id,business_id,customer_name,status) VALUES ($1,$2,$3,'CI Customer A','active') ON CONFLICT(id) DO NOTHING",[contractA,tenantA,businessA]);
    await admin.query("INSERT INTO businesses(id,tenant_id,name) VALUES ($1,$2,'CI Business B') ON CONFLICT(id) DO NOTHING",[businessB,tenantB]);
    await admin.query("INSERT INTO contracts(id,tenant_id,business_id,customer_name,status) VALUES ($1,$2,$3,'CI Customer B','active') ON CONFLICT(id) DO NOTHING",[contractB,tenantB,businessB]);
    await assert.rejects(()=>admin.query("INSERT INTO import_batches(id,tenant_id,source_type,permission_ref,status,file_sha256,file_name,created_by) VALUES ($1,$2,'payroll','CI permission','uploaded',$3,'cross-tenant.csv',$4)",["bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",tenantA,"d".repeat(64),userC]),/foreign key constraint/i,"a user who belongs only to tenant B must not be recorded as the creator of a tenant A import");

    const healthResponse=await request("/health");
    assert.equal(healthResponse.headers.get("x-powered-by"),null,"the API must not disclose its Express framework");
    assert.ok(healthResponse.headers.get("x-content-type-options"),"Helmet security headers must be present");
    const savedAudience=process.env.AUTH_AUDIENCE;
    delete process.env.AUTH_AUDIENCE;
    const unavailableAuth=await fetch(base+"/v1/me",{headers:{authorization:"Bearer "+await token("ci-api-analyst")}});
    assert.equal(unavailableAuth.status,503,"missing authentication configuration must fail closed as service unavailable");
    process.env.AUTH_AUDIENCE=savedAudience;
    const savedNodeEnv=process.env.NODE_ENV;
    const savedJwksUrl=process.env.AUTH_JWKS_URL;
    process.env.NODE_ENV="production";
    process.env.AUTH_JWKS_URL="http://127.0.0.1/.well-known/jwks.json";
    const insecureJwks=await fetch(base+"/v1/me",{headers:{authorization:"Bearer "+await token("ci-api-analyst")}});
    assert.equal(insecureJwks.status,503,"production authentication must reject a non-HTTPS JWKS endpoint");
    process.env.NODE_ENV=savedNodeEnv;
    process.env.AUTH_JWKS_URL=savedJwksUrl;
    const oversizedToken=await fetch(base+"/v1/me",{headers:{authorization:"Bearer "+"a".repeat(8193)}});
    assert.equal(oversizedToken.status,401,"oversized bearer tokens must be rejected before remote key verification");
    const trackedSessionToken=await token("ci-api-analyst");
    const trackedSessionResponse=await fetch(base+"/v1/me",{headers:{authorization:"Bearer "+trackedSessionToken}});
    assert.equal(trackedSessionResponse.status,200,"valid jti-bearing tokens must register a server-side session");
    const revocableSessionToken=await token("ci-api-analyst");
    const revocableSessionResponse=await fetch(base+"/v1/me",{headers:{authorization:"Bearer "+revocableSessionToken}});
    assert.equal(revocableSessionResponse.status,200);
    const sessionListResponse=await fetch(base+"/v1/me/sessions",{headers:{authorization:"Bearer "+trackedSessionToken}});
    assert.equal(sessionListResponse.status,200,"users must be able to inspect their own active and revoked sessions");
    const sessionList=(await sessionListResponse.json()).items;
    assert.ok(sessionList.length>=2,"session inventory must contain registered sessions");
    const sessionPayload=JSON.parse(Buffer.from(revocableSessionToken.split(".")[1],"base64url").toString("utf8"));
    const revokeResponse=await fetch(base+`/v1/me/sessions/${sessionPayload.jti}`,{method:"DELETE",headers:{authorization:"Bearer "+trackedSessionToken}});
    assert.equal(revokeResponse.status,200,"a user must be able to revoke another one of their own sessions");
    const revokedSessionUse=await fetch(base+"/v1/me",{headers:{authorization:"Bearer "+revocableSessionToken}});
    assert.equal(revokedSessionUse.status,401,"a revoked access session must be rejected on its next request");

    const noToken=await request("/v1/me");
    assert.equal(noToken.status,401,"requests without a bearer token must be rejected");
    const noExpiry=await fetch(base+"/v1/me",{headers:{authorization:"Bearer "+await customToken("ci-api-analyst",{includeExpiry:false})}});
    assert.equal(noExpiry.status,401,"JWTs without an expiry claim must be rejected");
    const staleToken=await fetch(base+"/v1/me",{headers:{authorization:"Bearer "+await customToken("ci-api-analyst",{issuedAt:Math.floor(Date.now()/1000)-3600,expiresAt:Math.floor(Date.now()/1000)+60})}});
    assert.equal(staleToken.status,401,"access tokens older than the configured maximum age must be rejected");
    const expiredToken=await fetch(base+"/v1/me",{headers:{authorization:"Bearer "+await customToken("ci-api-analyst",{issuedAt:Math.floor(Date.now()/1000)-600,expiresAt:Math.floor(Date.now()/1000)-30})}});
    assert.equal(expiredToken.status,401,"expired access tokens must be rejected");

    assert.equal(noToken.headers.get("cache-control"),"no-store","unauthenticated API responses must not be cached");
    const malformed=await fetch(base+"/v1/me",{method:"POST",headers:{"content-type":"application/json"},body:"{"});
    assert.equal(malformed.status,400,"malformed JSON must be rejected");
    assert.equal((await malformed.json()).error,"Invalid request","parser details must not be exposed to clients");

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
    await assert.rejects(()=>withTenant(tenantA,"ci-api-analyst",client=>client.query("INSERT INTO contracts(id,tenant_id,business_id,customer_name,status) VALUES ($1,$2,$3,'RLS write probe','active')",["99999999-9999-4999-8999-999999999999",tenantB,businessB])),/row-level security/i,"RLS WITH CHECK must reject cross-tenant writes");

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

    const matchId="99999999-9999-4999-8999-999999999999";
    const analystDecision=await request(`/v1/tenants/${tenantA}/matches/${matchId}/decision`,{subject:"ci-api-analyst",method:"POST",body:{decision:"confirmed",reason:"CI role test"}});
    assert.equal(analystDecision.status,403,"analysts must not finalise match-review decisions");
    const readerDecision=await request(`/v1/tenants/${tenantA}/matches/${matchId}/decision`,{subject:"ci-api-reader",method:"POST",body:{decision:"confirmed",reason:"CI role test"}});
    assert.equal(readerDecision.status,403,"read-only members must not finalise match-review decisions");
    const staleStepUp=await fetch(base+`/v1/tenants/${tenantA}/matches/${matchId}/decision`,{method:"POST",headers:{"content-type":"application/json",authorization:"Bearer "+await customToken("ci-api-reviewer",{authTime:Math.floor(Date.now()/1000)-600,acr:"urn:profitpilot:step-up"})},body:JSON.stringify({decision:"confirmed",reason:"CI stale step-up test"})});
    assert.equal(staleStepUp.status,403,"sensitive decisions must reject stale step-up authentication");
    const missingStepUp=await fetch(base+`/v1/tenants/${tenantA}/matches/${matchId}/decision`,{method:"POST",headers:{"content-type":"application/json",authorization:"Bearer "+await customToken("ci-api-reviewer")},body:JSON.stringify({decision:"confirmed",reason:"CI missing step-up test"})});
    assert.equal(missingStepUp.status,403,"sensitive decisions must reject tokens without step-up claims");
    const reviewerDecision=await request(`/v1/tenants/${tenantA}/matches/${matchId}/decision`,{subject:"ci-api-reviewer",method:"POST",body:{}});
    assert.equal(reviewerDecision.status,400,"reviewers must pass role authorisation before decision payload validation");

    const reviewerImport=await request(`/v1/tenants/${tenantA}/imports`,{subject:"ci-api-reviewer",method:"POST",body:{...importBody,sha256:"e".repeat(64)}});
    assert.equal(reviewerImport.status,403,"reviewers must not create source imports");

    const permissionView=await request(`/v1/tenants/${tenantA}/security/permissions`,{subject:"ci-api-owner"});
    assert.equal(permissionView.status,200,"tenant owners must be able to inspect the permission catalogue and overrides");
    assert.ok((await permissionView.json()).catalogue.some(x=>x.permission_key==="security.audit.read"));
    const ownerGrant=await request(`/v1/tenants/${tenantA}/security/permissions/overrides`,{subject:"ci-api-owner",method:"POST",body:{userId:userD,permissionKey:"imports.create",effect:"grant",reason:"Temporary delegated import authority"}});
    assert.equal(ownerGrant.status,201,"an owner may create a step-up-protected member permission override");
    const grantedImport=await request(`/v1/tenants/${tenantA}/imports`,{subject:"ci-api-reviewer",method:"POST",body:{...importBody,sha256:"1".repeat(64)}});
    assert.equal(grantedImport.status,201,"a member grant must take effect on subsequent API requests");
    const ownerDeny=await request(`/v1/tenants/${tenantA}/security/permissions/overrides`,{subject:"ci-api-owner",method:"POST",body:{userId:userD,permissionKey:"imports.create",effect:"deny",reason:"Remove temporary import authority"}});
    assert.equal(ownerDeny.status,201,"an owner may replace a grant with an explicit denial");
    const deniedImport=await request(`/v1/tenants/${tenantA}/imports`,{subject:"ci-api-reviewer",method:"POST",body:{...importBody,sha256:"2".repeat(64)}});
    assert.equal(deniedImport.status,403,"an explicit member denial must override role defaults and prior grants");
    const removedOverride=await fetch(base+`/v1/tenants/${tenantA}/security/permissions/overrides/${userD}/imports.create`,{method:"DELETE",headers:{"content-type":"application/json",authorization:"Bearer "+await token("ci-api-owner")},body:JSON.stringify({reason:"Return to default role permissions"})});
    assert.equal(removedOverride.status,200,"an owner may remove a member override with a recorded reason");
    const auditView=await request(`/v1/tenants/${tenantA}/security/audit?limit=20`,{subject:"ci-api-owner"});
    assert.equal(auditView.status,200,"tenant owners must be able to inspect security audit events");
    const auditBody=await auditView.json();
    assert.equal(auditBody.integrity.is_valid,true,"the tenant audit hash chain must verify");
    const privacySubmit=await request(`/v1/tenants/${tenantA}/privacy/requests`,{subject:"ci-api-analyst",method:"POST",body:{requestType:"access",details:"Please provide a copy of personal information held about me."}});
    assert.equal(privacySubmit.status,201,"tenant members must be able to submit privacy requests");
    const privacyItem=await privacySubmit.json();
    const secondPrivacySubmit=await request(`/v1/tenants/${tenantA}/privacy/requests`,{subject:"ci-api-reader",method:"POST",body:{requestType:"access",details:"Please provide the personal information held about me."}});
    assert.equal(secondPrivacySubmit.status,201,"a second member may submit their own privacy request");
    const secondPrivacyItem=await secondPrivacySubmit.json();
    const privacyMine=await request(`/v1/tenants/${tenantA}/privacy/requests`,{subject:"ci-api-analyst"});
    assert.equal(privacyMine.status,200);
    assert.deepEqual((await privacyMine.json()).items.map(item=>item.id),[privacyItem.id],"members must see only their own privacy requests");
    const analystDatabasePrivacyRows=await withTenant(tenantA,"ci-api-analyst",client=>client.query("SELECT id FROM privacy_requests ORDER BY id"));
    assert.deepEqual(analystDatabasePrivacyRows.rows.map(row=>row.id),[privacyItem.id],"PostgreSQL RLS must hide another member's privacy request even from direct runtime SQL");
    await assert.rejects(()=>withTenant(tenantA,"ci-api-analyst",client=>client.query("INSERT INTO privacy_requests(tenant_id,subject_user_id,submitted_by,request_type,details) VALUES($1,$2,$2,'access','Attempt to submit for another member')",[tenantA,userB])),/row-level security/i,"members must not submit privacy requests on behalf of another member");
    const analystCrossMemberUpdate=await withTenant(tenantA,"ci-api-analyst",client=>client.query("UPDATE privacy_requests SET status='withdrawn' WHERE id=$1 RETURNING id",[secondPrivacyItem.id]));
    assert.equal(analystCrossMemberUpdate.rowCount,0,"members must not update another member's privacy request");
    const secondWithdraw=await request(`/v1/tenants/${tenantA}/privacy/requests/${secondPrivacyItem.id}/withdraw`,{subject:"ci-api-reader",method:"POST",body:{reason:"Request withdrawn by its submitter"}});
    assert.equal(secondWithdraw.status,200,"a member may withdraw their own pending request through the constrained database function");
    assert.equal((await secondWithdraw.json()).status,"withdrawn");
    const privacyManage=await request(`/v1/tenants/${tenantA}/privacy/requests/manage`,{subject:"ci-api-owner"});
    assert.equal(privacyManage.status,200,"owners must be able to review tenant privacy requests");
    assert.equal((await privacyManage.json()).items.length,2,"privacy managers may review requests across their tenant");
    const verifyPrivacy=await request(`/v1/tenants/${tenantA}/privacy/requests/${privacyItem.id}/decision`,{subject:"ci-api-owner",method:"POST",body:{action:"verify_identity",reason:"Identity evidence reviewed"}});
    assert.equal(verifyPrivacy.status,200);
    const beginPrivacy=await request(`/v1/tenants/${tenantA}/privacy/requests/${privacyItem.id}/decision`,{subject:"ci-api-owner",method:"POST",body:{action:"begin_review",reason:"Identity verified; review commenced"}});
    assert.equal(beginPrivacy.status,200);
    const holdPrivacy=await request(`/v1/tenants/${tenantA}/privacy/requests/${privacyItem.id}/decision`,{subject:"ci-api-owner",method:"POST",body:{action:"place_legal_hold",reason:"Preserve records for an active dispute"}});
    assert.equal(holdPrivacy.status,200);
    assert.equal((await holdPrivacy.json()).status,"legal_hold");
    const releasePrivacy=await request(`/v1/tenants/${tenantA}/privacy/requests/${privacyItem.id}/decision`,{subject:"ci-api-owner",method:"POST",body:{action:"release_legal_hold",reason:"Dispute preservation requirement has ended"}});
    assert.equal(releasePrivacy.status,200);
    const fulfilPrivacy=await request(`/v1/tenants/${tenantA}/privacy/requests/${privacyItem.id}/decision`,{subject:"ci-api-owner",method:"POST",body:{action:"fulfil",reason:"Attempt to close request without an implemented export executor",resolutionSummary:"This must not be accepted as proof of fulfilment."}});
    assert.equal(fulfilPrivacy.status,409,"the API must not claim fulfilment when export and deletion execution are not implemented");
    const stillUnderReview=await request(`/v1/tenants/${tenantA}/privacy/requests/manage`,{subject:"ci-api-owner"});
    assert.equal(stillUnderReview.status,200);
    assert.equal(stillUnderReview.items.find(item=>item.id===privacyItem.id)?.status,"under_review","a rejected fulfilment attempt must leave the request open for genuine completion");
    const privacyAudit=await request(`/v1/tenants/${tenantA}/security/audit?limit=100`,{subject:"ci-api-owner"});
    assert.equal((await privacyAudit.json()).integrity.is_valid,true,"privacy request events must remain verifiable in the audit chain");
    const privacyOtherTenant=await request(`/v1/tenants/${tenantB}/privacy/requests/manage`,{subject:"ci-api-tenant-b-only"});
    assert.equal(privacyOtherTenant.status,403,"privacy requests must remain tenant-scoped and require manager permission");
    assert.ok(auditBody.integrity.event_count>=3,"permission changes must be recorded in the append-only audit chain");
    await assert.rejects(()=>withTenant(tenantA,"ci-api-owner",client=>client.query("UPDATE audit_events SET reason='tampered' WHERE tenant_id=$1",[tenantA])),/permission denied/i,"the runtime role must not update append-only audit events");
    const memberCannotManage=await request(`/v1/tenants/${tenantA}/security/permissions/overrides`,{subject:"ci-api-reviewer",method:"POST",body:{userId:userA,permissionKey:"imports.create",effect:"grant",reason:"Must be denied"}});
    assert.equal(memberCannotManage.status,403,"non-owners must not manage member permission overrides");
    await admin.query("INSERT INTO tenant_membership_permission_overrides(tenant_id,user_id,permission_key,effect,reason,granted_by) VALUES ($1,$2,'imports.create','grant','Temporary CI override grant',$2)",[tenantA,userD]);
    const overriddenReviewerImport=await request(`/v1/tenants/${tenantA}/imports`,{subject:"ci-api-reviewer",method:"POST",body:{...importBody,sha256:"f".repeat(64)}});
    assert.equal(overriddenReviewerImport.status,201,"an explicit tenant-scoped member grant must override the role default");
    await admin.query("UPDATE tenant_membership_permission_overrides SET effect='deny',reason='Temporary CI override denial' WHERE tenant_id=$1 AND user_id=$2 AND permission_key='imports.create'",[tenantA,userD]);
    const deniedReviewerImport=await request(`/v1/tenants/${tenantA}/imports`,{subject:"ci-api-reviewer",method:"POST",body:{...importBody,sha256:"a".repeat(64)}});
    assert.equal(deniedReviewerImport.status,403,"an explicit tenant-scoped member denial must override a role grant");
    await admin.query("DELETE FROM tenant_membership_permission_overrides WHERE tenant_id=$1 AND user_id=$2 AND permission_key='imports.create'",[tenantA,userD]);
    const reviewerRows=await request(`/v1/tenants/${tenantA}/imports/${matchId}/rows`,{subject:"ci-api-reviewer",method:"POST",body:{rows:[{invoice:"CI"}]}});
    assert.equal(reviewerRows.status,403,"reviewers must not ingest source rows");
    const analystRows=await request(`/v1/tenants/${tenantA}/imports/${matchId}/rows`,{subject:"ci-api-analyst",method:"POST",body:{rows:[{invoice:"CI"}]}});
    assert.equal(analystRows.status,404,"analysts may ingest rows, subject to tenant-scoped batch existence");

    const readerValidation=await request(`/v1/tenants/${tenantA}/imports/${matchId}/validate`,{subject:"ci-api-reader",method:"POST",body:{}});
    assert.equal(readerValidation.status,403,"read-only members must not initiate validation");
    const reviewerValidation=await request(`/v1/tenants/${tenantA}/imports/${matchId}/validate`,{subject:"ci-api-reviewer",method:"POST",body:{}});
    assert.equal(reviewerValidation.status,404,"reviewers may validate only an existing tenant-scoped batch");

    const readerCalculation=await request(`/v1/tenants/${tenantA}/calculations`,{subject:"ci-api-reader",method:"POST",body:{}});
    assert.equal(readerCalculation.status,403,"read-only members must not create calculations");
    const analystCalculation=await request(`/v1/tenants/${tenantA}/calculations`,{subject:"ci-api-analyst",method:"POST",body:{}});
    assert.equal(analystCalculation.status,400,"analysts may initiate calculations subject to valid inputs");

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

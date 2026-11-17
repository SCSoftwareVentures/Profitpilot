import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";

const enabled=Boolean(process.env.TEST_ADMIN_DATABASE_URL&&process.env.TEST_APP_DATABASE_URL);

test("all public tables require explicit security classification and restrictive tenant isolation",{
 skip:!enabled
},async()=>{
 const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
 const app=new pg.Pool({connectionString:process.env.TEST_APP_DATABASE_URL});
 const globalReadOnly=new Set(["permission_catalog","role_permissions"]);
 const specialScoped=new Set(["tenants","users"]);
 const directWriteForbidden=new Set([
  "tenants","users","tenant_memberships","permission_catalog",
  "role_permissions","tenant_membership_permission_overrides","businesses","sites","contracts","contract_versions","variations"
 ]);
 const safeName=name=>'"'+name.replaceAll('"','""')+'"';
 let client;
 try{
  const {rows:tables}=await admin.query([
   "SELECT c.relname AS name,c.relrowsecurity AS rls,c.relforcerowsecurity AS forced,",
   "EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attname='tenant_id'",
   "AND a.attnum>0 AND NOT a.attisdropped) AS tenant_scoped",
   "FROM pg_class c JOIN pg_namespace ns ON ns.oid=c.relnamespace",
   "WHERE ns.nspname='public' AND c.relkind IN ('r','p') AND NOT c.relispartition",
   "ORDER BY c.relname"
  ].join("\n"));
  assert.ok(tables.length>=16,"the security audit must inspect the migrated application schema");
  const nameSet=new Set(tables.map(t=>t.name));
  for(const required of [...globalReadOnly,...specialScoped,"tenant_memberships","privacy_requests"]){
   assert.ok(nameSet.has(required),"expected application security table missing: "+required);
  }
  const {rows:policies}=await admin.query(
   "SELECT tablename,policyname,cmd,qual,with_check FROM pg_policies WHERE schemaname='public'"
  );
  const tenantValidator=/private\.current_tenant_id\s*\(/i;
  const protectedTables=[];
  for(const table of tables){
   if(globalReadOnly.has(table.name)){
    assert.equal(table.tenant_scoped,false,"global catalogue cannot quietly become tenant-owned: "+table.name);
    continue;
   }
   assert.ok(table.tenant_scoped||specialScoped.has(table.name),
    "public table lacks a tenant_id and has no reviewed global classification: "+table.name);
   assert.equal(table.rls,true,"RLS must be enabled: "+table.name);
   assert.equal(table.forced,true,"RLS must be forced even for table owners: "+table.name);
   protectedTables.push(table.name);
   for(const policy of policies.filter(p=>p.tablename===table.name)){
    if(["ALL","SELECT","UPDATE","DELETE"].includes(policy.cmd)){
     assert.match(policy.qual||"",tenantValidator,
      "a public RLS read/write policy lacks signed tenant validation: "+table.name+"/"+policy.policyname);
    }
    if(["ALL","INSERT","UPDATE"].includes(policy.cmd)){
     const check=policy.with_check||"";
     assert.ok(tenantValidator.test(check)||(table.name==="users"&&/\bfalse\b/i.test(check)),
      "a public RLS write policy lacks a tenant-scoped WITH CHECK: "+table.name+"/"+policy.policyname);
    }
   }
  }

  // Verify the actual application's database role, not the migration owner.
  client=await app.connect();
  const selectable=[];
  for(const name of protectedTables){
   const {rows:[access]}=await admin.query(
    "SELECT has_table_privilege('profitpilot_app',$1,'SELECT') AS allowed",
    ["public."+name]
   );
   if(access.allowed)selectable.push(name);
  }
  for(const name of selectable){
   const rows=await client.query("SELECT 1 FROM public."+safeName(name)+" LIMIT 1");
   assert.equal(rows.rowCount,0,"unscoped runtime read exposed records from "+name);
  }
  await client.query("BEGIN");
  try{
   await client.query("SELECT set_config('app.tenant_id',$1,true)",
    ["11111111-1111-4111-8111-111111111111"]);
   for(const name of selectable){
    const rows=await client.query("SELECT 1 FROM public."+safeName(name)+" LIMIT 1");
    assert.equal(rows.rowCount,0,
     "a forged unsigned tenant_id GUC exposed records from "+name);
   }
  }finally{await client.query("ROLLBACK");}

  for(const name of directWriteForbidden){
   for(const privilege of ["INSERT","UPDATE","DELETE","TRUNCATE"]){
    const {rows:[access]}=await admin.query(
     "SELECT has_table_privilege('profitpilot_app',$1,$2) AS allowed",
     ["public."+name,privilege]
    );
    assert.equal(access.allowed,false,
     "runtime database role retains direct "+privilege+" on "+name);
   }
  }
  for(const name of ["import_batches","raw_import_rows","mapping_decisions","payroll_pools","allocation_runs","allocation_lines","invoices","invoice_lines","match_reviews","calculation_runs","privacy_requests"]){
   for(const privilege of ["DELETE","TRUNCATE"]){
    const {rows:[access]}=await admin.query("SELECT has_table_privilege('profitpilot_app',$1,$2) AS allowed",["public."+name,privilege]);
    assert.equal(access.allowed,false,"runtime direct destructive financial/privacy privilege: "+name+" "+privilege);
   }
   assert.ok(policies.some(p=>p.tablename===name&&p.cmd==="INSERT"&&/has_scoped_permission/.test(p.with_check||"")),"runtime write authority policy missing: "+name);
  }
  for(const privilege of ["DELETE","TRUNCATE"]){
   const {rows:[access]}=await admin.query(
    "SELECT has_table_privilege('profitpilot_app','public.privacy_requests',$1) AS allowed",
    [privilege]
   );
   assert.equal(access.allowed,false,"privacy requests must not be deleted directly by runtime");
  }

  for(const privilege of ["CREATE","TEMPORARY"]){
   const {rows:[access]}=await admin.query("SELECT has_database_privilege('profitpilot_app',current_database(),$1) AS allowed",[privilege]);
   assert.equal(access.allowed,false,"runtime cannot create database objects: "+privilege);
  }
  for(const schema of ["public","private"]){
   const {rows:[access]}=await admin.query("SELECT has_schema_privilege('profitpilot_app',$1,'CREATE') AS allowed",[schema]);
   assert.equal(access.allowed,false,"runtime cannot shadow schema objects: "+schema);
  }
  const {rows:[rawAccess]}=await admin.query("SELECT has_column_privilege('profitpilot_app','public.raw_import_rows','payload','SELECT') AS payload_read,has_column_privilege('profitpilot_app','public.raw_import_rows','payload','INSERT') AS payload_insert");
  assert.deepEqual(rawAccess,{payload_read:false,payload_insert:false},"raw financial payloads require controlled read and stage functions");
  const {rows:[defaults]}=await admin.query([
   "SELECT count(*)::integer AS unsafe FROM pg_default_acl d",
   "JOIN pg_namespace ns ON ns.oid=d.defaclnamespace",
   "CROSS JOIN LATERAL aclexplode(d.defaclacl) acl",
   "JOIN pg_roles grantee ON grantee.oid=acl.grantee",
   "WHERE ns.nspname='public' AND d.defaclobjtype='r'",
   "AND grantee.rolname='profitpilot_app'"
  ].join("\n"));
  assert.equal(defaults.unsafe,0,
   "new public tables must not inherit unreviewed runtime privileges");

  const {rows:views}=await admin.query([
   "SELECT c.relname FROM pg_class c JOIN pg_namespace ns ON ns.oid=c.relnamespace",
   "WHERE ns.nspname='public' AND c.relkind IN ('v','m')"
  ].join("\n"));
  assert.deepEqual(views,[],
   "a new public view/materialized view needs an explicit security review");

  const {rows:privateTables}=await admin.query([
   "SELECT c.relname FROM pg_class c JOIN pg_namespace ns ON ns.oid=c.relnamespace",
   "WHERE ns.nspname='private' AND c.relkind IN ('r','p')"
  ].join("\n"));
  for(const item of privateTables){
   const relation="private."+item.relname;
   for(const privilege of ["SELECT","INSERT","UPDATE","DELETE","TRUNCATE"]){
    const {rows:[access]}=await admin.query(
     "SELECT has_table_privilege('profitpilot_app',$1,$2) AS allowed",
     [relation,privilege]
    );
    assert.equal(access.allowed,false,
     "private security table has a direct runtime privilege: "+relation+" / "+privilege);
   }
  }
 }finally{
  if(client)client.release();
  await Promise.all([admin.end(),app.end()]);
 }
});

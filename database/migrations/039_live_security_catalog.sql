-- Migration-time reviewed schema fingerprint. No application data or secret
-- values are included. Runtime can ask for a boolean verification only.
BEGIN;
CREATE TABLE private.security_catalog_baseline(
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 revision integer NOT NULL CHECK(revision=39),
 digest text NOT NULL CHECK(digest ~ '^[0-9a-f]{64}$')
);
REVOKE ALL ON private.security_catalog_baseline FROM PUBLIC,profitpilot_app;
CREATE TRIGGER security_catalog_baseline_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON private.security_catalog_baseline
 FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();

CREATE FUNCTION private.security_catalog_digest()
RETURNS text LANGUAGE sql STABLE SET search_path=pg_catalog AS $fn$
 WITH relations AS (
  SELECT c.*,n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname IN ('public','private') AND c.relkind IN ('r','p','v','m','f','S')
 ), functions AS (
  SELECT p.*,n.nspname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
  WHERE n.nspname IN ('public','private') AND NOT EXISTS(
   SELECT 1 FROM pg_depend d WHERE d.classid='pg_proc'::regclass AND d.objid=p.oid AND d.deptype='e')
 ), roles AS (
  SELECT * FROM pg_roles WHERE rolname IN ('profitpilot_app','profitpilot_context_owner','profitpilot_scanner','profitpilot_identity_operator','profitpilot_audit_reader','profitpilot_recovery_reader')
 ), entries AS (
  SELECT jsonb_build_array('relation',r.nspname,r.relname,r.relkind,pg_get_userbyid(r.relowner),r.relrowsecurity,r.relforcerowsecurity,r.reloptions,
   CASE WHEN r.relkind IN ('v','m') THEN pg_get_viewdef(r.oid,false) END) AS item FROM relations r
  UNION ALL SELECT jsonb_build_array('relation_acl',r.nspname,r.relname,pg_get_userbyid(a.grantor),CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,a.privilege_type,a.is_grantable)
   FROM relations r CROSS JOIN LATERAL aclexplode(CASE WHEN cardinality(coalesce(r.relacl,acldefault(CASE WHEN r.relkind='S' THEN 'S'::"char" ELSE 'r'::"char" END,r.relowner)))>0 THEN coalesce(r.relacl,acldefault(CASE WHEN r.relkind='S' THEN 'S'::"char" ELSE 'r'::"char" END,r.relowner)) END) a
  UNION ALL SELECT jsonb_build_array('column',r.nspname,r.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attidentity,a.attgenerated,pg_get_expr(d.adbin,d.adrelid))
   FROM relations r JOIN pg_attribute a ON a.attrelid=r.oid AND a.attnum>0 AND NOT a.attisdropped
   LEFT JOIN pg_attrdef d ON d.adrelid=r.oid AND d.adnum=a.attnum
  UNION ALL SELECT jsonb_build_array('column_acl',r.nspname,r.relname,col.attname,pg_get_userbyid(a.grantor),CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,a.privilege_type,a.is_grantable)
   FROM relations r JOIN pg_attribute col ON col.attrelid=r.oid AND col.attnum>0 AND NOT col.attisdropped
   CROSS JOIN LATERAL aclexplode(CASE WHEN cardinality(col.attacl)>0 THEN col.attacl END) a
  UNION ALL SELECT jsonb_build_array('policy',r.nspname,r.relname,p.polname,p.polcmd,p.polpermissive,
   ARRAY(SELECT CASE WHEN x=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x)::text END FROM unnest(p.polroles) x ORDER BY 1),
   pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid))
   FROM relations r JOIN pg_policy p ON p.polrelid=r.oid
  UNION ALL SELECT jsonb_build_array('trigger',r.nspname,r.relname,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid,false))
   FROM relations r JOIN pg_trigger t ON t.tgrelid=r.oid WHERE NOT t.tgisinternal
  UNION ALL SELECT jsonb_build_array('constraint',r.nspname,r.relname,c.conname,c.convalidated,pg_get_constraintdef(c.oid,false))
   FROM relations r JOIN pg_constraint c ON c.conrelid=r.oid
  UNION ALL SELECT jsonb_build_array('index',r.nspname,r.relname,i.indisvalid,i.indisready,pg_get_indexdef(i.indexrelid))
   FROM relations r JOIN pg_index i ON i.indrelid=r.oid
  UNION ALL SELECT jsonb_build_array('function',f.nspname,f.proname,pg_get_function_identity_arguments(f.oid),pg_get_userbyid(f.proowner),
   f.prokind,f.prosecdef,f.proleakproof,f.provolatile,f.proparallel,f.proconfig,
   CASE WHEN f.prokind IN ('f','p','w') THEN pg_get_functiondef(f.oid) END)
   FROM functions f
  UNION ALL SELECT jsonb_build_array('function_acl',f.nspname,f.proname,pg_get_function_identity_arguments(f.oid),pg_get_userbyid(a.grantor),CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,a.privilege_type,a.is_grantable)
   FROM functions f CROSS JOIN LATERAL aclexplode(CASE WHEN cardinality(coalesce(f.proacl,acldefault('f',f.proowner)))>0 THEN coalesce(f.proacl,acldefault('f',f.proowner)) END) a
  UNION ALL SELECT jsonb_build_array('role',rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls)
   FROM roles
  UNION ALL SELECT jsonb_build_array('membership',pg_get_userbyid(m.roleid),pg_get_userbyid(m.member),m.admin_option,m.inherit_option,m.set_option)
   FROM pg_auth_members m WHERE m.member IN (SELECT oid FROM roles) OR m.roleid IN (SELECT oid FROM roles)
  UNION ALL SELECT jsonb_build_array('schema',n.nspname,pg_get_userbyid(n.nspowner),pg_get_userbyid(a.grantor),CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,a.privilege_type,a.is_grantable)
   FROM pg_namespace n CROSS JOIN LATERAL aclexplode(CASE WHEN cardinality(coalesce(n.nspacl,acldefault('n',n.nspowner)))>0 THEN coalesce(n.nspacl,acldefault('n',n.nspowner)) END) a
   WHERE n.nspname IN ('public','private')
  UNION ALL SELECT jsonb_build_array('default_acl',pg_get_userbyid(d.defaclrole),coalesce(n.nspname,''),d.defaclobjtype,pg_get_userbyid(a.grantor),CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,a.privilege_type,a.is_grantable)
   FROM pg_default_acl d LEFT JOIN pg_namespace n ON n.oid=d.defaclnamespace
   CROSS JOIN LATERAL aclexplode(CASE WHEN cardinality(d.defaclacl)>0 THEN d.defaclacl END) a WHERE d.defaclnamespace=0 OR n.nspname IN ('public','private')
  UNION ALL SELECT jsonb_build_array('extension',e.extname,e.extversion,n.nspname,pg_get_userbyid(e.extowner)) FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace
 )
 SELECT encode(public.digest(convert_to(coalesce(string_agg(item::text,E'\n' ORDER BY item::text COLLATE "C"),''),'UTF8'),'sha256'),'hex') FROM entries
$fn$;
CREATE FUNCTION private.verify_security_catalog()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT revision=39 AND digest=private.security_catalog_digest() FROM private.security_catalog_baseline WHERE singleton),false)
$fn$;
REVOKE ALL ON FUNCTION private.security_catalog_digest(),private.verify_security_catalog() FROM PUBLIC,profitpilot_app;
GRANT EXECUTE ON FUNCTION private.verify_security_catalog() TO profitpilot_app;
INSERT INTO private.security_catalog_baseline(singleton,revision,digest) VALUES(true,39,private.security_catalog_digest());
COMMIT;

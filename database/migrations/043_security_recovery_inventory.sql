-- Offline authoritative recovery: export only bounded security metadata,
-- never emails, subject text, signing material, JWTs or file contents.
BEGIN;
DO $check$ BEGIN
 IF NOT private.verify_security_catalog() THEN RAISE EXCEPTION 'Prior security catalog does not verify'; END IF;
END $check$;

CREATE FUNCTION private.security_recovery_inventory()
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE inventory jsonb;
BEGIN
 SELECT jsonb_build_object(
  'tenants',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY id),'[]') FROM (SELECT id,status FROM public.tenants ORDER BY id LIMIT 100001) x),
  'users',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY id),'[]') FROM (SELECT id,status,encode(public.digest(convert_to(auth_subject,'UTF8'),'sha256'),'hex') AS subject_hash FROM public.users ORDER BY id LIMIT 100001) x),
  'memberships',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY tenant_id,user_id),'[]') FROM (SELECT tenant_id,user_id,role,status FROM public.tenant_memberships ORDER BY tenant_id,user_id LIMIT 100001) x),
  'cutoffs',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY user_id),'[]') FROM (SELECT user_id,revoked_through::text FROM private.identity_session_cutoffs ORDER BY user_id LIMIT 100001) x),
  'sessions',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY user_id,session_digest),'[]') FROM (SELECT user_id,session_digest FROM private.revoked_identity_sessions ORDER BY user_id,session_digest LIMIT 100001) x),
  'keys',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY key_id),'[]') FROM (SELECT key_id,active FROM private.tenant_context_keys ORDER BY key_id LIMIT 100001) x),
  'incidents',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY incident_id),'[]') FROM (SELECT incident_id,tenant_id,category,released_at IS NOT NULL AS released FROM private.tenant_emergency_incidents ORDER BY incident_id LIMIT 100001) x)
 ) INTO inventory;
 IF (SELECT sum(jsonb_array_length(value)) FROM jsonb_each(inventory))>100000 THEN
  RAISE EXCEPTION 'Security recovery inventory exceeds reviewed capacity' USING ERRCODE='54000';
 END IF;
 RETURN inventory;
END $fn$;
REVOKE ALL ON FUNCTION private.security_recovery_inventory() FROM PUBLIC,profitpilot_app;
GRANT EXECUTE ON FUNCTION private.security_recovery_inventory() TO profitpilot_recovery_reader;

CREATE OR REPLACE FUNCTION private.security_catalog_entries()
RETURNS SETOF jsonb LANGUAGE sql STABLE SET search_path=pg_catalog AS $fn$
 WITH relations AS (
  SELECT c.*,n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname IN ('public','private') AND c.relkind IN ('r','p','v','m','f','S')
 ), functions AS (
  SELECT p.*,n.nspname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
  WHERE n.nspname IN ('public','private') AND NOT EXISTS(
   SELECT 1 FROM pg_depend d WHERE d.classid='pg_proc'::regclass AND d.objid=p.oid AND d.deptype='e')
 ), roles AS (
  SELECT * FROM pg_roles WHERE rolname IN ('profitpilot_app','profitpilot_context_owner','profitpilot_scanner','profitpilot_identity_operator','profitpilot_audit_reader','profitpilot_recovery_reader','profitpilot_incident_operator','profitpilot_incident_recovery','profitpilot_security_reader')
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
  -- Internal constraint trigger names contain database-local OIDs.
  -- Compare their stable relationship, function, event and enabled state
  -- instead of the generated name. This survives logical backup restores.
  UNION ALL SELECT jsonb_build_array('constraint_trigger',r.nspname,r.relname,
   cn.nspname,cc.relname,c.conname,t.tgfoid::regprocedure::text,t.tgtype,t.tgenabled,t.tgdeferrable,t.tginitdeferred)
   FROM relations r JOIN pg_trigger t ON t.tgrelid=r.oid AND t.tgisinternal
   JOIN pg_constraint c ON c.oid=t.tgconstraint
   JOIN pg_class cc ON cc.oid=c.conrelid JOIN pg_namespace cn ON cn.oid=cc.relnamespace
  UNION ALL SELECT jsonb_build_array('other_internal_trigger',r.nspname,r.relname,t.tgfoid::regprocedure::text,t.tgtype,t.tgenabled,t.tgdeferrable,t.tginitdeferred)
   FROM relations r JOIN pg_trigger t ON t.tgrelid=r.oid AND t.tgisinternal AND t.tgconstraint=0
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
  UNION ALL SELECT jsonb_build_array('role',rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls,CASE WHEN rolname='profitpilot_context_owner' THEN rolcanlogin ELSE NULL END)
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
 SELECT item FROM entries
$fn$;




CREATE OR REPLACE FUNCTION private.verify_security_catalog()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT digest=private.security_catalog_digest() FROM private.security_catalog_baseline WHERE revision=43),false)
$fn$;
INSERT INTO private.security_catalog_baseline(singleton,revision,digest) VALUES(true,43,private.security_catalog_digest());
COMMIT;

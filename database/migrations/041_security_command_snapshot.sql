-- Read-only security operations snapshot. Never expose financial records,
-- identity details, session digests, keys, free-text refs or file payloads.
BEGIN;
DO $check$ BEGIN
 IF NOT private.verify_security_catalog() THEN RAISE EXCEPTION 'Prior security catalog does not verify'; END IF;
END $check$;
DO $role$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='profitpilot_security_reader') THEN
  CREATE ROLE profitpilot_security_reader NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
 END IF;
END $role$;
GRANT USAGE ON SCHEMA private TO profitpilot_security_reader;
REVOKE CREATE ON SCHEMA public,private FROM profitpilot_security_reader;
CREATE INDEX security_active_incidents_page_idx ON private.tenant_emergency_incidents(incident_id) WHERE released_at IS NULL;
CREATE INDEX security_actor_blocked_idx ON private.actor_request_security(blocked_until) WHERE blocked_until IS NOT NULL;
CREATE INDEX security_identity_events_time_idx ON private.identity_security_events(occurred_at);

CREATE FUNCTION private.security_command_snapshot(p_limit integer,p_after uuid)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE checked_at timestamptz:=statement_timestamp(); incidents jsonb; next_cursor uuid; counts jsonb; verified boolean;
BEGIN
 IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100 THEN
  RAISE EXCEPTION 'Invalid security report page limit' USING ERRCODE='22023';
 END IF;
 verified:=private.verify_security_catalog();
 IF verified IS DISTINCT FROM true THEN
  -- Do not expose other details through an unverified security schema.
  RETURN jsonb_build_object('schemaVersion',1,'observedAt',checked_at,'catalogVerified',false,
   'status','catalog_drift','counts',NULL,'activeIncidents',NULL,'nextCursor',NULL);
 END IF;
 WITH page AS (
  SELECT incident_id,tenant_id,category,activated_at
  FROM private.tenant_emergency_incidents
  WHERE released_at IS NULL AND (p_after IS NULL OR incident_id>p_after)
  ORDER BY incident_id LIMIT p_limit+1
 ), numbered AS (
  SELECT *,row_number() OVER(ORDER BY incident_id) AS n FROM page
 )
 SELECT coalesce(jsonb_agg(jsonb_build_object('incidentId',incident_id,'tenantId',tenant_id,'category',category,'activatedAt',activated_at) ORDER BY incident_id) FILTER(WHERE n<=p_limit),'[]'::jsonb),
  CASE WHEN count(*)>p_limit THEN (array_agg(incident_id ORDER BY incident_id))[p_limit] END
 INTO incidents,next_cursor FROM numbered;
 SELECT jsonb_build_object(
  'activeTenantIncidents',(SELECT count(*) FROM private.tenant_emergency_incidents WHERE released_at IS NULL),
  'temporarilyContainedActors',(SELECT count(*) FROM private.actor_request_security WHERE blocked_until>checked_at),
  'identitySecurityEvents24h',(SELECT count(*) FROM private.identity_security_events WHERE occurred_at>checked_at-interval '24 hours' AND occurred_at<=checked_at),
  'pendingOrRetryableScans',(SELECT count(*) FROM private.quarantined_files WHERE created_at>checked_at-interval '24 hours' AND attempts<3 AND scan_state IN ('pending','error')),
  'processingScans',(SELECT count(*) FROM private.quarantined_files WHERE scan_state='scanning' AND lease_until>=checked_at),
  'pendingOrProcessingPromotions',(SELECT count(*) FROM private.quarantine_promotions WHERE state IN ('approved','processing')),
  'failedPromotions',(SELECT count(*) FROM private.quarantine_promotions WHERE state='failed')
 ) INTO counts;
 RETURN jsonb_build_object('schemaVersion',1,'observedAt',checked_at,'catalogVerified',true,
  'status',CASE WHEN (counts->>'activeTenantIncidents')::bigint>0 OR (counts->>'temporarilyContainedActors')::bigint>0 THEN 'containment_active' ELSE 'no_active_containment' END,
  'counts',counts,'activeIncidents',incidents,'nextCursor',next_cursor);
END $fn$;
REVOKE ALL ON FUNCTION private.security_command_snapshot(integer,uuid) FROM PUBLIC,profitpilot_app,profitpilot_security_reader;
GRANT EXECUTE ON FUNCTION private.security_command_snapshot(integer,uuid) TO profitpilot_security_reader;

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
 SELECT item FROM entries
$fn$;


CREATE OR REPLACE FUNCTION private.verify_security_catalog()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT digest=private.security_catalog_digest() FROM private.security_catalog_baseline WHERE revision=41),false)
$fn$;
INSERT INTO private.security_catalog_baseline(singleton,revision,digest) VALUES(true,41,private.security_catalog_digest());
COMMIT;

-- This exact privilege inventory is intentionally strict. New runtime or
-- worker capabilities must be reviewed here as well as in their migration.
DO $audit$
DECLARE role_name text; p record; t record; privilege text; allowed boolean; expected text[];
BEGIN
 FOREACH role_name IN ARRAY ARRAY['profitpilot_app','profitpilot_scanner','profitpilot_identity_operator','profitpilot_audit_reader'] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=role_name AND NOT (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication))
   OR EXISTS(SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member WHERE r.rolname=role_name)
   OR has_schema_privilege(role_name,'public','CREATE') OR has_schema_privilege(role_name,'private','CREATE')
  THEN RAISE EXCEPTION 'Unsafe privileges for role %',role_name; END IF;
  CASE role_name
   WHEN 'profitpilot_app' THEN expected:=ARRAY[
    'private.current_tenant_id()','private.current_actor_role()',
    'private.import_reference_safe(text,integer,boolean)','private.invoice_import_payload_safe(jsonb)',
    'private.export_calculation_summary(uuid,uuid,text)',
    'private.quarantine_invoice_file(uuid,uuid,text,text,bytea,bytea,bytea)',
    'private.quarantine_status(uuid,uuid)','private.session_authorized(text,bigint,bigint,text,bigint,text,text,text)',
    'private.approve_quarantine_promotion(uuid,uuid)',
    'private.site_payroll_summary(uuid,uuid,date,date)','private.read_calculation_summary(uuid,uuid)',
    'public.consume_api_rate_limit(text)','public.purge_api_rate_limits()'];
   WHEN 'profitpilot_scanner' THEN expected:=ARRAY[
    'private.claim_quarantine_scan()','private.expire_quarantine_bytes()',
    'private.finish_quarantine_manifest(uuid,uuid,uuid,text,text,jsonb)',
    'private.claim_quarantine_promotion()','private.finish_quarantine_promotion(uuid,uuid,uuid,jsonb)'];
   WHEN 'profitpilot_identity_operator' THEN expected:=ARRAY[
    'private.provision_verified_identity(text,text,text)','private.administer_membership(uuid,uuid,text,text,text)'];
   WHEN 'profitpilot_audit_reader' THEN expected:=ARRAY[
    'private.audit_checkpoint_heads()','private.audit_checkpoint_matches(uuid,bigint,text)'];
  END CASE;
  FOREACH privilege IN ARRAY expected LOOP
   IF to_regprocedure(privilege) IS NULL OR NOT has_function_privilege(role_name,to_regprocedure(privilege),'EXECUTE') THEN
    RAISE EXCEPTION 'Missing reviewed function permission: % / %',role_name,privilege;
   END IF;
  END LOOP;
  FOR p IN SELECT f.oid,n.nspname,f.proname FROM pg_proc f JOIN pg_namespace n ON n.oid=f.pronamespace
    WHERE n.nspname='private' OR (n.nspname='public' AND f.prosecdef)
  LOOP
   SELECT EXISTS(SELECT 1 FROM unnest(expected) a(sig) WHERE to_regprocedure(a.sig)=p.oid) INTO allowed;
   IF has_function_privilege(role_name,p.oid,'EXECUTE') IS DISTINCT FROM allowed THEN
    RAISE EXCEPTION 'Unexpected function permission: % / %.%',role_name,p.nspname,p.proname;
   END IF;
  END LOOP;
  FOR t IN SELECT c.oid,c.relname,n.nspname,c.relkind,c.relowner FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname IN ('public','private') AND c.relkind IN ('r','p','v','m','f','S')
  LOOP
   IF t.relowner=(SELECT oid FROM pg_roles WHERE rolname=role_name) THEN
    RAISE EXCEPTION 'Restricted role owns application object: % / %.%',role_name,t.nspname,t.relname;
   END IF;
   -- Workers never access table or sequence data directly. API can use only
   -- reviewed public relations; private tables/sequences and rate counters
   -- remain inaccessible even through column-level grants.
   IF role_name<>'profitpilot_app' OR t.nspname='private' OR t.relname IN ('api_rate_limits','payroll_source_rows','allocation_lines') THEN
    IF t.relkind='S' THEN
     IF has_sequence_privilege(role_name,t.oid,'USAGE,SELECT,UPDATE') THEN RAISE EXCEPTION 'Unexpected direct sequence privilege: % / %.%',role_name,t.nspname,t.relname; END IF;
    ELSE
     IF has_table_privilege(role_name,t.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
     OR has_any_column_privilege(role_name,t.oid,'SELECT,INSERT,UPDATE,REFERENCES') THEN
      RAISE EXCEPTION 'Unexpected direct data privilege: % / %.%',role_name,t.nspname,t.relname;
     END IF;
    END IF;
   END IF;
  END LOOP;
 END LOOP;
 IF has_column_privilege('profitpilot_app','public.calculation_runs','inputs','SELECT') OR has_column_privilege('profitpilot_app','public.calculation_runs','outputs','SELECT') THEN RAISE EXCEPTION 'Runtime can read unminimized calculation JSON'; END IF;
 IF EXISTS(
  SELECT 1 FROM pg_proc f JOIN pg_namespace n ON n.oid=f.pronamespace
  CROSS JOIN LATERAL aclexplode(coalesce(f.proacl,acldefault('f',f.proowner))) a
  WHERE n.nspname='private' AND a.grantee=0 AND a.privilege_type='EXECUTE'
 ) THEN RAISE EXCEPTION 'PUBLIC can execute private functions'; END IF;
 RAISE NOTICE 'Private function and worker privilege inventory passed';
END $audit$;

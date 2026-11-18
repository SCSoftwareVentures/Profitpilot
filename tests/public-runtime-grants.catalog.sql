-- Exhaustive effective table, sequence and column permissions for the API role.
-- Review changes explicitly alongside every schema or capability change.
DO $runtime_grants$
DECLARE
 r record; col record; action text; expected boolean; role_name text:='profitpilot_app';
 read_tables text[]:=ARRAY['tenants','users','tenant_memberships','businesses','sites','contracts','contract_versions','import_batches','raw_import_rows','mapping_decisions','payroll_pools','allocation_runs','invoices','invoice_lines','match_reviews','variations','audit_events'];
 insert_tables text[]:=ARRAY['import_batches','raw_import_rows','mapping_decisions','calculation_runs'];
 calc_cols text[]:=ARRAY['id','tenant_id','contract_id','site_id','period_start','period_end','formula_version','completeness','created_at','created_by'];
BEGIN
 FOR r IN SELECT c.oid,c.relname,c.relkind FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','f','S')
 LOOP
  IF r.relkind='S' THEN
   IF has_sequence_privilege(role_name,r.oid,'USAGE,SELECT,UPDATE') THEN RAISE EXCEPTION 'Unexpected public sequence privilege: %',r.relname; END IF;
   CONTINUE;
  END IF;
  FOREACH action IN ARRAY ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER'] LOOP
   expected:=(action='SELECT' AND r.relname=ANY(read_tables)) OR (action='INSERT' AND r.relname=ANY(insert_tables));
   IF has_table_privilege(role_name,r.oid,action) IS DISTINCT FROM expected THEN
    RAISE EXCEPTION 'Unexpected public table privilege: % / %',r.relname,action;
   END IF;
   IF has_table_privilege(role_name,r.oid,action||' WITH GRANT OPTION') THEN
    RAISE EXCEPTION 'Unapproved public table grant option: % / %',r.relname,action;
   END IF;
  END LOOP;
  FOR col IN SELECT attnum,attname FROM pg_attribute WHERE attrelid=r.oid AND attnum>0 AND NOT attisdropped LOOP
   FOREACH action IN ARRAY ARRAY['SELECT','INSERT','UPDATE','REFERENCES'] LOOP
    expected:=CASE action
     WHEN 'SELECT' THEN r.relname=ANY(read_tables) OR (r.relname='calculation_runs' AND col.attname=ANY(calc_cols))
     WHEN 'INSERT' THEN r.relname=ANY(insert_tables)
     WHEN 'UPDATE' THEN
      (r.relname='import_batches' AND col.attname='status') OR
      (r.relname='mapping_decisions' AND col.attname IN ('decision','reason')) OR
      (r.relname='match_reviews' AND col.attname IN ('decision','reviewer_id','reviewed_at'))
     ELSE false END;
    IF has_column_privilege(role_name,r.oid,col.attnum,action) IS DISTINCT FROM expected THEN
     RAISE EXCEPTION 'Unexpected public column privilege: %.% / %',r.relname,col.attname,action;
    END IF;
    IF has_column_privilege(role_name,r.oid,col.attnum,action||' WITH GRANT OPTION') THEN
     RAISE EXCEPTION 'Unapproved public column grant option: %.% / %',r.relname,col.attname,action;
    END IF;
   END LOOP;
  END LOOP;
 END LOOP;
 IF EXISTS(
 SELECT 1 FROM pg_default_acl d CROSS JOIN LATERAL aclexplode(d.defaclacl) a
 WHERE d.defaclobjtype IN ('r','S') AND
 (d.defaclnamespace=0 OR d.defaclnamespace='public'::regnamespace)
 AND a.grantee IN (0,(SELECT oid FROM pg_roles WHERE rolname=role_name))
 ) THEN RAISE EXCEPTION 'Unapproved default public relation grant'; END IF;
 RAISE NOTICE 'Exact public API table, sequence and column privilege inventory passed';
END $runtime_grants$;

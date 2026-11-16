-- Exhaustive catalog-driven tenant boundary audit.
-- Run as a migration administrator after every migration; fails closed on omissions.
DO $$
DECLARE
  r record;
  tenant_att smallint;
  target_att smallint;
  fk record;
  has_tenant boolean;
  has_target_tenant boolean;
  checked integer := 0;
BEGIN
  FOR r IN
    SELECT c.oid, n.nspname, c.relname, c.relrowsecurity, c.relforcerowsecurity
    FROM pg_class c
    JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND c.relkind IN ('r','p')
      AND (c.relname IN ('tenants','users') OR EXISTS (
        SELECT 1 FROM pg_attribute a
        WHERE a.attrelid=c.oid AND a.attname='tenant_id'
          AND a.attnum>0 AND NOT a.attisdropped
      ))
    ORDER BY c.relname
  LOOP
    checked := checked + 1;
    IF NOT r.relrowsecurity OR NOT r.relforcerowsecurity THEN
      RAISE EXCEPTION 'RLS must be enabled and forced on %.%',r.nspname,r.relname;
    END IF;
    IF r.relname='users' THEN
      IF NOT EXISTS (
        SELECT 1 FROM pg_policies p
        WHERE p.schemaname=r.nspname AND p.tablename=r.relname
          AND p.policyname='users_signed_subject_only'
          AND position('auth_subject' in coalesce(p.qual,''))>0
          AND position('private.current_tenant_id' in coalesce(p.qual,''))>0
      ) THEN RAISE EXCEPTION 'Missing self-only signed-subject policy on users'; END IF;
    ELSE
      IF NOT EXISTS (
        SELECT 1 FROM pg_policies p
        WHERE p.schemaname=r.nspname AND p.tablename=r.relname
          AND p.policyname='tenant_isolation'
          AND position('private.current_tenant_id' in coalesce(p.qual,''))>0
          AND position('private.current_tenant_id' in coalesce(p.with_check,''))>0
      ) THEN RAISE EXCEPTION 'Missing tenant USING/WITH CHECK policy on %.%',r.nspname,r.relname; END IF;
    END IF;
  END LOOP;
  IF checked < 2 THEN RAISE EXCEPTION 'Unexpectedly few protected tables: %',checked; END IF;

  -- Every pair of tenant-owned tables connected by foreign keys must have
  -- at least one composite FK carrying tenant_id on both sides. Some legacy
  -- single-column FKs coexist with the composite guard and are not sufficient alone.
  FOR fk IN
    SELECT DISTINCT src.oid AS source_oid, src.relname AS source_table,
                    dst.oid AS target_oid, dst.relname AS target_table
    FROM pg_constraint con
    JOIN pg_class src ON src.oid=con.conrelid
    JOIN pg_namespace sn ON sn.oid=src.relnamespace
    JOIN pg_class dst ON dst.oid=con.confrelid
    JOIN pg_namespace dn ON dn.oid=dst.relnamespace
    WHERE con.contype='f' AND sn.nspname='public' AND dn.nspname='public'
      AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid=src.oid AND a.attname='tenant_id' AND a.attnum>0 AND NOT a.attisdropped)
      AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid=dst.oid AND a.attname='tenant_id' AND a.attnum>0 AND NOT a.attisdropped)
  LOOP
    SELECT attnum INTO tenant_att FROM pg_attribute WHERE attrelid=fk.source_oid AND attname='tenant_id' AND NOT attisdropped;
    SELECT attnum INTO target_att FROM pg_attribute WHERE attrelid=fk.target_oid AND attname='tenant_id' AND NOT attisdropped;
    IF NOT EXISTS (
      SELECT 1 FROM pg_constraint con
      WHERE con.contype='f' AND con.conrelid=fk.source_oid AND con.confrelid=fk.target_oid
        AND tenant_att=ANY(con.conkey) AND target_att=ANY(con.confkey)
    ) THEN
      RAISE EXCEPTION 'Tenant-scoped relationship %.% has no composite tenant_id foreign key',
        fk.source_table,fk.target_table;
    END IF;
  END LOOP;
  IF has_table_privilege('profitpilot_app','public.tenants','INSERT')
     OR has_table_privilege('profitpilot_app','public.tenants','UPDATE')
     OR has_table_privilege('profitpilot_app','public.tenants','DELETE')
     OR has_table_privilege('profitpilot_app','public.users','INSERT')
     OR has_table_privilege('profitpilot_app','public.users','UPDATE')
     OR has_table_privilege('profitpilot_app','public.users','DELETE')
     OR has_table_privilege('profitpilot_app','public.tenant_memberships','INSERT')
     OR has_table_privilege('profitpilot_app','public.tenant_memberships','UPDATE')
     OR has_table_privilege('profitpilot_app','public.tenant_memberships','DELETE')
  THEN RAISE EXCEPTION 'Runtime role has forbidden identity, tenant or membership write privileges'; END IF;
  IF has_table_privilege('profitpilot_app','public.import_batches','DELETE')
     OR has_table_privilege('profitpilot_app','public.raw_import_rows','DELETE')
     OR has_table_privilege('profitpilot_app','public.mapping_decisions','DELETE')
     OR has_table_privilege('profitpilot_app','public.match_reviews','DELETE')
     OR has_table_privilege('profitpilot_app','public.calculation_runs','DELETE')
     OR has_table_privilege('profitpilot_app','public.audit_events','DELETE')
  THEN RAISE EXCEPTION 'Runtime role has an unapproved destructive delete privilege'; END IF;
  RAISE NOTICE 'Tenant catalog audit passed: % tenant-scoped/root tables checked; tenant-to-tenant foreign keys inspected.',checked;
END $$;

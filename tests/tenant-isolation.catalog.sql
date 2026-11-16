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
      AND (c.relname='tenants' OR EXISTS (
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

  -- Every FK between two tenant-owned tables must carry tenant_id on both
  -- sides, preventing a valid row ID from another tenant being attached.
  FOR fk IN
    SELECT con.conname, src.relname AS source_table, dst.relname AS target_table,
           con.conrelid, con.confrelid, con.conkey, con.confkey
    FROM pg_constraint con
    JOIN pg_class src ON src.oid=con.conrelid
    JOIN pg_namespace sn ON sn.oid=src.relnamespace
    JOIN pg_class dst ON dst.oid=con.confrelid
    JOIN pg_namespace dn ON dn.oid=dst.relnamespace
    WHERE con.contype='f' AND sn.nspname='public' AND dn.nspname='public'
      AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid=src.oid AND a.attname='tenant_id' AND a.attnum>0 AND NOT a.attisdropped)
      AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid=dst.oid AND a.attname='tenant_id' AND a.attnum>0 AND NOT a.attisdropped)
  LOOP
    SELECT attnum INTO tenant_att FROM pg_attribute WHERE attrelid=fk.conrelid AND attname='tenant_id' AND NOT attisdropped;
    SELECT attnum INTO target_att FROM pg_attribute WHERE attrelid=fk.confrelid AND attname='tenant_id' AND NOT attisdropped;
    IF NOT tenant_att=ANY(fk.conkey) OR NOT target_att=ANY(fk.confkey) THEN
      RAISE EXCEPTION 'Cross-tenant-capable FK %.% -> %.% (%): tenant_id missing from composite FK',
        fk.source_table,fk.conname,fk.target_table,fk.conname,fk.conname;
    END IF;
  END LOOP;
  RAISE NOTICE 'Tenant catalog audit passed: % tenant-scoped/root tables checked; tenant-to-tenant foreign keys inspected.',checked;
END $$;

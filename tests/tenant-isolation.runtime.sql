-- Run as profitpilot_app after integration fixtures have been created.
-- Every tenant-scoped table must return zero rows without a valid signed context.
DO $$
DECLARE r record; n bigint; checked integer:=0;
BEGIN
 FOR r IN
  SELECT c.relname
  FROM pg_class c JOIN pg_namespace ns ON ns.oid=c.relnamespace
  WHERE ns.nspname='public' AND c.relkind IN ('r','p')
   AND (c.relname IN ('tenants','users') OR EXISTS (
    SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attname='tenant_id' AND a.attnum>0 AND NOT a.attisdropped
   ))
  ORDER BY c.relname
 LOOP
  EXECUTE format('SELECT count(*) FROM public.%I',r.relname) INTO n;
  IF n<>0 THEN RAISE EXCEPTION 'Unscoped runtime role can read % row(s) from public.%',n,r.relname; END IF;
  checked:=checked+1;
 END LOOP;
 IF checked<2 THEN RAISE EXCEPTION 'Unexpectedly few protected tables checked: %',checked; END IF;
 RAISE NOTICE 'Unscoped runtime isolation passed for % protected tables.',checked;
END $$;

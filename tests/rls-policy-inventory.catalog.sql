-- CI-only exact policy inventory. Reference policies are restrictive and
-- created/dropped inside one transaction; never run this DDL audit on a
-- live serving database. Any mismatch aborts the transaction.
DO $policy_audit$
DECLARE
 t text; expected_count integer; found_count integer; p record; model record;
 role_oid oid; expression text; command text; target_roles oid[];
 known_tables text[]:=ARRAY['tenants','users','tenant_memberships','businesses','sites','contracts','contract_versions','import_batches','raw_import_rows','mapping_decisions','payroll_pools','allocation_runs','allocation_lines','payroll_source_rows','invoices','invoice_lines','match_reviews','variations','calculation_runs','audit_events'];
BEGIN
 SELECT oid INTO STRICT role_oid FROM pg_roles WHERE rolname='profitpilot_app';
 IF EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','f')
 AND NOT(c.relname=ANY(known_tables) OR c.relname='api_rate_limits')) THEN
  RAISE EXCEPTION 'Unreviewed public relation';
 END IF;
 FOREACH t IN ARRAY known_tables LOOP
  IF to_regclass('public.'||t) IS NULL THEN RAISE EXCEPTION 'Missing reviewed tenant relation: %',t; END IF;
  expected_count:=CASE WHEN t IN ('match_reviews','raw_import_rows') THEN 2 ELSE 1 END;
  SELECT count(*) INTO found_count FROM pg_policy WHERE polrelid=to_regclass('public.'||t);
  IF found_count<>expected_count THEN RAISE EXCEPTION 'Unexpected policy inventory: %',t; END IF;
  IF t='users' THEN
   expression:='auth_subject = nullif(current_setting(''app.tenant_subject'',true),'''') AND private.current_tenant_id() IS NOT NULL';
   SELECT * INTO p FROM pg_policy WHERE polrelid='public.users'::regclass AND polname='users_signed_subject_only';
   EXECUTE format('CREATE POLICY pp_acceptance_reference ON public.%I AS RESTRICTIVE USING (%s) WITH CHECK (false)',t,expression);
  ELSE
   expression:=CASE WHEN t='tenants' THEN 'id = private.current_tenant_id()' ELSE 'tenant_id = private.current_tenant_id()' END;
   SELECT * INTO p FROM pg_policy WHERE polrelid=to_regclass('public.'||t) AND polname='tenant_isolation';
   EXECUTE format('CREATE POLICY pp_acceptance_reference ON public.%I AS RESTRICTIVE USING (%s) WITH CHECK (%s)',t,expression,expression);
  END IF;
  SELECT * INTO STRICT model FROM pg_policy WHERE polrelid=to_regclass('public.'||t) AND polname='pp_acceptance_reference';
  IF p.oid IS NULL OR p.polpermissive IS DISTINCT FROM true OR p.polcmd IS DISTINCT FROM '*'::"char" OR p.polroles IS DISTINCT FROM ARRAY[0::oid]
   OR pg_get_expr(p.polqual,p.polrelid) IS DISTINCT FROM pg_get_expr(model.polqual,model.polrelid)
   OR pg_get_expr(p.polwithcheck,p.polrelid) IS DISTINCT FROM pg_get_expr(model.polwithcheck,model.polrelid)
  THEN RAISE EXCEPTION 'Tenant policy definition differs from reviewed boundary: %',t; END IF;
  EXECUTE format('DROP POLICY pp_acceptance_reference ON public.%I',t);
  IF t='match_reviews' THEN
   SELECT * INTO p FROM pg_policy WHERE polrelid=to_regclass('public.'||t) AND polname='match_reviews_actor_update';
   CREATE POLICY pp_acceptance_reference ON public.match_reviews AS RESTRICTIVE FOR UPDATE TO profitpilot_app
   USING (private.current_actor_role() IN ('owner','admin','reviewer'))
   WITH CHECK (private.current_actor_role() IN ('owner','admin','reviewer'));
   command:='w';
  ELSIF t='raw_import_rows' THEN
   SELECT * INTO p FROM pg_policy WHERE polrelid=to_regclass('public.'||t) AND polname='raw_import_rows_invoice_read';
   CREATE POLICY pp_acceptance_reference ON public.raw_import_rows AS RESTRICTIVE FOR SELECT TO profitpilot_app
   USING (EXISTS(SELECT 1 FROM public.import_batches b WHERE b.tenant_id=raw_import_rows.tenant_id AND b.id=raw_import_rows.batch_id AND b.source_type IN ('customer_invoice','supplier_invoice')));
   command:='r';
  ELSE CONTINUE;
  END IF;
  SELECT * INTO STRICT model FROM pg_policy WHERE polrelid=to_regclass('public.'||t) AND polname='pp_acceptance_reference';
  IF p.oid IS NULL OR p.polpermissive IS DISTINCT FROM false OR p.polcmd::text IS DISTINCT FROM command OR p.polroles IS DISTINCT FROM ARRAY[role_oid]
   OR pg_get_expr(p.polqual,p.polrelid) IS DISTINCT FROM pg_get_expr(model.polqual,model.polrelid)
   OR pg_get_expr(p.polwithcheck,p.polrelid) IS DISTINCT FROM pg_get_expr(model.polwithcheck,model.polrelid)
  THEN RAISE EXCEPTION 'Restrictive policy definition differs from reviewed boundary: %',t; END IF;
  EXECUTE format('DROP POLICY pp_acceptance_reference ON public.%I',t);
 END LOOP;
 IF EXISTS(SELECT 1 FROM pg_policy WHERE polrelid='public.api_rate_limits'::regclass) THEN RAISE EXCEPTION 'Unexpected rate counter policy'; END IF;
 RAISE NOTICE 'Exact tenant policy and public relation inventory passed';
END $policy_audit$;

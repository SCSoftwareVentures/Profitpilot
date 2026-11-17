-- Prevent arbitrary or prohibited data entering the current invoice-only ingestion path.
-- Conservative screening, not comprehensive DLP. Admin/fixture imports remain separately controlled.
BEGIN;

CREATE FUNCTION private.import_reference_safe(p_value text,p_max integer,p_filename boolean DEFAULT false)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE v text;
BEGIN
 IF p_value IS NULL OR char_length(p_value)>p_max THEN RETURN false; END IF;
 v:=normalize(p_value,NFKC);
 -- Permit bounded business references, not arbitrary notes, contact details or paths.
 IF v !~ '^[[:alnum:] ._:/&''()-]*$' OR (p_filename AND (strpos(v,'/')>0 OR strpos(v,':')>0 OR v IN ('.','..'))) THEN RETURN false; END IF;
 IF v ~* '(^|[^[:alnum:]])(tfn|tax[ _-]*file|medicare|passport|bank[ _-]*account|bsb|card[ _-]*number|credit[ _-]*card|cvv|cvc|password|access[ _-]*code|payslip)([^[:alnum:]]|$)' THEN RETURN false; END IF;
 -- Deny digit strings resembling TFNs, payment cards, phone or account numbers.
 -- Deliberately conservative: some valid external numeric identifiers need opaque aliases.
 IF v ~ '[0-9]([ .:/()-]*[0-9]){7,}' THEN RETURN false; END IF;
 RETURN true;
END $$;
REVOKE ALL ON FUNCTION private.import_reference_safe(text,integer,boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.import_reference_safe(text,integer,boolean) TO profitpilot_app;

CREATE FUNCTION private.invoice_import_payload_safe(p_payload jsonb)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE f record; v text;
BEGIN
 IF p_payload IS NULL OR jsonb_typeof(p_payload)<>'object' THEN RETURN false; END IF;
 FOR f IN SELECT key,value FROM jsonb_each(p_payload) LOOP
  IF jsonb_typeof(f.value)<>'string' THEN RETURN false; END IF;
  v:=f.value #>> '{}';
  CASE f.key
   WHEN 'invoice_id' THEN IF NOT private.import_reference_safe(v,128,false) THEN RETURN false; END IF;
   WHEN 'site' THEN IF NOT private.import_reference_safe(v,160,false) THEN RETURN false; END IF;
   WHEN 'customer_id','contract_id','site_id' THEN
    IF v !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND NOT private.import_reference_safe(v,128,false) THEN RETURN false; END IF;
   WHEN 'date','service_period_start','service_period_end' THEN
    IF v !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' AND NOT private.import_reference_safe(v,32,false) THEN RETURN false; END IF;
   WHEN 'amount' THEN IF v !~ '^([+-]?[0-9]{1,12}([.][0-9]{1,2})?)?$' THEN RETURN false; END IF;
   WHEN 'currency' THEN IF v !~ '^([A-Z]{3})?$' THEN RETURN false; END IF;
   WHEN 'tax_basis' THEN IF v NOT IN ('','gst_inclusive','gst_exclusive','no_gst','unknown') THEN RETURN false; END IF;
   ELSE RETURN false;
  END CASE;
 END LOOP;
 RETURN true;
END $$;
REVOKE ALL ON FUNCTION private.invoice_import_payload_safe(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.invoice_import_payload_safe(jsonb) TO profitpilot_app;

CREATE FUNCTION private.guard_runtime_invoice_payload()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE source_kind text; batch_status text;
BEGIN
 IF current_user<>'profitpilot_app' THEN RETURN NEW; END IF;
 -- Do not change cross-tenant RLS denial behavior or expose other tenants.
 IF private.current_tenant_id() IS DISTINCT FROM NEW.tenant_id THEN RETURN NEW; END IF;
 IF private.current_actor_role() NOT IN ('owner','admin','analyst') OR private.current_actor_role() IS NULL THEN
   RAISE EXCEPTION 'Invoice import requires an authorized tenant role' USING ERRCODE='42501';
 END IF;
 SELECT source_type,status INTO source_kind,batch_status FROM public.import_batches
   WHERE id=NEW.batch_id AND tenant_id=NEW.tenant_id FOR UPDATE;
 IF source_kind IS NULL OR source_kind NOT IN ('customer_invoice','supplier_invoice') OR batch_status NOT IN ('registered','review','validating') THEN
   RAISE EXCEPTION 'Invoice ingestion is not enabled for this source or state' USING ERRCODE='23514';
 END IF;
 IF NOT private.invoice_import_payload_safe(NEW.payload) THEN
   RAISE EXCEPTION 'Invoice payload violates the import privacy boundary' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION private.guard_runtime_invoice_payload() FROM PUBLIC;
CREATE TRIGGER raw_import_rows_privacy_guard BEFORE INSERT ON public.raw_import_rows
 FOR EACH ROW EXECUTE FUNCTION private.guard_runtime_invoice_payload();

CREATE FUNCTION private.guard_runtime_import_metadata()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF current_user<>'profitpilot_app' OR private.current_tenant_id() IS DISTINCT FROM NEW.tenant_id THEN RETURN NEW; END IF;
 IF TG_OP='UPDATE' AND ROW(NEW.file_name,NEW.permission_ref,NEW.source_type,NEW.file_sha256,NEW.created_by,NEW.tenant_id,NEW.id,NEW.source_period_start,NEW.source_period_end,NEW.created_at)
  IS DISTINCT FROM ROW(OLD.file_name,OLD.permission_ref,OLD.source_type,OLD.file_sha256,OLD.created_by,OLD.tenant_id,OLD.id,OLD.source_period_start,OLD.source_period_end,OLD.created_at) THEN
   RAISE EXCEPTION 'Import source metadata is immutable' USING ERRCODE='23514';
 END IF;
 IF TG_OP='INSERT' AND (NOT private.import_reference_safe(NEW.file_name,255,true) OR NOT private.import_reference_safe(NEW.permission_ref,256,false) OR btrim(NEW.file_name)='' OR btrim(NEW.permission_ref)='') THEN
   RAISE EXCEPTION 'Import metadata violates the import privacy boundary' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION private.guard_runtime_import_metadata() FROM PUBLIC;
CREATE TRIGGER import_batches_privacy_guard BEFORE INSERT OR UPDATE ON public.import_batches
 FOR EACH ROW EXECUTE FUNCTION private.guard_runtime_import_metadata();
COMMIT;

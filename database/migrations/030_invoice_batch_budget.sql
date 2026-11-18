-- Bound an invoice batch even when the ordinary API role writes directly.
-- Existing duplicate rows can be retried at capacity without adding data.
BEGIN;
CREATE FUNCTION private.enforce_invoice_batch_budget()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE kind text;
BEGIN
 IF session_user='profitpilot_app' AND private.current_tenant_id() IS DISTINCT FROM NEW.tenant_id THEN RETURN NEW; END IF;
 SELECT source_type INTO kind FROM public.import_batches WHERE tenant_id=NEW.tenant_id AND id=NEW.batch_id FOR UPDATE;
 IF kind NOT IN ('customer_invoice','supplier_invoice') OR kind IS NULL THEN RETURN NEW; END IF;
 IF NEW.row_number NOT BETWEEN 1 AND 1000000000 THEN
  RAISE EXCEPTION 'Invoice row number outside approved bounds' USING ERRCODE='23514';
 END IF;
 IF EXISTS(SELECT 1 FROM public.raw_import_rows WHERE tenant_id=NEW.tenant_id AND batch_id=NEW.batch_id AND row_number=NEW.row_number) THEN RETURN NEW; END IF;
 IF (SELECT count(*) FROM (SELECT 1 FROM public.raw_import_rows WHERE tenant_id=NEW.tenant_id AND batch_id=NEW.batch_id LIMIT 1000) AS bounded)>=1000 THEN
  RAISE EXCEPTION 'Invoice batch capacity exceeded' USING ERRCODE='54000';
 END IF;
 RETURN NEW;
END $fn$;
REVOKE ALL ON FUNCTION private.enforce_invoice_batch_budget() FROM PUBLIC,profitpilot_app;
CREATE TRIGGER invoice_batch_budget BEFORE INSERT ON public.raw_import_rows
 FOR EACH ROW EXECUTE FUNCTION private.enforce_invoice_batch_budget();
COMMIT;

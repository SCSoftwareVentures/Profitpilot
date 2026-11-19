-- Monotonic per-invoice-batch insert budget, including direct SQL and scanner
-- promotion. AFTER INSERT counts only actual inserts, not idempotent retries.
-- Atomic counter updates also serialize writers under repeatable-read.
BEGIN;
LOCK TABLE public.raw_import_rows IN SHARE ROW EXCLUSIVE MODE;
CREATE TABLE private.invoice_batch_row_budget(
 tenant_id uuid NOT NULL,
 batch_id uuid NOT NULL,
 used_rows bigint NOT NULL CHECK(used_rows>0),
 PRIMARY KEY(tenant_id,batch_id),
 FOREIGN KEY(tenant_id,batch_id) REFERENCES public.import_batches(tenant_id,id) ON DELETE CASCADE
);
REVOKE ALL ON private.invoice_batch_row_budget FROM PUBLIC,profitpilot_app,profitpilot_scanner;
INSERT INTO private.invoice_batch_row_budget(tenant_id,batch_id,used_rows)
 SELECT r.tenant_id,r.batch_id,count(*) FROM public.raw_import_rows r
 JOIN public.import_batches b ON b.tenant_id=r.tenant_id AND b.id=r.batch_id
 WHERE b.source_type IN ('customer_invoice','supplier_invoice') GROUP BY r.tenant_id,r.batch_id;

CREATE FUNCTION private.enforce_invoice_batch_budget()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE kind text;
BEGIN
 SELECT source_type INTO kind FROM public.import_batches WHERE tenant_id=NEW.tenant_id AND id=NEW.batch_id;
 IF kind NOT IN ('customer_invoice','supplier_invoice') OR kind IS NULL THEN RETURN NEW; END IF;
 IF NEW.row_number NOT BETWEEN 1 AND 1000000000 THEN
  RAISE EXCEPTION 'Invoice row number outside approved bounds' USING ERRCODE='23514';
 END IF;
 INSERT INTO private.invoice_batch_row_budget AS budget(tenant_id,batch_id,used_rows)
 VALUES(NEW.tenant_id,NEW.batch_id,1)
 ON CONFLICT(tenant_id,batch_id) DO UPDATE SET used_rows=budget.used_rows+1
 WHERE budget.used_rows<1000;
 IF NOT FOUND THEN RAISE EXCEPTION 'Invoice batch capacity exceeded' USING ERRCODE='54000'; END IF;
 RETURN NEW;
END $fn$;
REVOKE ALL ON FUNCTION private.enforce_invoice_batch_budget() FROM PUBLIC,profitpilot_app;
CREATE TRIGGER invoice_batch_budget AFTER INSERT ON public.raw_import_rows
 FOR EACH ROW EXECUTE FUNCTION private.enforce_invoice_batch_budget();
COMMIT;

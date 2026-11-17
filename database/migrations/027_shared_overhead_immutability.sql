-- Protect confirmed shared overhead source evidence from silent restatement.
BEGIN;
CREATE FUNCTION private.protect_shared_overhead_match()
RETURNS trigger LANGUAGE plpgsql
SET search_path=pg_catalog,public,private
AS $f$
BEGIN
 IF OLD.decision='confirmed' AND OLD.evidence #>> '{deliveryExpenseReview,costCategory}'='shared_overhead' THEN
  RAISE EXCEPTION 'Confirmed shared overhead match is immutable' USING ERRCODE='55000';
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END
$f$;
CREATE TRIGGER shared_overhead_match_immutable BEFORE UPDATE OR DELETE ON public.match_reviews
 FOR EACH ROW EXECUTE FUNCTION private.protect_shared_overhead_match();

CREATE FUNCTION private.protect_shared_overhead_line()
RETURNS trigger LANGUAGE plpgsql
SET search_path=pg_catalog,public,private
AS $f$
BEGIN
 IF EXISTS(SELECT 1 FROM public.match_reviews m WHERE m.tenant_id=OLD.tenant_id AND m.invoice_line_id=OLD.id
  AND m.decision='confirmed' AND m.evidence #>> '{deliveryExpenseReview,costCategory}'='shared_overhead') THEN
  RAISE EXCEPTION 'Confirmed shared overhead invoice line is immutable' USING ERRCODE='55000';
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END
$f$;
CREATE TRIGGER shared_overhead_line_immutable BEFORE UPDATE OR DELETE ON public.invoice_lines
 FOR EACH ROW EXECUTE FUNCTION private.protect_shared_overhead_line();

CREATE FUNCTION private.protect_shared_overhead_invoice()
RETURNS trigger LANGUAGE plpgsql
SET search_path=pg_catalog,public,private
AS $f$
BEGIN
 IF EXISTS(SELECT 1 FROM public.invoice_lines l JOIN public.match_reviews m ON m.tenant_id=l.tenant_id AND m.invoice_line_id=l.id
  WHERE l.tenant_id=OLD.tenant_id AND l.invoice_id=OLD.id AND m.decision='confirmed'
  AND m.evidence #>> '{deliveryExpenseReview,costCategory}'='shared_overhead') THEN
  RAISE EXCEPTION 'Confirmed shared overhead invoice header is immutable' USING ERRCODE='55000';
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END
$f$;
CREATE TRIGGER shared_overhead_invoice_immutable BEFORE UPDATE OR DELETE ON public.invoices
 FOR EACH ROW EXECUTE FUNCTION private.protect_shared_overhead_invoice();
COMMIT;

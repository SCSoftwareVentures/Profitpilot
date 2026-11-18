-- Automated validation may create proposals only, never edit prior evidence.
BEGIN;
REVOKE UPDATE(decision,reason) ON public.mapping_decisions FROM profitpilot_app;
REVOKE INSERT ON public.mapping_decisions FROM profitpilot_app;
GRANT INSERT(tenant_id,raw_row_id,target_type,target_id,decision,confidence,method_version,reason)
 ON public.mapping_decisions TO profitpilot_app;
CREATE FUNCTION private.guard_automated_mapping()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
BEGIN
 IF current_user<>'profitpilot_app' THEN RETURN NEW; END IF;
 IF TG_OP<>'INSERT' OR NEW.tenant_id IS DISTINCT FROM private.current_tenant_id()
 OR coalesce(private.current_actor_role(),'') NOT IN ('owner','admin','analyst','reviewer')
 OR NEW.target_type IS DISTINCT FROM 'invoice_row' OR NEW.target_id IS NOT NULL
 OR NEW.decision NOT IN ('candidate','held') OR NEW.confidence IS DISTINCT FROM 'LOW'
 OR NEW.method_version IS DISTINCT FROM 'invoice-validator-0.1.0'
 OR NEW.reviewer_id IS NOT NULL OR NEW.reviewed_at IS NOT NULL
 OR NEW.reason IS NULL OR char_length(NEW.reason) NOT BETWEEN 1 AND 2000
 THEN RAISE EXCEPTION 'Automated mapping may only create unreviewed invoice proposals' USING ERRCODE='42501'; END IF;
 IF NOT EXISTS(SELECT 1 FROM public.raw_import_rows r JOIN public.import_batches b ON b.tenant_id=r.tenant_id AND b.id=r.batch_id
 WHERE r.tenant_id=NEW.tenant_id AND r.id=NEW.raw_row_id AND b.source_type IN ('customer_invoice','supplier_invoice')
 AND b.status IN ('registered','validating','review'))
 THEN RAISE EXCEPTION 'Mapping source is not eligible' USING ERRCODE='42501'; END IF;
 RETURN NEW;
END $fn$;
REVOKE ALL ON FUNCTION private.guard_automated_mapping() FROM PUBLIC,profitpilot_app;
CREATE TRIGGER automated_mapping_guard BEFORE INSERT OR UPDATE ON public.mapping_decisions
 FOR EACH ROW EXECUTE FUNCTION private.guard_automated_mapping();
COMMIT;

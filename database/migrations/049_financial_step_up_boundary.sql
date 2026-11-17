-- Verified MFA at the financial mutation boundary, not merely HTTP middleware.
BEGIN;
CREATE FUNCTION private.assert_financial_step_up(p_tenant uuid,p_target uuid,p_action text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
DECLARE at_time bigint; proof text; perm text;
BEGIN
 IF p_action IS NULL OR p_target IS NULL THEN RAISE EXCEPTION 'Financial step-up target required' USING ERRCODE='42501'; END IF;
 IF p_action ~ '^payroll_row_decision:[1-9][0-9]{0,6}$' THEN perm:='payroll.rows.decide';
 ELSIF p_action='payroll_pool_reconcile' THEN perm:='payroll.pools.reconcile';
 ELSIF p_action='payroll_allocation_confirm' THEN perm:='payroll.allocations.confirm';
 ELSIF p_action IN ('invoice_batch_prepare','invoice_match_decide') THEN perm:='matching.decide';
 ELSE RAISE EXCEPTION 'Unrecognised financial step-up action' USING ERRCODE='42501'; END IF;
 IF nullif(current_setting('app.financial_auth_time',true),'') IS NULL
 OR current_setting('app.financial_auth_time',true) !~ '^[0-9]{1,15}$'
 THEN RAISE EXCEPTION 'Financial step-up proof required' USING ERRCODE='42501'; END IF;
 at_time:=current_setting('app.financial_auth_time')::bigint;
 proof:=current_setting('app.financial_proof',true);
 IF private.has_scoped_permission(p_tenant,perm) IS DISTINCT FROM true THEN RAISE EXCEPTION 'Financial permission required' USING ERRCODE='42501'; END IF;
 RETURN private.assert_privacy_step_up(p_tenant,p_target,'financial:'||p_action,at_time,proof);
END
$fn$;
ALTER FUNCTION private.assert_financial_step_up(uuid,uuid,text) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.assert_financial_step_up(uuid,uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.assert_financial_step_up(uuid,uuid,text) TO profitpilot_app;

CREATE FUNCTION private.guard_runtime_financial_write() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public,private AS $fn$
DECLARE v_batch uuid; v_importer uuid; v_actor uuid; v_row_no integer; v_canonical jsonb;
BEGIN
 IF current_user<>'profitpilot_app' THEN RETURN NEW; END IF;
 IF TG_TABLE_NAME='import_batches' THEN
  IF OLD.status NOT IN ('uploaded','review') THEN RAISE EXCEPTION 'Final import state is immutable' USING ERRCODE='55000'; END IF;
  IF NEW.status='accepted' THEN
   IF OLD.status<>'review' OR NEW.source_type NOT IN ('payroll','customer_invoice','supplier_invoice') THEN RAISE EXCEPTION 'Review required before acceptance' USING ERRCODE='55000'; END IF;
   v_actor:=private.assert_financial_step_up(NEW.tenant_id,NEW.id,CASE WHEN NEW.source_type='payroll' THEN 'payroll_pool_reconcile' ELSE 'invoice_batch_prepare' END);
   IF v_actor=NEW.created_by THEN RAISE EXCEPTION 'Independent source reviewer required' USING ERRCODE='42501'; END IF;
  END IF;
 ELSIF TG_TABLE_NAME='mapping_decisions' THEN
  IF TG_OP='INSERT' THEN
   IF NEW.decision IN ('candidate','held') THEN
    IF NEW.reviewer_id IS NOT NULL OR NEW.reviewed_at IS NOT NULL OR NEW.target_id IS NOT NULL THEN RAISE EXCEPTION 'Validation cannot fabricate review evidence' USING ERRCODE='42501'; END IF;
    RETURN NEW;
   END IF;
   SELECT r.batch_id,b.created_by INTO v_batch,v_importer FROM public.raw_import_rows r JOIN public.import_batches b ON b.tenant_id=r.tenant_id AND b.id=r.batch_id
   WHERE r.tenant_id=NEW.tenant_id AND r.id=NEW.raw_row_id AND b.status='review' AND b.source_type IN ('customer_invoice','supplier_invoice');
   v_actor:=private.assert_financial_step_up(NEW.tenant_id,v_batch,'invoice_batch_prepare');
   IF NEW.decision<>'accepted' OR NEW.method_version<>'canonical-invoice-0.1.0' OR NEW.reviewer_id IS DISTINCT FROM v_actor OR NEW.reviewed_at IS NULL OR v_importer=v_actor
   THEN RAISE EXCEPTION 'Independent invoice preparation evidence required' USING ERRCODE='42501'; END IF;
  ELSE
   IF OLD.decision NOT IN ('candidate','held') THEN RAISE EXCEPTION 'Final source review is immutable' USING ERRCODE='55000'; END IF;
   IF NEW.decision IN ('candidate','held') AND NEW.reviewer_id IS NULL AND OLD.reviewer_id IS NULL AND NEW.reviewed_at IS NULL AND OLD.reviewed_at IS NULL THEN RETURN NEW; END IF;
   SELECT r.batch_id,r.row_number,b.created_by INTO v_batch,v_row_no,v_importer FROM public.raw_import_rows r JOIN public.import_batches b ON b.tenant_id=r.tenant_id AND b.id=r.batch_id
   WHERE r.tenant_id=NEW.tenant_id AND r.id=NEW.raw_row_id AND b.status='review' AND b.source_type='payroll';
   v_actor:=private.assert_financial_step_up(NEW.tenant_id,v_batch,'payroll_row_decision:'||v_row_no);
   IF NEW.method_version<>'payroll-validator-0.1.0' OR NEW.decision NOT IN ('accepted','rejected') OR NEW.reviewer_id IS DISTINCT FROM v_actor OR NEW.reviewed_at IS NULL OR v_importer=v_actor OR (OLD.decision='held' AND NEW.decision='accepted')
   THEN RAISE EXCEPTION 'Independent payroll decision required' USING ERRCODE='42501'; END IF;
  END IF;
 ELSIF TG_TABLE_NAME='payroll_pools' THEN
  SELECT b.created_by INTO v_importer FROM public.import_batches b WHERE b.tenant_id=NEW.tenant_id AND b.id=NEW.batch_id AND b.source_type='payroll' AND b.status='review';
  v_actor:=private.assert_financial_step_up(NEW.tenant_id,NEW.batch_id,'payroll_pool_reconcile');
  IF v_importer IS NULL OR v_importer=v_actor THEN RAISE EXCEPTION 'Independent payroll reconciliation required' USING ERRCODE='42501'; END IF;
 ELSIF TG_TABLE_NAME='allocation_runs' THEN
  v_actor:=private.assert_financial_step_up(NEW.tenant_id,NEW.id,'payroll_allocation_confirm');
  IF OLD.status<>'review' OR NEW.status<>'confirmed' OR NEW.reviewer_id IS DISTINCT FROM v_actor OR v_actor=OLD.created_by OR OLD.created_by IS NULL
  THEN RAISE EXCEPTION 'Independent allocation confirmation required' USING ERRCODE='42501'; END IF;
 ELSIF TG_TABLE_NAME='invoices' THEN
  IF NEW.source_ref !~ '^canonical-batch:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN RAISE EXCEPTION 'Canonical invoice source required' USING ERRCODE='42501'; END IF;
  v_batch:=substring(NEW.source_ref from 17)::uuid;
  SELECT b.created_by INTO v_importer FROM public.import_batches b WHERE b.tenant_id=NEW.tenant_id AND b.id=v_batch AND b.status='review' AND b.source_type=NEW.direction||'_invoice';
  v_actor:=private.assert_financial_step_up(NEW.tenant_id,v_batch,'invoice_batch_prepare');
  IF v_importer IS NULL OR v_importer=v_actor THEN RAISE EXCEPTION 'Independent invoice preparation required' USING ERRCODE='42501'; END IF;
 ELSIF TG_TABLE_NAME='invoice_lines' THEN
  SELECT r.batch_id,b.created_by INTO v_batch,v_importer FROM public.raw_import_rows r JOIN public.import_batches b ON b.tenant_id=r.tenant_id AND b.id=r.batch_id
  JOIN public.invoices i ON i.tenant_id=r.tenant_id AND i.id=NEW.invoice_id AND i.source_ref='canonical-batch:'||r.batch_id::text
  WHERE r.tenant_id=NEW.tenant_id AND r.id=NEW.source_row_id AND b.status='review';
  v_actor:=private.assert_financial_step_up(NEW.tenant_id,v_batch,'invoice_batch_prepare');
  IF v_importer IS NULL OR v_importer=v_actor THEN RAISE EXCEPTION 'Independent invoice line preparation required' USING ERRCODE='42501'; END IF;
 ELSIF TG_TABLE_NAME='match_reviews' THEN
  IF TG_OP='INSERT' THEN
   SELECT r.batch_id,b.created_by INTO v_batch,v_importer FROM public.invoice_lines l JOIN public.raw_import_rows r ON r.tenant_id=l.tenant_id AND r.id=l.source_row_id
   JOIN public.import_batches b ON b.tenant_id=r.tenant_id AND b.id=r.batch_id
   WHERE l.tenant_id=NEW.tenant_id AND l.id=NEW.invoice_line_id AND b.status='review';
   v_actor:=private.assert_financial_step_up(NEW.tenant_id,v_batch,'invoice_batch_prepare');
   v_canonical:=NEW.evidence->'canonicalInvoice';
   IF v_importer IS NULL OR v_importer=v_actor OR v_canonical->>'batchId' IS DISTINCT FROM v_batch::text OR v_canonical->>'preparedBy' IS DISTINCT FROM v_actor::text OR v_canonical->>'importedBy' IS DISTINCT FROM v_importer::text OR NEW.reviewer_id IS NOT NULL OR NEW.reviewed_at IS NOT NULL
   THEN RAISE EXCEPTION 'Canonical candidate attribution required' USING ERRCODE='42501'; END IF;
  ELSE
   v_actor:=private.assert_financial_step_up(NEW.tenant_id,NEW.id,'invoice_match_decide');
   IF NEW.evidence->'canonicalInvoice' IS DISTINCT FROM OLD.evidence->'canonicalInvoice' THEN RAISE EXCEPTION 'Canonical invoice attribution is immutable' USING ERRCODE='55000'; END IF;
   IF NEW.decision='confirmed' AND OLD.evidence #>> '{canonicalInvoice,method}'='canonical-invoice-0.1.0'
    AND v_actor::text IN (OLD.evidence #>> '{canonicalInvoice,preparedBy}',OLD.evidence #>> '{canonicalInvoice,importedBy}')
   THEN RAISE EXCEPTION 'Independent match confirmer required' USING ERRCODE='42501'; END IF;
   IF NEW.decision IS DISTINCT FROM OLD.decision AND (NEW.reviewer_id IS DISTINCT FROM v_actor OR NEW.reviewed_at IS NULL)
   THEN RAISE EXCEPTION 'Match reviewer attribution required' USING ERRCODE='42501'; END IF;
  END IF;
 END IF;
 RETURN NEW;
END
$fn$;
ALTER FUNCTION private.guard_runtime_financial_write() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.guard_runtime_financial_write() FROM PUBLIC,profitpilot_app;
CREATE TRIGGER financial_step_up_import BEFORE UPDATE ON public.import_batches FOR EACH ROW EXECUTE FUNCTION private.guard_runtime_financial_write();
CREATE TRIGGER financial_step_up_mapping BEFORE INSERT OR UPDATE ON public.mapping_decisions FOR EACH ROW EXECUTE FUNCTION private.guard_runtime_financial_write();
CREATE TRIGGER financial_step_up_pool BEFORE INSERT ON public.payroll_pools FOR EACH ROW EXECUTE FUNCTION private.guard_runtime_financial_write();
CREATE TRIGGER financial_step_up_allocation BEFORE UPDATE ON public.allocation_runs FOR EACH ROW EXECUTE FUNCTION private.guard_runtime_financial_write();
CREATE TRIGGER financial_step_up_invoice BEFORE INSERT ON public.invoices FOR EACH ROW EXECUTE FUNCTION private.guard_runtime_financial_write();
CREATE TRIGGER financial_step_up_invoice_line BEFORE INSERT ON public.invoice_lines FOR EACH ROW EXECUTE FUNCTION private.guard_runtime_financial_write();
CREATE TRIGGER financial_step_up_match BEFORE INSERT OR UPDATE ON public.match_reviews FOR EACH ROW EXECUTE FUNCTION private.guard_runtime_financial_write();
COMMIT;

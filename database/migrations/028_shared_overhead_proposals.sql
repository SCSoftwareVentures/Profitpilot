-- Preserve draft allocations; a shared confirmation must reference the immutable proposal.
BEGIN;
CREATE FUNCTION private.guard_shared_overhead_proposal()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,private AS $f$
DECLARE p jsonb; r jsonb;
BEGIN
 IF TG_OP='DELETE' THEN
  IF OLD.evidence ? 'sharedOverheadProposal' THEN RAISE EXCEPTION 'Shared overhead proposal is immutable' USING ERRCODE='55000'; END IF;
  RETURN OLD;
 END IF;
 IF TG_OP='UPDATE' AND OLD.evidence ? 'sharedOverheadProposal' THEN
  IF NEW.evidence->'sharedOverheadProposal' IS DISTINCT FROM OLD.evidence->'sharedOverheadProposal'
   OR NEW.evidence->'canonicalInvoice' IS DISTINCT FROM OLD.evidence->'canonicalInvoice'
   OR ROW(NEW.tenant_id,NEW.invoice_line_id,NEW.contract_id,NEW.site_id,NEW.service_period_start,NEW.service_period_end)
      IS DISTINCT FROM ROW(OLD.tenant_id,OLD.invoice_line_id,OLD.contract_id,OLD.site_id,OLD.service_period_start,OLD.service_period_end)
   THEN RAISE EXCEPTION 'Shared overhead proposal and scope are immutable' USING ERRCODE='55000'; END IF;
 END IF;
 p:=NEW.evidence->'sharedOverheadProposal';r:=NEW.evidence->'deliveryExpenseReview';
 IF NEW.decision='confirmed' AND (p IS NOT NULL OR r->>'costCategory'='shared_overhead') THEN
  IF TG_OP='INSERT' THEN RAISE EXCEPTION 'Shared overhead requires an existing proposal' USING ERRCODE='55000'; END IF;
  IF OLD.evidence->'sharedOverheadProposal' IS NULL OR p IS NULL OR r->>'costCategory' IS DISTINCT FROM 'shared_overhead'
   OR p->>'id' IS NULL OR r #>> '{sharedOverhead,proposalId}' IS DISTINCT FROM p->>'id'
   OR r #> '{sharedOverhead,shares}' IS DISTINCT FROM p->'shares'
   OR r #>> '{sharedOverhead,sourceAmount}' IS DISTINCT FROM p->>'sourceAmount'
   OR NEW.reviewer_id IS NULL OR NEW.reviewer_id::text IS NOT DISTINCT FROM p->>'proposedBy'
   THEN RAISE EXCEPTION 'Shared overhead confirmation must match independent immutable proposal' USING ERRCODE='55000'; END IF;
 END IF;
 RETURN NEW;
END
$f$;
CREATE TRIGGER shared_overhead_proposal_guard BEFORE INSERT OR UPDATE OR DELETE ON public.match_reviews
 FOR EACH ROW EXECUTE FUNCTION private.guard_shared_overhead_proposal();
COMMIT;

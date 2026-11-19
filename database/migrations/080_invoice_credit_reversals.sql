-- Append-only full credit reversal. Original and reversal amounts remain positive
-- evidence entries; the snapshot subtracts reversals from net credit totals.
BEGIN;
DO $check$ BEGIN IF private.verify_security_catalog() IS DISTINCT FROM true THEN RAISE EXCEPTION 'Prior catalog does not verify'; END IF; END $check$;
ALTER TABLE private.invoice_credit_orders ADD COLUMN reverses_order_id uuid,
 ADD CHECK(reverses_order_id IS NULL OR reverses_order_id<>order_id),
 ADD FOREIGN KEY(tenant_id,reverses_order_id) REFERENCES private.invoice_credit_receipts(tenant_id,order_id);
ALTER TABLE private.invoice_credit_receipts ADD COLUMN reverses_order_id uuid,
 ADD CHECK(reverses_order_id IS NULL OR reverses_order_id<>order_id),
 ADD UNIQUE(tenant_id,reverses_order_id),
 ADD FOREIGN KEY(tenant_id,reverses_order_id) REFERENCES private.invoice_credit_receipts(tenant_id,order_id);
CREATE OR REPLACE FUNCTION private.invoice_credit_summary(t uuid,l uuid,o uuid) RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE result jsonb;
BEGIN
 SELECT jsonb_build_object('orderId',q.order_id,'source',q.source_snapshot,'creditReferenceDigest',q.credit_ref_digest,'amount',q.amount::text,
 'evidenceDigest',q.evidence_digest,'scopeDigest',q.scope_digest,'status',CASE WHEN r.order_id=q.order_id AND EXISTS(SELECT 1 FROM private.invoice_credit_receipts v WHERE v.tenant_id=q.tenant_id AND v.reverses_order_id=q.order_id) THEN 'reversed' WHEN r.order_id=q.order_id THEN 'recorded' WHEN d.decision='rejected' THEN 'rejected'
 WHEN d.expires_at<=clock_timestamp() OR (d.order_id IS NULL AND w.requested_at+interval '24 hours'<=clock_timestamp()) THEN 'expired'
 WHEN d.decision='approved' THEN 'approved_pending_record' ELSE 'requested' END,'paymentAuthorized',false,'accountingTreatment','original_service_period_management_only')
 ||CASE WHEN q.reverses_order_id IS NOT NULL THEN jsonb_build_object('reversesOrderId',q.reverses_order_id,'adjustmentType','full_reversal') ELSE '{}'::jsonb END
 INTO result FROM private.invoice_credit_orders q JOIN private.security_work_orders w ON w.tenant_id=q.tenant_id AND w.id=q.order_id
 LEFT JOIN private.security_work_decisions d ON d.tenant_id=q.tenant_id AND d.order_id=q.order_id
 LEFT JOIN private.invoice_credit_receipts r ON r.tenant_id=q.tenant_id AND r.order_id=q.order_id WHERE q.tenant_id=t AND q.line_id=l AND q.order_id=o;
 IF result IS NULL THEN RAISE EXCEPTION 'Credit order unavailable' USING ERRCODE='42501'; END IF;RETURN result;
END $fn$;
CREATE OR REPLACE FUNCTION private.api_invoice_credit_step(t uuid,l uuid,o uuid,ref text,amount_text text,evidence text,scope text,step text,
 auth bigint,iat bigint,session_digest text,expiry bigint,nonce text,key_id text,signature text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE actor uuid; src jsonb; q private.invoice_credit_orders%ROWTYPE; consumed numeric;
BEGIN
 actor:=private.security_work_actor(t,o,'privileged_operation',scope,step,auth,iat,session_digest,expiry,nonce,key_id,signature);
 IF l IS NULL OR ref IS NULL OR ref !~ '^[a-f0-9]{64}$' OR ref=repeat('0',64) OR evidence IS NULL OR evidence !~ '^[a-f0-9]{64}$' OR evidence=repeat('0',64)
 OR amount_text IS NULL OR amount_text !~ '^(0|[1-9][0-9]{0,11})[.][0-9]{2}$' OR amount_text='0.00'
 OR scope IS DISTINCT FROM encode(public.digest(convert_to('invoice-credit-v1'||E'\n'||l||E'\n'||ref||E'\n'||amount_text||E'\n'||evidence,'UTF8'),'sha256'),'hex')
 THEN RAISE EXCEPTION 'Credit scope denied' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('profitpilot-workspace:'||t::text,0));
 src:=private.invoice_credit_source(t,l);
 IF src IS NULL THEN RAISE EXCEPTION 'Accepted eligible invoice line unavailable' USING ERRCODE='42501'; END IF;
 IF step<>'request' THEN
  SELECT * INTO q FROM private.invoice_credit_orders WHERE tenant_id=t AND line_id=l AND order_id=o AND scope_digest=scope;
  IF NOT FOUND OR q.source_snapshot IS DISTINCT FROM src OR q.reverses_order_id IS NOT NULL THEN RAISE EXCEPTION 'Credit source changed' USING ERRCODE='42501'; END IF;
 END IF;
 IF step<>'reject' THEN
  IF EXISTS(SELECT 1 FROM private.invoice_credit_receipts WHERE tenant_id=t AND credit_ref_digest=ref) THEN RAISE EXCEPTION 'Credit reference already recorded' USING ERRCODE='23514'; END IF;
  SELECT coalesce(sum(x.amount),0) INTO consumed FROM private.invoice_credit_receipts r JOIN private.invoice_credit_orders x ON x.tenant_id=r.tenant_id AND x.order_id=r.order_id WHERE r.tenant_id=t AND r.line_id=l AND r.reverses_order_id IS NULL
  AND NOT EXISTS(SELECT 1 FROM private.invoice_credit_receipts v WHERE v.tenant_id=r.tenant_id AND v.reverses_order_id=r.order_id);
  IF consumed+amount_text::numeric>(src->>'originalAmount')::numeric THEN RAISE EXCEPTION 'Credits exceed original line' USING ERRCODE='23514'; END IF;
 END IF;
 IF step='request' AND (SELECT count(*) FROM private.invoice_credit_orders WHERE tenant_id=t AND line_id=l)>=50 THEN RAISE EXCEPTION 'Credit review capacity reached' USING ERRCODE='54000'; END IF;
 PERFORM private.record_security_work(t,o,'privileged_operation',scope,step,auth,iat,session_digest,expiry,nonce,key_id,signature);
 IF step='request' THEN
  INSERT INTO private.invoice_credit_orders(tenant_id,order_id,line_id,credit_ref_digest,amount,evidence_digest,scope_digest,source_snapshot) VALUES(t,o,l,ref,amount_text::numeric,evidence,scope,src);
 ELSIF step='consume' THEN
  INSERT INTO private.invoice_credit_receipts(tenant_id,order_id,line_id,credit_ref_digest) VALUES(t,o,l,ref);
  INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,metadata) VALUES(t,actor,'invoice_credit_recorded','invoice_line',l,jsonb_build_object('orderId',o,'scopeDigest',scope));
 END IF;
 PERFORM private.sensitive_api_fresh(auth,expiry);RETURN private.invoice_credit_summary(t,l,o);
END $fn$;
CREATE FUNCTION private.api_invoice_credit_reversal_step(t uuid,l uuid,o uuid,prior uuid,ref text,amount_text text,evidence text,scope text,step text,
 auth bigint,iat bigint,session_digest text,expiry bigint,nonce text,key_id text,signature text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE actor uuid; src jsonb; q private.invoice_credit_orders%ROWTYPE; original private.invoice_credit_orders%ROWTYPE;
BEGIN
 actor:=private.security_work_actor(t,o,'privileged_operation',scope,step,auth,iat,session_digest,expiry,nonce,key_id,signature);
 IF l IS NULL OR prior IS NULL OR prior=o OR ref IS NULL OR ref !~ '^[a-f0-9]{64}$' OR ref=repeat('0',64) OR evidence IS NULL OR evidence !~ '^[a-f0-9]{64}$' OR evidence=repeat('0',64)
 OR amount_text IS NULL OR amount_text !~ '^(0|[1-9][0-9]{0,11})[.][0-9]{2}$' OR amount_text='0.00'
 OR scope IS DISTINCT FROM encode(public.digest(convert_to('invoice-credit-reversal-v1'||E'\n'||l||E'\n'||prior||E'\n'||ref||E'\n'||amount_text||E'\n'||evidence,'UTF8'),'sha256'),'hex')
 THEN RAISE EXCEPTION 'Credit scope denied' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('profitpilot-workspace:'||t::text,0));
 src:=private.invoice_credit_source(t,l);
 IF src IS NULL THEN RAISE EXCEPTION 'Accepted eligible invoice line unavailable' USING ERRCODE='42501'; END IF;
 SELECT v.* INTO original FROM private.invoice_credit_orders v JOIN private.invoice_credit_receipts r ON r.tenant_id=v.tenant_id AND r.order_id=v.order_id WHERE v.tenant_id=t AND v.line_id=l AND v.order_id=prior AND v.reverses_order_id IS NULL AND r.reverses_order_id IS NULL;
 IF NOT FOUND OR original.source_snapshot IS DISTINCT FROM src THEN RAISE EXCEPTION 'Recorded original credit unavailable' USING ERRCODE='42501'; END IF;
 IF original.amount IS DISTINCT FROM amount_text::numeric THEN RAISE EXCEPTION 'Reversal must equal original credit' USING ERRCODE='23514'; END IF;
 IF step<>'request' THEN
  SELECT * INTO q FROM private.invoice_credit_orders WHERE tenant_id=t AND line_id=l AND order_id=o AND scope_digest=scope;
  IF NOT FOUND OR q.source_snapshot IS DISTINCT FROM src OR q.reverses_order_id IS DISTINCT FROM prior THEN RAISE EXCEPTION 'Credit source changed' USING ERRCODE='42501'; END IF;
 END IF;
 IF step<>'reject' THEN
  IF EXISTS(SELECT 1 FROM private.invoice_credit_receipts WHERE tenant_id=t AND credit_ref_digest=ref) THEN RAISE EXCEPTION 'Credit reference already recorded' USING ERRCODE='23514'; END IF;
  IF EXISTS(SELECT 1 FROM private.invoice_credit_receipts v WHERE v.tenant_id=t AND v.reverses_order_id=prior) THEN RAISE EXCEPTION 'Original credit already reversed' USING ERRCODE='23514'; END IF;
 END IF;
 IF step='request' AND (SELECT count(*) FROM private.invoice_credit_orders WHERE tenant_id=t AND line_id=l)>=50 THEN RAISE EXCEPTION 'Credit review capacity reached' USING ERRCODE='54000'; END IF;
 PERFORM private.record_security_work(t,o,'privileged_operation',scope,step,auth,iat,session_digest,expiry,nonce,key_id,signature);
 IF step='request' THEN
  INSERT INTO private.invoice_credit_orders(tenant_id,order_id,line_id,credit_ref_digest,amount,evidence_digest,scope_digest,source_snapshot,reverses_order_id) VALUES(t,o,l,ref,amount_text::numeric,evidence,scope,src,prior);
 ELSIF step='consume' THEN
  INSERT INTO private.invoice_credit_receipts(tenant_id,order_id,line_id,credit_ref_digest,reverses_order_id) VALUES(t,o,l,ref,prior);
  INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,metadata) VALUES(t,actor,'invoice_credit_reversed','invoice_line',l,jsonb_build_object('orderId',o,'scopeDigest',scope,'reversesOrderId',prior));
 END IF;
 PERFORM private.sensitive_api_fresh(auth,expiry);RETURN private.invoice_credit_summary(t,l,o);
END $fn$;
REVOKE ALL ON FUNCTION private.api_invoice_credit_reversal_step(uuid,uuid,uuid,uuid,text,text,text,text,text,bigint,bigint,text,bigint,text,text,text) FROM PUBLIC,profitpilot_app;
GRANT EXECUTE ON FUNCTION private.api_invoice_credit_reversal_step(uuid,uuid,uuid,uuid,text,text,text,text,text,bigint,bigint,text,bigint,text,text,text) TO profitpilot_app;
CREATE OR REPLACE FUNCTION private.invoice_credit_snapshot(t uuid,c uuid,s uuid,starts date,ends date,baseline uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $fn$
DECLARE result jsonb;
BEGIN
 IF private.current_tenant_id() IS DISTINCT FROM t OR c IS NULL OR s IS NULL OR starts IS NULL OR ends IS NULL OR ends<starts OR NOT isfinite(starts) OR NOT isfinite(ends)
 THEN RAISE EXCEPTION 'Credit snapshot denied' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('profitpilot-workspace:'||t::text,0));
 WITH credits AS MATERIALIZED (
 SELECT q.*,private.invoice_credit_source(t,q.line_id) actual FROM private.invoice_credit_receipts r JOIN private.invoice_credit_orders q ON q.tenant_id=r.tenant_id AND q.order_id=r.order_id
 WHERE r.tenant_id=t AND q.source_snapshot->>'contractId'=c::text AND q.source_snapshot->>'siteId'=s::text
 AND (q.source_snapshot->>'periodStart')::date<=ends AND (q.source_snapshot->>'periodEnd')::date>=starts
 ORDER BY q.order_id LIMIT 10001
 )
 SELECT jsonb_build_object('customerCredit',coalesce(sum(CASE WHEN reverses_order_id IS NULL THEN amount ELSE -amount END) FILTER(WHERE source_snapshot->>'direction'='customer'),0)::numeric(30,2)::text,
 'supplierCredit',coalesce(sum(CASE WHEN reverses_order_id IS NULL THEN amount ELSE -amount END) FILTER(WHERE source_snapshot->>'direction'='supplier'),0)::numeric(30,2)::text,
 'creditCount',count(*),'reversalCount',count(*) FILTER(WHERE reverses_order_id IS NOT NULL),'invalid',count(*)>10000 OR coalesce(bool_or(actual IS DISTINCT FROM source_snapshot OR source_snapshot->>'baselineId' IS DISTINCT FROM baseline::text
 OR (source_snapshot->>'periodStart')::date<starts OR (source_snapshot->>'periodEnd')::date>ends),false),
 'lines',coalesce(jsonb_agg(jsonb_build_array(order_id,line_id,credit_ref_digest,amount::text,evidence_digest,scope_digest,source_snapshot)||CASE WHEN reverses_order_id IS NOT NULL THEN jsonb_build_array(reverses_order_id) ELSE '[]'::jsonb END ORDER BY order_id),'[]'::jsonb))
 INTO result FROM credits;RETURN result;
END $fn$;
CREATE OR REPLACE FUNCTION private.capture_calculation_sources() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $fn$
DECLARE snap jsonb; baseline uuid; baselines integer; revenue numeric; cost numeric; ic integer; ac integer; reviewed integer;
 bad boolean; digest_value text; supplier jsonb; supplier_total numeric:=0; shared jsonb; business jsonb; credits jsonb;
BEGIN
 IF NEW.formula_version NOT IN ('0.2.0','0.3.0','0.4.0','0.5.0','0.6.0') THEN RETURN NEW; END IF;
 IF private.current_tenant_id() IS DISTINCT FROM NEW.tenant_id OR coalesce(private.current_actor_role(),'') NOT IN ('owner','admin','analyst','reviewer')
 OR NEW.completeness<>'incomplete' THEN RAISE EXCEPTION 'Calculation receipt authority denied' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('payroll-correction:'||NEW.tenant_id::text,0));
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('profitpilot-workspace:'||NEW.tenant_id::text,0));
 -- Single statement snapshot: a concurrent source change cannot produce a receipt
 -- with a different total/count or silently attach a partial period.
 WITH bas AS (
  SELECT v.id,v.version_no,v.currency,v.tax_basis FROM public.contract_versions v
  JOIN public.contracts c ON c.tenant_id=v.tenant_id AND c.id=v.contract_id
  JOIN public.sites s ON s.tenant_id=c.tenant_id AND s.business_id=c.business_id AND s.id=NEW.site_id
  WHERE v.tenant_id=NEW.tenant_id AND v.contract_id=NEW.contract_id AND v.approved_at IS NOT NULL AND v.approved_by IS NOT NULL
  AND v.effective_from<=NEW.period_start AND (v.effective_to IS NULL OR v.effective_to>=NEW.period_end)
  AND private.workspace_contract_site_allowed(c.tenant_id,c.id,s.id)
 ), inv AS (
  SELECT m.id match_id,l.id line_id,h.id invoice_id,l.amount,h.currency,h.tax_basis,m.service_period_start starts,m.service_period_end ends,
   k.batch_id,k.raw_row_id,k.baseline_id reviewed_baseline
  FROM public.match_reviews m JOIN public.invoice_lines l ON l.tenant_id=m.tenant_id AND l.id=m.invoice_line_id
  JOIN public.invoices h ON h.tenant_id=l.tenant_id AND h.id=l.invoice_id
  LEFT JOIN private.invoice_intake_lines k ON k.tenant_id=m.tenant_id AND k.match_id=m.id AND k.line_id=l.id
  WHERE m.tenant_id=NEW.tenant_id AND m.contract_id=NEW.contract_id AND m.site_id=NEW.site_id AND m.decision='confirmed'
  AND h.direction='customer' AND m.service_period_start<=NEW.period_end AND m.service_period_end>=NEW.period_start
  ORDER BY m.id LIMIT 10001
 ), pay AS (
  SELECT a.id line_id,r.id run_id,p.id pool_id,a.amount,p.currency,p.period_start starts,p.period_end ends,a.bucket_type
  FROM public.allocation_lines a JOIN public.allocation_runs r ON r.tenant_id=a.tenant_id AND r.id=a.allocation_run_id
  JOIN public.payroll_pools p ON p.tenant_id=r.tenant_id AND p.id=r.payroll_pool_id
  WHERE a.tenant_id=NEW.tenant_id AND a.site_id=NEW.site_id AND r.status='confirmed'
  AND p.period_start<=NEW.period_end AND p.period_end>=NEW.period_start
  AND NOT EXISTS(SELECT 1 FROM private.payroll_supersessions x WHERE x.tenant_id=r.tenant_id AND x.old_run_id=r.id)
  ORDER BY a.id LIMIT 10001
 ), ia AS (
  SELECT count(*)::integer n,coalesce(sum(amount),0) total,count(batch_id)::integer reviewed,
   coalesce(bool_or(starts<NEW.period_start OR ends>NEW.period_end OR tax_basis='unknown'
    OR currency IS DISTINCT FROM (SELECT currency FROM bas LIMIT 1)
    OR tax_basis IS DISTINCT FROM (SELECT tax_basis FROM bas LIMIT 1)
    OR (reviewed_baseline IS NOT NULL AND reviewed_baseline IS DISTINCT FROM (SELECT id FROM bas LIMIT 1))),false) invalid,
   jsonb_agg(jsonb_build_array(match_id,line_id,invoice_id,amount::text,currency,tax_basis,starts,ends,batch_id,raw_row_id,reviewed_baseline) ORDER BY match_id) items FROM inv
 ), pa AS (
  SELECT count(*) FILTER(WHERE bucket_type IN ('direct','approved_allocated'))::integer n,
   count(*)::integer all_n,coalesce(sum(amount) FILTER(WHERE bucket_type IN ('direct','approved_allocated')),0) total,
   coalesce(bool_or(starts<NEW.period_start OR ends>NEW.period_end OR (bucket_type IN ('direct','approved_allocated') AND currency IS DISTINCT FROM (SELECT currency FROM bas LIMIT 1))),false) invalid,
   jsonb_agg(jsonb_build_array(line_id,run_id,pool_id,amount::text,currency,starts,ends,bucket_type) ORDER BY line_id) FILTER(WHERE bucket_type IN ('direct','approved_allocated')) items FROM pay
 )
 SELECT (SELECT id FROM bas LIMIT 1),(SELECT count(*)::integer FROM bas),ia.total,pa.total,ia.n,pa.n,ia.reviewed,
 ia.invalid OR pa.invalid OR pa.all_n>10000 OR (SELECT version_no::text FROM bas LIMIT 1) IS DISTINCT FROM NEW.inputs->>'contractVersion'
 OR (SELECT currency FROM bas LIMIT 1) IS DISTINCT FROM NEW.outputs->>'currency',
 jsonb_build_object('format','profitpilot-source-trace-v1','tenantId',NEW.tenant_id,'contractId',NEW.contract_id,'siteId',NEW.site_id,
 'baselineId',(SELECT id FROM bas LIMIT 1),'periodStart',NEW.period_start,'periodEnd',NEW.period_end,'formulaVersion',NEW.formula_version,
 'invoices',ia.items,'allocations',pa.items)
 INTO baseline,baselines,revenue,cost,ic,ac,reviewed,bad,snap FROM ia CROSS JOIN pa;
 IF NEW.formula_version IN ('0.3.0','0.4.0','0.5.0','0.6.0') THEN
  supplier:=private.supplier_cost_snapshot(NEW.tenant_id,NEW.contract_id,NEW.site_id,NEW.period_start,NEW.period_end,baseline);
  supplier_total:=(supplier->>'directCost')::numeric;
  IF NEW.formula_version IN ('0.4.0','0.5.0','0.6.0') THEN
   shared:=private.shared_cost_calculation_snapshot(NEW.tenant_id,NEW.contract_id,NEW.site_id,NEW.period_start,NEW.period_end,baseline);
   IF (shared->>'invalid')::boolean OR (shared->>'missingCount')::integer<>0
    OR NEW.outputs->>'overheadCost' IS DISTINCT FROM shared->>'overheadCost'
    OR NEW.outputs->>'sharedSourceCount' IS DISTINCT FROM shared->>'sourceCount'
    OR NEW.outputs->>'unallocatedSharedCost' IS DISTINCT FROM shared->>'unallocatedSiteCost'
   THEN RAISE EXCEPTION 'Calculation source snapshot changed or does not reconcile' USING ERRCODE='23514'; END IF;
   cost:=(shared->>'payrollCost')::numeric;
  END IF;
  IF (supplier->>'invalid')::boolean OR NEW.outputs->>'payrollCost' IS DISTINCT FROM cost::numeric(30,2)::text
   OR NEW.outputs->>'supplierCost' IS DISTINCT FROM supplier->>'directCost'
   OR NEW.outputs->>'supplierLineCount' IS DISTINCT FROM supplier->>'directCount'
   OR NEW.outputs->>'supplierExcludedLineCount' IS DISTINCT FROM supplier->>'excludedCount'
   OR NEW.outputs->>'supplierPendingLineCount' IS DISTINCT FROM supplier->>'pendingCount'
  THEN RAISE EXCEPTION 'Calculation source snapshot changed or does not reconcile' USING ERRCODE='23514'; END IF;
  snap:=snap||jsonb_build_object('format','profitpilot-source-trace-v2','supplier',supplier,'payrollCost',cost::numeric(30,2)::text);
  cost:=cost+supplier_total;
  IF NEW.formula_version IN ('0.4.0','0.5.0','0.6.0') THEN
   snap:=snap||jsonb_build_object('format','profitpilot-source-trace-v3','shared',shared);
   cost:=cost+(shared->>'overheadCost')::numeric;
  END IF;
 END IF;
 IF NEW.formula_version IN ('0.5.0','0.6.0') THEN
  business:=private.business_overhead_snapshot(NEW.tenant_id,NEW.contract_id,NEW.site_id,NEW.period_start,NEW.period_end,baseline);
  IF (business->>'invalid')::boolean OR (business->>'missingCount')::integer<>0
   OR NEW.outputs->>'businessOverheadCost' IS DISTINCT FROM business->>'cost'
   OR NEW.outputs->>'businessOverheadSourceCount' IS DISTINCT FROM business->>'sourceCount'
   OR NEW.outputs->>'unallocatedBusinessOverhead' IS DISTINCT FROM business->>'unallocatedCost'
  THEN RAISE EXCEPTION 'Calculation source snapshot changed or does not reconcile' USING ERRCODE='23514'; END IF;
  cost:=cost+(business->>'cost')::numeric;
  snap:=snap||jsonb_build_object('format','profitpilot-source-trace-v4','businessOverhead',business);
 END IF;
 credits:=private.invoice_credit_snapshot(NEW.tenant_id,NEW.contract_id,NEW.site_id,NEW.period_start,NEW.period_end,baseline);
 IF (credits->>'invalid')::boolean OR (NEW.formula_version<>'0.6.0' AND (credits->>'creditCount')::integer>0)
 THEN RAISE EXCEPTION 'Calculation source snapshot changed or does not reconcile' USING ERRCODE='23514'; END IF;
 IF NEW.formula_version='0.6.0' THEN
  IF NEW.outputs->>'customerCredit' IS DISTINCT FROM credits->>'customerCredit' OR NEW.outputs->>'supplierCredit' IS DISTINCT FROM credits->>'supplierCredit'
  OR NEW.outputs->>'creditReversalCount' IS DISTINCT FROM credits->>'reversalCount'
  OR NEW.outputs->>'creditCount' IS DISTINCT FROM credits->>'creditCount' OR NEW.outputs->>'grossRevenue' IS DISTINCT FROM revenue::numeric(30,2)::text
  THEN RAISE EXCEPTION 'Calculation source snapshot changed or does not reconcile' USING ERRCODE='23514'; END IF;
  snap:=snap||jsonb_build_object('format','profitpilot-source-trace-v5','credits',credits,'grossRevenue',revenue::numeric(30,2)::text);
  revenue:=revenue-(credits->>'customerCredit')::numeric;
  cost:=cost-(credits->>'supplierCredit')::numeric;
 END IF;
 IF baselines<>1 OR bad OR ic NOT BETWEEN 1 AND 10000 OR ac NOT BETWEEN 1 AND 10000
 OR NEW.outputs->>'revenue' IS DISTINCT FROM revenue::numeric(30,2)::text
 OR NEW.outputs->>'deliveryCost' IS DISTINCT FROM cost::numeric(30,2)::text
 OR NEW.outputs->>'indicativeContribution' IS DISTINCT FROM (revenue-cost)::numeric(30,2)::text
 OR NEW.outputs->>'invoiceLineCount' IS DISTINCT FROM ic::text OR NEW.outputs->>'allocationLineCount' IS DISTINCT FROM ac::text
 OR NEW.outputs->'contribution' IS DISTINCT FROM 'null'::jsonb OR NEW.outputs->'marginPercent' IS DISTINCT FROM 'null'::jsonb
 OR NEW.outputs->>'completeness' IS DISTINCT FROM 'incomplete'
 THEN RAISE EXCEPTION 'Calculation source snapshot changed or does not reconcile' USING ERRCODE='23514'; END IF;
 digest_value:=encode(public.digest(convert_to(snap::text,'UTF8'),'sha256'),'hex');
 INSERT INTO private.calculation_source_receipts(tenant_id,calculation_id,baseline_id,source_snapshot,snapshot_digest,invoice_count,allocation_count,reviewed_invoice_count)
 VALUES(NEW.tenant_id,NEW.id,baseline,snap,digest_value,ic,ac,reviewed);
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,metadata)
 VALUES(NEW.tenant_id,NEW.created_by,'calculation_source_receipt_created','calculation_run',NEW.id,jsonb_build_object('sourceDigest',digest_value));
 RETURN NEW;
END $fn$;
CREATE OR REPLACE FUNCTION private.calculation_trace_projection(p_tenant uuid,p_run uuid) RETURNS jsonb
LANGUAGE sql STABLE SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT jsonb_build_object('status','captured','format',source_snapshot->>'format','digest',snapshot_digest,'baselineId',baseline_id,
 'invoiceLineCount',invoice_count,'reviewedInvoiceLineCount',reviewed_invoice_count,'allocationLineCount',allocation_count,'capturedAt',captured_at)
 ||CASE WHEN source_snapshot->>'format' IN ('profitpilot-source-trace-v2','profitpilot-source-trace-v3','profitpilot-source-trace-v4','profitpilot-source-trace-v5') THEN jsonb_build_object(
 'payrollCost',source_snapshot->>'payrollCost','supplierCost',source_snapshot->'supplier'->>'directCost',
 'supplierLineCount',(source_snapshot->'supplier'->>'directCount')::integer,
 'supplierExcludedLineCount',(source_snapshot->'supplier'->>'excludedCount')::integer,
 'supplierPendingLineCount',(source_snapshot->'supplier'->>'pendingCount')::integer) ELSE '{}'::jsonb END
 ||CASE WHEN source_snapshot->>'format' IN ('profitpilot-source-trace-v3','profitpilot-source-trace-v4','profitpilot-source-trace-v5') THEN jsonb_build_object(
 'overheadCost',source_snapshot->'shared'->>'overheadCost','sharedSourceCount',(source_snapshot->'shared'->>'sourceCount')::integer,
 'unallocatedSharedCost',source_snapshot->'shared'->>'unallocatedSiteCost') ELSE '{}'::jsonb END
 ||CASE WHEN source_snapshot->>'format' IN ('profitpilot-source-trace-v4','profitpilot-source-trace-v5') THEN jsonb_build_object(
 'businessOverheadCost',source_snapshot->'businessOverhead'->>'cost',
 'businessOverheadSourceCount',(source_snapshot->'businessOverhead'->>'sourceCount')::integer,
 'unallocatedBusinessOverhead',source_snapshot->'businessOverhead'->>'unallocatedCost') ELSE '{}'::jsonb END
 ||CASE WHEN source_snapshot->>'format'='profitpilot-source-trace-v5' THEN jsonb_build_object('grossRevenue',source_snapshot->>'grossRevenue',
 'customerCredit',source_snapshot->'credits'->>'customerCredit','supplierCredit',source_snapshot->'credits'->>'supplierCredit','creditCount',(source_snapshot->'credits'->>'creditCount')::integer,'creditReversalCount',coalesce((source_snapshot->'credits'->>'reversalCount')::integer,0)) ELSE '{}'::jsonb END
 FROM private.calculation_source_receipts WHERE tenant_id=p_tenant AND calculation_id=p_run),jsonb_build_object('status','legacy_unavailable'))
$fn$;
CREATE OR REPLACE FUNCTION private.api_financial_coverage(t uuid,c uuid,action text,scope text,auth bigint,iat bigint,session_digest text,expiry bigint,nonce text,key_id text,signature text,s uuid,starts date,ends date)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $fn$
DECLARE actor uuid; baseline uuid; n integer; tax text; supplier jsonb; shared jsonb; business jsonb; credits jsonb; credit_review jsonb; imports jsonb; payroll jsonb; invoices jsonb; pending jsonb; blockers jsonb:='[]'::jsonb; gaps jsonb; result jsonb;
BEGIN
 IF s IS NULL OR starts IS NULL OR ends IS NULL OR NOT isfinite(starts) OR NOT isfinite(ends) OR ends<starts OR ends-starts>366 OR action IS DISTINCT FROM 'financial_coverage'
 OR scope IS DISTINCT FROM encode(public.digest(convert_to('financial-coverage-v1'||E'\n'||s||E'\n'||starts||E'\n'||ends,'UTF8'),'sha256'),'hex') THEN RAISE EXCEPTION 'Coverage scope denied' USING ERRCODE='42501'; END IF;
 actor:=private.sensitive_api_actor(t,c,action,scope,auth,iat,session_digest,expiry,nonce,key_id,signature);
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('payroll-correction:'||t::text,0));
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('profitpilot-workspace:'||t::text,0));
 IF NOT EXISTS(SELECT 1 FROM public.contracts co JOIN public.sites si ON si.tenant_id=co.tenant_id AND si.business_id=co.business_id AND si.id=s WHERE co.tenant_id=t AND co.id=c AND private.workspace_contract_site_allowed(t,c,s))
 THEN RAISE EXCEPTION 'Coverage authority denied' USING ERRCODE='42501'; END IF;
 PERFORM private.consume_financial_access_budget(t,'payroll_summary');
 SELECT count(*)::integer,(array_agg(v.id ORDER BY v.id))[1],min(v.tax_basis) INTO n,baseline,tax FROM public.contract_versions v
 WHERE v.tenant_id=t AND v.contract_id=c AND v.approved_at IS NOT NULL AND v.approved_by IS NOT NULL AND v.effective_from<=starts AND (v.effective_to IS NULL OR v.effective_to>=ends) AND v.currency='AUD' AND v.tax_basis<>'unknown';
 IF n<>1 THEN
  result:=jsonb_build_object('format','profitpilot-financial-coverage-v1','contractId',c,'siteId',s,'periodStart',starts,'periodEnd',ends,'status','blocked','canAttemptCalculation',false,'definitiveProfitAvailable',false,'blockers',jsonb_build_array('BASELINE_REQUIRED'),'gaps',jsonb_build_array('EXTERNAL_SOURCE_COMPLETENESS_UNVERIFIED'));
 ELSE
  supplier:=private.supplier_cost_snapshot(t,c,s,starts,ends,baseline);
  shared:=private.shared_cost_calculation_snapshot(t,c,s,starts,ends,baseline);
  business:=private.business_overhead_snapshot(t,c,s,starts,ends,baseline);
  credits:=private.invoice_credit_snapshot(t,c,s,starts,ends,baseline);
  WITH pending_orders AS MATERIALIZED (
   SELECT q.order_id,q.amount,q.reverses_order_id,d.decision FROM private.invoice_credit_orders q
   JOIN private.security_work_orders w ON w.tenant_id=q.tenant_id AND w.id=q.order_id
   LEFT JOIN private.security_work_decisions d ON d.tenant_id=q.tenant_id AND d.order_id=q.order_id
   LEFT JOIN private.invoice_credit_receipts r ON r.tenant_id=q.tenant_id AND r.order_id=q.order_id
   WHERE q.tenant_id=t AND q.source_snapshot->>'contractId'=c::text AND q.source_snapshot->>'siteId'=s::text
   AND (q.source_snapshot->>'periodStart')::date<=ends AND (q.source_snapshot->>'periodEnd')::date>=starts
   AND r.order_id IS NULL AND (d.order_id IS NULL AND w.requested_at+interval '24 hours'>clock_timestamp() OR d.decision='approved' AND d.expires_at>clock_timestamp())
   ORDER BY q.order_id LIMIT 10001
  ) SELECT jsonb_build_object('pendingCount',count(*),'pendingReversalCount',count(*) FILTER(WHERE reverses_order_id IS NOT NULL),'overCapacity',count(*)>10000) INTO credit_review FROM pending_orders;
  WITH b AS MATERIALIZED (
   SELECT id,source_type,status,source_period_start,source_period_end FROM public.import_batches WHERE tenant_id=t
   AND (source_period_start IS NULL OR source_period_end IS NULL OR (source_period_start<=ends AND source_period_end>=starts)) ORDER BY id LIMIT 10001
  )
  SELECT jsonb_build_object('count',count(*),'overCapacity',count(*)>10000,
   'unresolvedCount',count(*) FILTER(WHERE status IN ('registered','validating','review')),
   'failedOrRejectedCount',count(*) FILTER(WHERE status IN ('failed','rejected')),
   'unknownPeriodCount',count(*) FILTER(WHERE source_period_start IS NULL OR source_period_end IS NULL),
   'acceptedWithoutMaterializationCount',count(*) FILTER(WHERE status='accepted' AND
    ((source_type IN ('customer_invoice','supplier_invoice') AND NOT EXISTS(SELECT 1 FROM private.invoice_intake_receipts r WHERE r.tenant_id=t AND r.batch_id=b.id))
     OR (source_type='payroll' AND NOT EXISTS(SELECT 1 FROM public.payroll_pools p WHERE p.tenant_id=t AND p.batch_id=b.id))))) INTO imports FROM b;
  WITH pools AS MATERIALIZED (
   SELECT p.id,p.currency,p.period_start,p.period_end,p.total_amount FROM public.payroll_pools p
   WHERE p.tenant_id=t AND p.period_start<=ends AND p.period_end>=starts ORDER BY p.id LIMIT 10001
  ), active AS (
   SELECT p.*,r.id run_id,r.non_site_amount,r.excluded_amount,r.residual_amount FROM pools p
   LEFT JOIN public.allocation_runs r ON r.tenant_id=t AND r.payroll_pool_id=p.id AND r.status='confirmed'
   AND NOT EXISTS(SELECT 1 FROM private.payroll_supersessions x WHERE x.tenant_id=t AND x.old_run_id=r.id)
  )
  SELECT jsonb_build_object('poolCount',count(DISTINCT id),'overCapacity',count(*)>10000,
   'unconfirmedPoolCount',count(DISTINCT id) FILTER(WHERE run_id IS NULL),
   'nonAudPoolCount',count(DISTINCT id) FILTER(WHERE currency<>'AUD'),
   'partialPeriodPoolCount',count(DISTINCT id) FILTER(WHERE period_start<starts OR period_end>ends),
   'nonSiteAmountAUD',coalesce(sum(non_site_amount) FILTER(WHERE currency='AUD' AND period_start>=starts AND period_end<=ends),0)::numeric(30,2)::text,
   'excludedAmountAUD',coalesce(sum(excluded_amount) FILTER(WHERE currency='AUD' AND period_start>=starts AND period_end<=ends),0)::numeric(30,2)::text,
   'residualAmountAUD',coalesce(sum(residual_amount) FILTER(WHERE currency='AUD' AND period_start>=starts AND period_end<=ends),0)::numeric(30,2)::text,
   'unconfirmedPoolAmountAUD',coalesce(sum(total_amount) FILTER(WHERE run_id IS NULL AND currency='AUD' AND period_start>=starts AND period_end<=ends),0)::numeric(30,2)::text)
  INTO payroll FROM active;
  WITH matches AS MATERIALIZED (
   SELECT m.id,m.decision,m.service_period_start ps,m.service_period_end pe,l.amount,i.currency,i.tax_basis,k.batch_id,k.baseline_id
   FROM public.match_reviews m JOIN public.invoice_lines l ON l.tenant_id=m.tenant_id AND l.id=m.invoice_line_id
   JOIN public.invoices i ON i.tenant_id=l.tenant_id AND i.id=l.invoice_id
   LEFT JOIN private.invoice_intake_lines k ON k.tenant_id=m.tenant_id AND k.match_id=m.id AND k.line_id=l.id
   WHERE m.tenant_id=t AND m.contract_id=c AND m.site_id=s AND i.direction='customer'
   AND (m.service_period_start IS NULL OR m.service_period_end IS NULL OR (m.service_period_start<=ends AND m.service_period_end>=starts))
   ORDER BY m.id LIMIT 10001
  )
  SELECT jsonb_build_object('matchCount',count(*),'overCapacity',count(*)>10000,
   'confirmedCount',count(*) FILTER(WHERE decision='confirmed' AND ps>=starts AND pe<=ends),
   'unreviewedConfirmedCount',count(*) FILTER(WHERE decision='confirmed' AND batch_id IS NULL),
   'pendingCount',count(*) FILTER(WHERE decision IN ('candidate','held')),
   'rejectedCount',count(*) FILTER(WHERE decision='rejected'),
   'invalidConfirmedCount',count(*) FILTER(WHERE decision='confirmed' AND (ps IS NULL OR pe IS NULL OR ps<starts OR pe>ends OR currency<>'AUD' OR tax_basis IS DISTINCT FROM tax OR (baseline_id IS NOT NULL AND baseline_id<>baseline))))
  INTO invoices FROM matches;
  -- Business overhead sources are already represented in the business snapshot;
  -- pending supplier classifications below are counted tenant-wide, not charged.
  WITH candidates AS MATERIALIZED (
   SELECT k.line_id,l.amount,h.currency,q.classification FROM private.invoice_intake_lines k
   JOIN public.invoice_lines l ON l.tenant_id=k.tenant_id AND l.id=k.line_id
   JOIN public.invoices h ON h.tenant_id=k.tenant_id AND h.id=k.invoice_id
   JOIN public.match_reviews m ON m.tenant_id=k.tenant_id AND m.id=k.match_id
   LEFT JOIN private.supplier_cost_receipts r ON r.tenant_id=k.tenant_id AND r.batch_id=k.batch_id
   LEFT JOIN private.supplier_cost_orders q ON q.tenant_id=r.tenant_id AND q.order_id=r.order_id
   WHERE k.tenant_id=t AND h.direction='supplier' AND m.decision='confirmed'
   AND (m.service_period_start IS NULL OR m.service_period_end IS NULL OR (m.service_period_start<=ends AND m.service_period_end>=starts))
   ORDER BY k.line_id LIMIT 10001
  )
  SELECT jsonb_build_object('count',count(*),'overCapacity',count(*)>10000,
   'unclassifiedCount',count(*) FILTER(WHERE classification IS NULL),
   'unclassifiedAmountAUD',coalesce(sum(amount) FILTER(WHERE classification IS NULL AND currency='AUD'),0)::numeric(30,2)::text,
   'overlapOrExcludedCount',count(*) FILTER(WHERE classification IN ('payroll_overlap','excluded')))
  INTO pending FROM candidates;
  IF (invoices->>'confirmedCount')::integer=0 THEN blockers:=blockers||'"CUSTOMER_REVENUE_REQUIRED"'::jsonb; END IF;
  IF (invoices->>'invalidConfirmedCount')::integer>0 THEN blockers:=blockers||'"CUSTOMER_PERIOD_OR_BASIS_INVALID"'::jsonb; END IF;
  IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(shared->'lines') x WHERE x->>0='payroll') THEN blockers:=blockers||'"SITE_PAYROLL_REQUIRED"'::jsonb; END IF;
  IF (supplier->>'invalid')::boolean THEN blockers:=blockers||'"DIRECT_SUPPLIER_SCOPE_INVALID"'::jsonb; END IF;
  IF (shared->>'invalid')::boolean OR (shared->>'missingCount')::integer>0 THEN blockers:=blockers||'"SHARED_COST_ALLOCATION_REQUIRED"'::jsonb; END IF;
  IF (business->>'invalid')::boolean OR (business->>'missingCount')::integer>0 THEN blockers:=blockers||'"BUSINESS_OVERHEAD_ALLOCATION_REQUIRED"'::jsonb; END IF;
  IF (imports->>'overCapacity')::boolean OR (payroll->>'overCapacity')::boolean OR (invoices->>'overCapacity')::boolean OR (pending->>'overCapacity')::boolean THEN blockers:=blockers||'"DIAGNOSTIC_CAPACITY_EXCEEDED"'::jsonb; END IF;
  IF (credit_review->>'overCapacity')::boolean THEN blockers:=blockers||'"CREDIT_REVIEW_CAPACITY_EXCEEDED"'::jsonb; END IF;
  IF (credits->>'invalid')::boolean THEN blockers:=blockers||'"CREDIT_SCOPE_INVALID"'::jsonb; END IF;
  gaps:=jsonb_build_array('EXTERNAL_SOURCE_COMPLETENESS_UNVERIFIED','CREDITS_AND_ADJUSTMENTS_NOT_RECONCILED','TENANT_WIDE_COSTS_NOT_ATTRIBUTED');
  IF (credit_review->>'pendingCount')::integer>0 THEN gaps:=gaps||'"CREDIT_REVIEW_OUTSTANDING"'::jsonb; END IF;
  IF (imports->>'unresolvedCount')::integer>0 OR (imports->>'acceptedWithoutMaterializationCount')::integer>0 OR (imports->>'failedOrRejectedCount')::integer>0 OR (imports->>'unknownPeriodCount')::integer>0 THEN gaps:=gaps||'"IMPORT_RECONCILIATION_OUTSTANDING"'::jsonb; END IF;
  IF (payroll->>'unconfirmedPoolCount')::integer>0 OR (payroll->>'nonSiteAmountAUD')::numeric>0 OR (payroll->>'excludedAmountAUD')::numeric>0 OR (payroll->>'residualAmountAUD')::numeric>0 OR (payroll->>'partialPeriodPoolCount')::integer>0 OR (payroll->>'nonAudPoolCount')::integer>0 THEN gaps:=gaps||'"TENANT_PAYROLL_RECONCILIATION_OUTSTANDING"'::jsonb; END IF;
  IF (pending->>'unclassifiedCount')::integer>0 THEN gaps:=gaps||'"SUPPLIER_CLASSIFICATION_OUTSTANDING"'::jsonb; END IF;
  IF (invoices->>'pendingCount')::integer>0 OR (invoices->>'unreviewedConfirmedCount')::integer>0 OR (invoices->>'rejectedCount')::integer>0 THEN gaps:=gaps||'"INVOICE_RECONCILIATION_OUTSTANDING"'::jsonb; END IF;
  IF (shared->>'unallocatedSiteCost')::numeric>0 OR (business->>'unallocatedCost')::numeric>0 THEN gaps:=gaps||'"REVIEWED_UNALLOCATED_REMAINDER"'::jsonb; END IF;
  result:=jsonb_build_object('format','profitpilot-financial-coverage-v1','contractId',c,'siteId',s,'baselineId',baseline,'periodStart',starts,'periodEnd',ends,'status',CASE WHEN blockers='[]'::jsonb THEN 'indicative_only' ELSE 'blocked' END,'canAttemptCalculation',blockers='[]'::jsonb,'definitiveProfitAvailable',false,'blockers',blockers,'gaps',gaps,
   'scopeInvoices',invoices,'recordedCredits',credits-'lines','creditReview',credit_review,'tenantImports',imports,'tenantPayroll',payroll,'tenantSupplier',pending,
   'shared',shared-'lines','businessOverhead',business-'lines'-'businessId',
   'missingSharedSources',(SELECT coalesce(jsonb_agg(jsonb_build_object('kind',x->>0,'sourceId',x->>1,'amount',x->2->>'amount')),'[]'::jsonb) FROM (SELECT x FROM jsonb_array_elements((shared->'lines')||(business->'lines')) x WHERE x->>3 IS NULL LIMIT 100) q));
 END IF;
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,metadata) VALUES(t,actor,'financial_coverage_read','contract',c,jsonb_build_object('siteId',s,'periodStart',starts,'periodEnd',ends,'status',result->>'status'));
 PERFORM private.sensitive_api_fresh(auth,expiry);
 RETURN result||jsonb_build_object('asOf',clock_timestamp(),'notice','Point-in-time diagnostic only. Tenant-wide amounts are contextual and not attributable to this contract; omitted sources and external accounting completeness remain unverified. Calculation revalidates current inputs.');
END $fn$;
CREATE OR REPLACE FUNCTION private.sensitive_recovery_fingerprint()
RETURNS text LANGUAGE plpgsql STABLE SET search_path=pg_catalog SET timezone='UTC' AS $fn$
DECLARE total bigint; result text;
BEGIN
 WITH entries AS (
  SELECT * FROM (
  SELECT 'account_email'::text AS kind,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') AS hash FROM (SELECT id,email FROM public.users LIMIT 100001) x
  UNION ALL SELECT 'security_work_orders'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.security_work_orders LIMIT 100001) x
  UNION ALL SELECT 'security_work_decisions'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.security_work_decisions LIMIT 100001) x
  UNION ALL SELECT 'security_work_consumptions'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.security_work_consumptions LIMIT 100001) x
  UNION ALL SELECT 'account_correction_nonces'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.account_correction_nonces LIMIT 100001) x
  UNION ALL SELECT 'privacy_rights_cases'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.privacy_rights_cases LIMIT 100001) x
  UNION ALL SELECT 'privacy_rights_acknowledgements'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.privacy_rights_acknowledgements LIMIT 100001) x
  UNION ALL SELECT 'privacy_rights_outcomes'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.privacy_rights_outcomes LIMIT 100001) x
  UNION ALL SELECT 'payroll_proposal_reviews'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.payroll_proposal_reviews LIMIT 100001) x
  UNION ALL SELECT 'payroll_proposal_decisions'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.payroll_proposal_decisions LIMIT 100001) x
  UNION ALL SELECT 'payroll_confirmation_receipts'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.payroll_confirmation_receipts LIMIT 100001) x
  UNION ALL SELECT 'payroll_correction_reservations'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.payroll_correction_reservations LIMIT 100001) x
  UNION ALL SELECT 'payroll_supersessions'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.payroll_supersessions LIMIT 100001) x
  UNION ALL SELECT 'financial_retention_reviews'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.financial_retention_reviews LIMIT 100001) x
  UNION ALL SELECT 'financial_retention_holds'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.financial_retention_holds LIMIT 100001) x
  UNION ALL SELECT 'financial_backup_plans'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.financial_backup_plans LIMIT 100001) x
  UNION ALL SELECT 'privacy_delivery_authorizations'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.privacy_delivery_authorizations LIMIT 100001) x
  UNION ALL SELECT 'privacy_delivery_requests'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.privacy_delivery_requests LIMIT 100001) x
  UNION ALL SELECT 'privacy_receipt_evidence'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.privacy_receipt_evidence LIMIT 100001) x
  UNION ALL SELECT 'privacy_receipt_requests'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.privacy_receipt_requests LIMIT 100001) x
  UNION ALL SELECT 'privacy_dispatch_reservations'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.privacy_dispatch_reservations LIMIT 100001) x
  UNION ALL SELECT 'privacy_dispatch_burns'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.privacy_dispatch_burns LIMIT 100001) x
  UNION ALL SELECT 'privacy_dispatch_revocations'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.privacy_dispatch_revocations LIMIT 100001) x
  UNION ALL SELECT 'privacy_case_key_versions'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.privacy_case_key_versions LIMIT 100001) x
  UNION ALL SELECT 'privacy_compromised_keys'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.privacy_compromised_keys LIMIT 100001) x
  UNION ALL SELECT 'payroll_intake_receipts'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.payroll_intake_receipts LIMIT 100001) x
  UNION ALL SELECT 'payroll_intake_requests'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.payroll_intake_requests LIMIT 100001) x
  UNION ALL SELECT 'payroll_allocation_builds'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.payroll_allocation_builds LIMIT 100001) x
  UNION ALL SELECT 'workspace_records'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.workspace_records LIMIT 100001) x
  UNION ALL SELECT 'workspace_version_orders'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.workspace_version_orders LIMIT 100001) x
  UNION ALL SELECT 'workspace_version_receipts'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.workspace_version_receipts LIMIT 100001) x
  UNION ALL SELECT 'workspace_jobs'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.workspace_jobs LIMIT 100001) x
  UNION ALL SELECT 'workspace_job_events'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.workspace_job_events LIMIT 100001) x
  UNION ALL SELECT 'invoice_intake_orders'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.invoice_intake_orders LIMIT 100001) x
  UNION ALL SELECT 'invoice_intake_receipts'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.invoice_intake_receipts LIMIT 100001) x
  UNION ALL SELECT 'invoice_intake_lines'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.invoice_intake_lines LIMIT 100001) x
  UNION ALL SELECT 'calculation_source_receipts'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.calculation_source_receipts LIMIT 100001) x
  UNION ALL SELECT 'supplier_cost_orders'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.supplier_cost_orders LIMIT 100001) x
  UNION ALL SELECT 'supplier_cost_receipts'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.supplier_cost_receipts LIMIT 100001) x
  UNION ALL SELECT 'shared_cost_orders',public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.shared_cost_orders LIMIT 100001) x
  UNION ALL SELECT 'shared_cost_receipts',public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.shared_cost_receipts LIMIT 100001) x
  UNION ALL SELECT 'shared_cost_revisions',public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.shared_cost_revisions LIMIT 100001) x
  UNION ALL SELECT 'invoice_credit_orders',public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.invoice_credit_orders LIMIT 100001) x
  UNION ALL SELECT 'invoice_credit_receipts',public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.invoice_credit_receipts LIMIT 100001) x
  ) all_entries LIMIT 100001
 ), hashes AS (SELECT kind,encode(hash,'hex') AS h FROM entries)
 SELECT count(*),CASE WHEN count(*)<=100000 THEN encode(public.digest(convert_to('profitpilot-sensitive-recovery-v21:'||coalesce(string_agg(kind||':'||h,',' ORDER BY kind COLLATE "C",h COLLATE "C"),''),'UTF8'),'sha256'),'hex') END
 INTO total,result FROM hashes;
 IF total>100000 OR result IS NULL THEN RAISE EXCEPTION 'Sensitive recovery inventory exceeds reviewed capacity' USING ERRCODE='54000'; END IF;
 RETURN result;
END $fn$;
REVOKE ALL ON FUNCTION private.sensitive_recovery_fingerprint() FROM PUBLIC,profitpilot_app;
CREATE OR REPLACE FUNCTION private.verify_security_catalog() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT digest=private.security_catalog_digest() FROM private.security_catalog_baseline WHERE revision=80),false)
$fn$;
INSERT INTO private.security_catalog_baseline(singleton,revision,digest) VALUES(true,80,private.security_catalog_digest());
COMMIT;

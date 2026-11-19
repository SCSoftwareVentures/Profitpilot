-- Synthetic direct site supplier cost intake. Reuse immutable reviewed invoice
-- materialization; direction and candidate classification are bound to scope.
-- No supplier identity, automatic allocation, credits or payment authority.
BEGIN;
DO $check$ BEGIN
 IF private.verify_security_catalog() IS DISTINCT FROM true THEN RAISE EXCEPTION 'Prior catalog does not verify'; END IF;
END $check$;
CREATE OR REPLACE FUNCTION private.invoice_intake_preview_data(p_tenant uuid,p_batch uuid,p_order uuid,p_total text,p_count integer,p_evidence text)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog SET timezone='UTC' AS $fn$
DECLARE b public.import_batches%ROWTYPE; m private.quarantine_manifests%ROWTYPE; r record; v public.contract_versions%ROWTYPE;
 src jsonb; mapped jsonb:='[]'::jsonb; payloads jsonb; actual_count integer; total numeric:=0;
 c uuid; s uuid; customer uuid; starts date; ends date; invoice_day date; price numeric; ref text; invoice_groups jsonb:='{}'::jsonb; header jsonb; result jsonb;
BEGIN
 IF p_total IS NULL OR p_total !~ '^(0|[1-9][0-9]{0,11})[.][0-9]{2}$' OR p_count IS NULL OR p_count NOT BETWEEN 1 AND 200
 OR p_evidence IS NULL OR p_evidence !~ '^[a-f0-9]{64}$' OR p_evidence=repeat('0',64) THEN RAISE EXCEPTION 'Invalid invoice controls' USING ERRCODE='23514'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('profitpilot-workspace:'||p_tenant::text,0));
 SELECT * INTO b FROM public.import_batches WHERE tenant_id=p_tenant AND id=p_batch FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Invoice source unavailable' USING ERRCODE='42501'; END IF;
 IF b.status<>'review' OR b.source_type NOT IN ('customer_invoice','supplier_invoice') OR b.source_period_start IS NULL OR b.source_period_end IS NULL
 OR NOT isfinite(b.source_period_start) OR NOT isfinite(b.source_period_end) OR b.source_period_end<b.source_period_start OR b.source_period_end-b.source_period_start>366
 OR EXISTS(SELECT 1 FROM private.import_disposal_controls WHERE tenant_id=p_tenant AND batch_id=p_batch AND hold_active)
 OR EXISTS(SELECT 1 FROM private.import_disposal_tombstones WHERE tenant_id=p_tenant AND batch_id=p_batch)
 OR EXISTS(SELECT 1 FROM private.invoice_intake_receipts WHERE tenant_id=p_tenant AND batch_id=p_batch)
 OR NOT EXISTS(SELECT 1 FROM private.quarantine_promotions q JOIN private.quarantined_files f USING(tenant_id,batch_id)
 WHERE q.tenant_id=p_tenant AND q.batch_id=p_batch AND q.state='promoted' AND q.approval_session_digest IS NOT NULL
 AND f.file_sha256=b.file_sha256 AND f.content_state='validated' AND f.scan_state IN ('clean','disposed'))
 THEN RAISE EXCEPTION 'Invoice batch not eligible for reviewed materialization' USING ERRCODE='23514'; END IF;
 SELECT * INTO m FROM private.quarantine_manifests WHERE tenant_id=p_tenant AND batch_id=p_batch;
 IF NOT FOUND OR m.row_count<>p_count THEN RAISE EXCEPTION 'Invoice manifest count mismatch' USING ERRCODE='23514'; END IF;
 SELECT count(*)::integer,jsonb_agg(payload ORDER BY row_number) INTO actual_count,payloads FROM public.raw_import_rows WHERE tenant_id=p_tenant AND batch_id=p_batch;
 IF actual_count<>p_count OR private.quarantine_rows_digest(payloads) IS DISTINCT FROM m.rows_hash
 OR (SELECT count(DISTINCT payload) FROM public.raw_import_rows WHERE tenant_id=p_tenant AND batch_id=p_batch)<>p_count
 THEN RAISE EXCEPTION 'Invoice source hash or duplicate line mismatch' USING ERRCODE='23514'; END IF;
 FOR r IN SELECT id,row_number,payload FROM public.raw_import_rows WHERE tenant_id=p_tenant AND batch_id=p_batch ORDER BY row_number LOOP
  src:=r.payload;
  IF NOT private.invoice_import_payload_safe(src) OR NOT(src ?& ARRAY['invoice_id','site','date','amount','customer_id','contract_id','site_id','service_period_start','service_period_end','currency','tax_basis'])
  OR src->>'invoice_id' !~ '^[A-Za-z][A-Za-z0-9 ._-]{0,79}$' OR btrim(src->>'invoice_id')<>src->>'invoice_id'
  OR src->>'currency'<>'AUD' OR src->>'tax_basis' NOT IN ('gst_inclusive','gst_exclusive','no_gst')
  OR src->>'amount' !~ '^(0|[1-9][0-9]{0,11})[.][0-9]{2}$' OR src->>'amount'='0.00'
  OR EXISTS(SELECT 1 FROM unnest(ARRAY[src->>'customer_id',src->>'contract_id',src->>'site_id']) x WHERE x !~ '^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$')
  OR EXISTS(SELECT 1 FROM unnest(ARRAY[src->>'date',src->>'service_period_start',src->>'service_period_end']) x WHERE x !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$')
  THEN RAISE EXCEPTION 'Invoice source requires complete canonical mapping fields' USING ERRCODE='23514'; END IF;
  c:=(src->>'contract_id')::uuid;s:=(src->>'site_id')::uuid;customer:=(src->>'customer_id')::uuid;
  starts:=(src->>'service_period_start')::date;ends:=(src->>'service_period_end')::date;invoice_day:=(src->>'date')::date;
  IF starts::text<>src->>'service_period_start' OR ends::text<>src->>'service_period_end' OR invoice_day::text<>src->>'date'
  OR starts>ends OR starts<b.source_period_start OR ends>b.source_period_end
  THEN RAISE EXCEPTION 'Invoice service period not within batch period' USING ERRCODE='23514'; END IF;
  IF NOT EXISTS(SELECT 1 FROM private.workspace_records cr JOIN private.workspace_records sr ON sr.tenant_id=cr.tenant_id AND sr.kind='site' AND sr.id=s AND sr.parent_id=cr.parent_id
   JOIN private.workspace_records cu ON cu.tenant_id=cr.tenant_id AND cu.kind='customer' AND cu.id=customer AND cu.parent_id=cr.parent_id
   JOIN private.workspace_records a ON a.tenant_id=cr.tenant_id AND a.kind='contract_site' AND a.parent_id=cr.id AND a.related_id=sr.id
   JOIN public.contracts pc ON pc.tenant_id=cr.tenant_id AND pc.id=cr.id AND pc.status='active'
   JOIN public.sites ps ON ps.tenant_id=sr.tenant_id AND ps.id=sr.id AND ps.status='active'
   WHERE cr.tenant_id=p_tenant AND cr.kind='contract' AND cr.id=c AND cr.related_id=customer AND sr.label=src->>'site')
  THEN RAISE EXCEPTION 'Invoice customer, contract or site scope unavailable' USING ERRCODE='23514'; END IF;
  SELECT cv.* INTO v FROM public.contract_versions cv JOIN private.workspace_version_receipts w ON w.tenant_id=cv.tenant_id AND w.version_id=cv.id
  WHERE cv.tenant_id=p_tenant AND cv.contract_id=c AND cv.effective_from<=starts AND cv.effective_to>=ends AND cv.currency='AUD' AND cv.tax_basis=src->>'tax_basis';
  IF NOT FOUND THEN RAISE EXCEPTION 'Invoice baseline basis or period mismatch' USING ERRCODE='23514'; END IF;
  IF EXISTS(SELECT 1 FROM public.invoice_lines WHERE tenant_id=p_tenant AND source_row_id=r.id)
  OR EXISTS(SELECT 1 FROM public.invoices WHERE tenant_id=p_tenant AND direction=(CASE b.source_type WHEN 'supplier_invoice' THEN 'supplier' ELSE 'customer' END) AND lower(invoice_number)=lower(src->>'invoice_id'))
  THEN RAISE EXCEPTION 'Invoice source already materialized' USING ERRCODE='23514'; END IF;
  ref:=src->>'invoice_id';price:=(src->>'amount')::numeric;total:=total+price;
  header:=jsonb_build_object('invoiceRef',ref,'customerId',customer,'date',invoice_day,'taxBasis',src->>'tax_basis');
  IF invoice_groups ? lower(ref) AND invoice_groups->lower(ref) IS DISTINCT FROM header THEN RAISE EXCEPTION 'Inconsistent invoice header' USING ERRCODE='23514'; END IF;
  invoice_groups:=invoice_groups||jsonb_build_object(lower(ref),header);
  mapped:=mapped||jsonb_build_array(jsonb_build_object('rawRowId',r.id,'rowNumber',r.row_number,'invoiceRef',ref,'customerId',customer,'contractId',c,'siteId',s,
  'invoiceDate',invoice_day,'periodStart',starts,'periodEnd',ends,'amount',src->>'amount','taxBasis',src->>'tax_basis','baselineId',v.id));
 END LOOP;
 IF total<>p_total::numeric THEN RAISE EXCEPTION 'Invoice total does not reconcile' USING ERRCODE='23514'; END IF;
 result:=jsonb_build_object('tenantId',p_tenant,'batchId',p_batch,'orderId',p_order,'fileSha256',b.file_sha256,'manifestDigest',m.rows_hash,'periodStart',b.source_period_start,'periodEnd',b.source_period_end,
 'currency','AUD','controlTotal',p_total,'rowCount',p_count,'evidenceDigest',p_evidence,'lines',mapped,'invoiceCount',(SELECT count(*) FROM jsonb_object_keys(invoice_groups)));
 IF b.source_type='supplier_invoice' THEN
  -- customerId identifies the beneficiary contract customer, NOT the supplier.
  -- Supplier invoice references must be tenant-unique opaque aliases.
  result:=result||jsonb_build_object('sourceType','supplier_invoice','costClassification','direct_site_candidate','supplierIdentityVerified',false);
 END IF;
 RETURN result||jsonb_build_object('scopeDigest',encode(public.digest(convert_to(jsonb_build_array('profitpilot-invoice-intake-v1',result)::text,'UTF8'),'sha256'),'hex'));
END $fn$;
CREATE OR REPLACE FUNCTION private.api_invoice_intake_step(
 p_tenant uuid,p_batch uuid,p_order uuid,p_total text,p_count integer,p_evidence text,p_scope text,p_step text,
 p_auth bigint,p_iat bigint,p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE actor uuid; reviewer uuid; preview jsonb; q private.invoice_intake_orders%ROWTYPE; line jsonb; group_row record; i uuid; l uuid; m uuid;
BEGIN
 actor:=private.security_work_actor(p_tenant,p_order,'privileged_operation',p_scope,p_step,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 IF p_step<>'request' THEN
  SELECT * INTO q FROM private.invoice_intake_orders WHERE tenant_id=p_tenant AND batch_id=p_batch AND order_id=p_order AND scope_digest=p_scope;
  IF NOT FOUND THEN RAISE EXCEPTION 'Invoice review unavailable' USING ERRCODE='42501'; END IF;
 END IF;
 IF p_step='reject' THEN
  IF q.preview->>'controlTotal' IS DISTINCT FROM p_total OR (q.preview->>'rowCount')::integer IS DISTINCT FROM p_count OR q.preview->>'evidenceDigest' IS DISTINCT FROM p_evidence THEN RAISE EXCEPTION 'Invoice review controls changed' USING ERRCODE='42501'; END IF;
 ELSE
  preview:=private.invoice_intake_preview_data(p_tenant,p_batch,p_order,p_total,p_count,p_evidence);
  IF preview->>'scopeDigest' IS DISTINCT FROM p_scope OR (p_step<>'request' AND preview IS DISTINCT FROM q.preview) THEN RAISE EXCEPTION 'Invoice review scope changed' USING ERRCODE='42501'; END IF;
 END IF;
 IF p_step='request' AND (SELECT count(*) FROM private.invoice_intake_orders WHERE tenant_id=p_tenant AND batch_id=p_batch)>=20 THEN RAISE EXCEPTION 'Invoice review capacity exceeded' USING ERRCODE='54000'; END IF;
 PERFORM private.record_security_work(p_tenant,p_order,'privileged_operation',p_scope,p_step,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 IF p_step='request' THEN
  INSERT INTO private.invoice_intake_orders(tenant_id,batch_id,order_id,scope_digest,preview) VALUES(p_tenant,p_batch,p_order,p_scope,preview);
 ELSIF p_step='consume' THEN
  SELECT decided_by INTO reviewer FROM private.security_work_decisions WHERE tenant_id=p_tenant AND order_id=p_order;
  INSERT INTO private.invoice_intake_receipts(tenant_id,batch_id,order_id) VALUES(p_tenant,p_batch,p_order);
  FOR group_row IN SELECT value->>'invoiceRef' AS ref,min(value->>'invoiceDate') AS invoice_day,min(value->>'taxBasis') AS tax,sum((value->>'amount')::numeric) AS total
   FROM jsonb_array_elements(preview->'lines') GROUP BY value->>'invoiceRef' LOOP
   i:=gen_random_uuid();
   INSERT INTO public.invoices(id,tenant_id,direction,invoice_number,invoice_date,total_amount,currency,tax_basis,source_ref)
   VALUES(i,p_tenant,CASE preview->>'sourceType' WHEN 'supplier_invoice' THEN 'supplier' ELSE 'customer' END,group_row.ref,group_row.invoice_day::date,group_row.total,'AUD',group_row.tax,'reviewed-invoice-intake-v1');
   FOR line IN SELECT value FROM jsonb_array_elements(preview->'lines') WHERE value->>'invoiceRef'=group_row.ref ORDER BY (value->>'rowNumber')::integer LOOP
    l:=gen_random_uuid();m:=gen_random_uuid();
    INSERT INTO public.invoice_lines(id,tenant_id,invoice_id,line_number,description,amount,source_row_id)
    VALUES(l,p_tenant,i,(line->>'rowNumber')::integer,CASE preview->>'sourceType' WHEN 'supplier_invoice' THEN 'Reviewed supplier site cost line' ELSE 'Reviewed source service line' END,(line->>'amount')::numeric,(line->>'rawRowId')::uuid);
    INSERT INTO public.match_reviews(id,tenant_id,invoice_line_id,contract_id,site_id,service_period_start,service_period_end,confidence,decision,evidence,reviewer_id,reviewed_at)
    VALUES(m,p_tenant,l,(line->>'contractId')::uuid,(line->>'siteId')::uuid,(line->>'periodStart')::date,(line->>'periodEnd')::date,'HIGH','confirmed',
    jsonb_build_object('orderId',p_order,'scopeDigest',p_scope,'baselineId',line->>'baselineId','evidenceDigest',p_evidence)||CASE preview->>'sourceType' WHEN 'supplier_invoice' THEN jsonb_build_object('sourceType','supplier_invoice','costClassification','direct_site_candidate','supplierIdentityVerified',false) ELSE '{}'::jsonb END,reviewer,clock_timestamp());
    -- Link after insertion; immutable guards below permit only construction in this transaction.
    INSERT INTO private.invoice_intake_lines(tenant_id,batch_id,raw_row_id,invoice_id,line_id,match_id,baseline_id)
    VALUES(p_tenant,p_batch,(line->>'rawRowId')::uuid,i,l,m,(line->>'baselineId')::uuid);
   END LOOP;
  END LOOP;
  UPDATE public.import_batches SET status='accepted' WHERE tenant_id=p_tenant AND id=p_batch;
  INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,metadata)
  VALUES(p_tenant,actor,'invoice_intake_accepted','import_batch',p_batch,jsonb_build_object('rowCount',p_count,'scopeDigest',p_scope));
 END IF;
 PERFORM private.sensitive_api_fresh(p_auth,p_expires);
 RETURN private.invoice_intake_summary(p_tenant,p_batch,p_order);
END $fn$;
CREATE OR REPLACE FUNCTION private.verify_security_catalog()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT digest=private.security_catalog_digest() FROM private.security_catalog_baseline WHERE revision=70),false)
$fn$;
INSERT INTO private.security_catalog_baseline(singleton,revision,digest) VALUES(true,70,private.security_catalog_digest());
COMMIT;

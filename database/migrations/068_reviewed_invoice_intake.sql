-- Reviewed exact materialization of promoted customer invoice source rows.
BEGIN;
DO $check$ BEGIN
 IF private.verify_security_catalog() IS DISTINCT FROM true THEN RAISE EXCEPTION 'Prior catalog does not verify'; END IF;
END $check$;
CREATE OR REPLACE FUNCTION private.sensitive_api_actor(
 p_tenant uuid,p_target uuid,p_action text,p_scope text,p_auth bigint,p_iat bigint,
 p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text)
RETURNS uuid LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE actor uuid; actor_role text; subject text; now_s bigint; key_bytes bytea; expected text;
BEGIN
 IF p_tenant IS NULL OR p_target IS NULL OR private.current_tenant_id() IS DISTINCT FROM p_tenant
 OR private.lock_tenant_available(p_tenant) IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'Sensitive operation denied' USING ERRCODE='42501'; END IF;
 subject:=nullif(current_setting('app.tenant_subject',true),'');
 SELECT u.id,m.role INTO actor,actor_role FROM public.users u JOIN public.tenant_memberships m ON m.user_id=u.id
 WHERE u.auth_subject=subject AND u.status='active' AND m.tenant_id=p_tenant AND m.status='active' FOR SHARE OF u,m;
 IF NOT FOUND THEN RAISE EXCEPTION 'Sensitive operation denied' USING ERRCODE='42501'; END IF;
 IF p_action IS NULL OR p_action NOT IN ('payroll_submit','payroll_read','account_read','account_correct_email','invoice_disposal_preview','privacy_case_request','privacy_case_status','privacy_case_intake','privacy_case_acknowledge','privacy_case_resolve','privacy_case_refuse','payroll_correction_preview','payroll_correction_status','privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status','privacy_key_revoke','payroll_intake_preview','payroll_intake_status','payroll_allocation_build','payroll_allocation_status','workspace_create','workspace_read','workspace_version_status','workspace_job_write','workspace_job_read','invoice_intake_preview','invoice_intake_status')
 OR (p_action IN ('privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status','privacy_key_revoke','payroll_intake_preview','payroll_intake_status','payroll_allocation_build','payroll_allocation_status','workspace_create','workspace_read','workspace_version_status','workspace_job_write','workspace_job_read','invoice_intake_preview','invoice_intake_status') AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('payroll_correction_preview','payroll_correction_status') AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('privacy_case_intake','privacy_case_acknowledge','privacy_case_resolve','privacy_case_refuse') AND actor_role NOT IN ('owner','admin'))
 OR (p_action='payroll_submit' AND actor_role NOT IN ('owner','admin','analyst'))
 OR (p_action='payroll_read' AND actor_role NOT IN ('owner','admin','reviewer'))
 OR (p_action='invoice_disposal_preview' AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('account_read','account_correct_email') AND p_target<>p_tenant)
 THEN RAISE EXCEPTION 'Sensitive operation denied' USING ERRCODE='42501'; END IF;
 now_s:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 IF p_scope IS NULL OR p_scope !~ '^[a-f0-9]{64}$'
 OR (p_action IN ('account_correct_email','privacy_case_request','privacy_case_intake','privacy_case_resolve','privacy_case_refuse','payroll_correction_preview','privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status','privacy_key_revoke','payroll_intake_preview','payroll_intake_status','payroll_allocation_build','payroll_allocation_status','workspace_create','workspace_read','workspace_version_status','workspace_job_write','workspace_job_read','invoice_intake_preview','invoice_intake_status') AND p_scope=repeat('0',64))
 OR (p_action NOT IN ('account_correct_email','privacy_case_request','privacy_case_intake','privacy_case_resolve','privacy_case_refuse','payroll_correction_preview','privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status','privacy_key_revoke','payroll_intake_preview','payroll_intake_status','payroll_allocation_build','payroll_allocation_status','workspace_create','workspace_read','workspace_version_status','workspace_job_write','workspace_job_read','invoice_intake_preview','invoice_intake_status') AND p_scope<>repeat('0',64))
 OR p_auth IS NULL OR p_auth<=0 OR p_auth<now_s-300 OR p_auth>now_s+5
 OR p_iat IS NULL OR p_iat<now_s-905 OR p_iat>now_s+5 OR p_auth>p_iat+5
 OR p_session IS NULL OR p_session !~ '^[a-f0-9]{64}$'
 OR p_expires IS NULL OR p_expires<now_s OR p_expires>now_s+30
 OR p_nonce IS NULL OR p_nonce !~ '^[a-f0-9]{32}$'
 OR p_key IS NULL OR p_key !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$'
 OR p_signature IS NULL OR p_signature !~ '^[a-f0-9]{64}$'
 THEN RAISE EXCEPTION 'Sensitive operation denied' USING ERRCODE='42501'; END IF;
 SELECT secret INTO key_bytes FROM private.tenant_context_keys WHERE key_id=p_key AND active FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Sensitive operation denied' USING ERRCODE='42501'; END IF;
 expected:=encode(public.hmac(convert_to('profitpilot-sensitive-api-v1'||E'\n'||p_tenant||E'\n'||p_target||E'\n'||p_action||E'\n'||p_scope||E'\n'||subject||E'\n'||p_auth||E'\n'||p_iat||E'\n'||p_session||E'\n'||p_expires||E'\n'||p_nonce||E'\n'||p_key,'UTF8'),key_bytes,'sha256'),'hex');
 IF expected IS DISTINCT FROM p_signature
 OR EXISTS(SELECT 1 FROM private.identity_session_cutoffs WHERE user_id=actor AND revoked_through>=p_auth)
 OR EXISTS(SELECT 1 FROM private.revoked_identity_sessions WHERE user_id=actor AND session_digest=p_session)
 THEN RAISE EXCEPTION 'Sensitive operation denied' USING ERRCODE='42501'; END IF;
 RETURN actor;
END $fn$;










CREATE TABLE private.invoice_intake_orders(
 tenant_id uuid NOT NULL,batch_id uuid NOT NULL,order_id uuid NOT NULL,
 scope_digest text NOT NULL CHECK(scope_digest ~ '^[a-f0-9]{64}$'),
 preview jsonb NOT NULL CHECK(octet_length(preview::text)<=150000),
 PRIMARY KEY(tenant_id,order_id),UNIQUE(tenant_id,batch_id,order_id),
 FOREIGN KEY(tenant_id,batch_id) REFERENCES public.import_batches(tenant_id,id),
 FOREIGN KEY(tenant_id,order_id) REFERENCES private.security_work_orders(tenant_id,id)
);
CREATE TABLE private.invoice_intake_receipts(
 tenant_id uuid NOT NULL,batch_id uuid NOT NULL,order_id uuid NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,batch_id),UNIQUE(tenant_id,order_id),
 FOREIGN KEY(tenant_id,batch_id,order_id) REFERENCES private.invoice_intake_orders(tenant_id,batch_id,order_id),
 FOREIGN KEY(tenant_id,order_id) REFERENCES private.security_work_consumptions(tenant_id,order_id)
);
CREATE TABLE private.invoice_intake_lines(
 tenant_id uuid NOT NULL,batch_id uuid NOT NULL,raw_row_id uuid NOT NULL,invoice_id uuid NOT NULL,line_id uuid NOT NULL,match_id uuid NOT NULL REFERENCES public.match_reviews(id),
 baseline_id uuid NOT NULL REFERENCES public.contract_versions(id),
 PRIMARY KEY(tenant_id,raw_row_id),UNIQUE(tenant_id,line_id),UNIQUE(tenant_id,match_id),
 FOREIGN KEY(tenant_id,batch_id) REFERENCES private.invoice_intake_receipts(tenant_id,batch_id),
 FOREIGN KEY(tenant_id,raw_row_id) REFERENCES public.raw_import_rows(tenant_id,id),
 FOREIGN KEY(tenant_id,invoice_id) REFERENCES public.invoices(tenant_id,id),
 FOREIGN KEY(tenant_id,line_id) REFERENCES public.invoice_lines(tenant_id,id)
);
CREATE INDEX invoice_intake_lines_invoice ON private.invoice_intake_lines(tenant_id,invoice_id);
REVOKE ALL ON private.invoice_intake_orders,private.invoice_intake_receipts,private.invoice_intake_lines FROM PUBLIC,profitpilot_app;
CREATE TRIGGER invoice_intake_orders_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON private.invoice_intake_orders FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();
CREATE TRIGGER invoice_intake_receipts_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON private.invoice_intake_receipts FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();
CREATE TRIGGER invoice_intake_lines_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON private.invoice_intake_lines FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();

CREATE FUNCTION private.invoice_intake_preview_data(p_tenant uuid,p_batch uuid,p_order uuid,p_total text,p_count integer,p_evidence text)
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
 IF b.status<>'review' OR b.source_type<>'customer_invoice' OR b.source_period_start IS NULL OR b.source_period_end IS NULL
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
  OR EXISTS(SELECT 1 FROM public.invoices WHERE tenant_id=p_tenant AND direction='customer' AND lower(invoice_number)=lower(src->>'invoice_id'))
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
 RETURN result||jsonb_build_object('scopeDigest',encode(public.digest(convert_to(jsonb_build_array('profitpilot-invoice-intake-v1',result)::text,'UTF8'),'sha256'),'hex'));
END $fn$;

CREATE FUNCTION private.api_invoice_intake_preview(
 p_tenant uuid,p_order uuid,p_action text,p_scope text,p_auth bigint,p_iat bigint,p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text,
 p_batch uuid,p_total text,p_count integer,p_evidence text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE actor uuid; result jsonb;
BEGIN
 IF p_action IS DISTINCT FROM 'invoice_intake_preview' OR p_scope IS DISTINCT FROM encode(public.digest(convert_to('invoice-intake-preview-v1'||E'\n'||p_batch||E'\n'||p_total||E'\n'||p_count||E'\n'||p_evidence,'UTF8'),'sha256'),'hex')
 THEN RAISE EXCEPTION 'Invoice preview denied' USING ERRCODE='42501'; END IF;
 actor:=private.sensitive_api_actor(p_tenant,p_order,p_action,p_scope,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 result:=private.invoice_intake_preview_data(p_tenant,p_batch,p_order,p_total,p_count,p_evidence);
 PERFORM private.sensitive_api_fresh(p_auth,p_expires);
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id) VALUES(p_tenant,actor,'invoice_intake_previewed','import_batch',p_batch);
 RETURN result||jsonb_build_object('status','pending_independent_review');
END $fn$;
CREATE FUNCTION private.invoice_intake_summary(p_tenant uuid,p_batch uuid,p_order uuid)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE result jsonb;
BEGIN
 SELECT o.preview||jsonb_build_object('status',CASE WHEN r.order_id=o.order_id THEN 'accepted' WHEN r.order_id IS NOT NULL THEN 'superseded'
 WHEN d.decision='rejected' THEN 'rejected' WHEN d.expires_at<=clock_timestamp() OR (d.order_id IS NULL AND w.requested_at+interval '24 hours'<=clock_timestamp()) THEN 'expired'
 WHEN d.decision='approved' THEN 'approved_pending_record' ELSE 'requested' END)
 INTO result FROM private.invoice_intake_orders o JOIN private.security_work_orders w ON w.tenant_id=o.tenant_id AND w.id=o.order_id
 LEFT JOIN private.security_work_decisions d ON d.tenant_id=o.tenant_id AND d.order_id=o.order_id
 LEFT JOIN private.invoice_intake_receipts r ON r.tenant_id=o.tenant_id AND r.batch_id=o.batch_id
 WHERE o.tenant_id=p_tenant AND o.batch_id=p_batch AND o.order_id=p_order;
 IF result IS NULL THEN RAISE EXCEPTION 'Invoice review unavailable' USING ERRCODE='42501'; END IF;RETURN result;
END $fn$;
CREATE FUNCTION private.api_invoice_intake_status(
 p_tenant uuid,p_order uuid,p_action text,p_scope text,p_auth bigint,p_iat bigint,p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text,p_batch uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE result jsonb;
BEGIN
 IF p_action IS DISTINCT FROM 'invoice_intake_status' OR p_scope IS DISTINCT FROM encode(public.digest(convert_to('invoice-intake-status-v1'||E'\n'||p_batch,'UTF8'),'sha256'),'hex')
 THEN RAISE EXCEPTION 'Invoice review status denied' USING ERRCODE='42501'; END IF;
 PERFORM private.sensitive_api_actor(p_tenant,p_order,p_action,p_scope,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 result:=private.invoice_intake_summary(p_tenant,p_batch,p_order);
 PERFORM private.sensitive_api_fresh(p_auth,p_expires);RETURN result;
END $fn$;
CREATE FUNCTION private.api_invoice_intake_step(
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
   VALUES(i,p_tenant,'customer',group_row.ref,group_row.invoice_day::date,group_row.total,'AUD',group_row.tax,'reviewed-invoice-intake-v1');
   FOR line IN SELECT value FROM jsonb_array_elements(preview->'lines') WHERE value->>'invoiceRef'=group_row.ref ORDER BY (value->>'rowNumber')::integer LOOP
    l:=gen_random_uuid();m:=gen_random_uuid();
    INSERT INTO public.invoice_lines(id,tenant_id,invoice_id,line_number,description,amount,source_row_id)
    VALUES(l,p_tenant,i,(line->>'rowNumber')::integer,'Reviewed source service line',(line->>'amount')::numeric,(line->>'rawRowId')::uuid);
    INSERT INTO public.match_reviews(id,tenant_id,invoice_line_id,contract_id,site_id,service_period_start,service_period_end,confidence,decision,evidence,reviewer_id,reviewed_at)
    VALUES(m,p_tenant,l,(line->>'contractId')::uuid,(line->>'siteId')::uuid,(line->>'periodStart')::date,(line->>'periodEnd')::date,'HIGH','confirmed',
    jsonb_build_object('orderId',p_order,'scopeDigest',p_scope,'baselineId',line->>'baselineId','evidenceDigest',p_evidence),reviewer,clock_timestamp());
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
-- Freeze materialized facts and prohibit new lines or matches against an
-- accepted batch. During construction the batch remains review; the runtime
-- role has no INSERT on invoices, invoice_lines or match_reviews.
CREATE FUNCTION private.guard_reviewed_invoice_intake()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE t uuid; x uuid; linked boolean:=false;
BEGIN
 IF TG_OP='INSERT' THEN t:=NEW.tenant_id; ELSE t:=OLD.tenant_id; END IF;
 CASE TG_TABLE_NAME
 WHEN 'invoices' THEN
  IF TG_OP<>'INSERT' THEN linked:=EXISTS(SELECT 1 FROM private.invoice_intake_lines WHERE tenant_id=t AND invoice_id=OLD.id); END IF;
 WHEN 'invoice_lines' THEN
  IF TG_OP='INSERT' THEN linked:=EXISTS(SELECT 1 FROM private.invoice_intake_lines l JOIN public.import_batches b USING(tenant_id,batch_id) WHERE l.tenant_id=t AND b.status='accepted' AND (l.invoice_id=NEW.invoice_id OR l.raw_row_id=NEW.source_row_id));
  ELSE linked:=EXISTS(SELECT 1 FROM private.invoice_intake_lines WHERE tenant_id=t AND (line_id=OLD.id OR invoice_id=OLD.invoice_id)); END IF;
 WHEN 'match_reviews' THEN
  IF TG_OP='INSERT' THEN linked:=EXISTS(SELECT 1 FROM private.invoice_intake_lines WHERE tenant_id=t AND line_id=NEW.invoice_line_id);
  ELSE linked:=EXISTS(SELECT 1 FROM private.invoice_intake_lines WHERE tenant_id=t AND (match_id=OLD.id OR line_id=OLD.invoice_line_id)); END IF;
 WHEN 'raw_import_rows' THEN
  IF TG_OP='INSERT' THEN x:=NEW.batch_id;ELSE x:=OLD.batch_id;END IF;
  linked:=EXISTS(SELECT 1 FROM private.invoice_intake_receipts WHERE tenant_id=t AND batch_id=x);
 WHEN 'import_batches' THEN
  linked:=OLD.status='accepted' AND EXISTS(SELECT 1 FROM private.invoice_intake_receipts WHERE tenant_id=t AND batch_id=OLD.id);
 END CASE;
 IF linked THEN RAISE EXCEPTION 'Reviewed invoice evidence is immutable' USING ERRCODE='55000'; END IF;
 -- Prevent moving an unmanaged row into an already managed identity.
 IF TG_OP='UPDATE' THEN
  CASE TG_TABLE_NAME
  WHEN 'invoice_lines' THEN
   IF EXISTS(SELECT 1 FROM private.invoice_intake_lines WHERE tenant_id=NEW.tenant_id AND (invoice_id=NEW.invoice_id OR raw_row_id=NEW.source_row_id))
   THEN RAISE EXCEPTION 'Reviewed invoice evidence is immutable' USING ERRCODE='55000'; END IF;
  WHEN 'match_reviews' THEN
   IF EXISTS(SELECT 1 FROM private.invoice_intake_lines WHERE tenant_id=NEW.tenant_id AND line_id=NEW.invoice_line_id)
   THEN RAISE EXCEPTION 'Reviewed invoice evidence is immutable' USING ERRCODE='55000'; END IF;
  WHEN 'raw_import_rows' THEN
   IF EXISTS(SELECT 1 FROM private.invoice_intake_receipts WHERE tenant_id=NEW.tenant_id AND batch_id=NEW.batch_id)
   THEN RAISE EXCEPTION 'Reviewed invoice evidence is immutable' USING ERRCODE='55000'; END IF;
  ELSE NULL;
  END CASE;
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;RETURN NEW;
END $fn$;
CREATE TRIGGER reviewed_invoice_header_guard BEFORE UPDATE OR DELETE ON public.invoices FOR EACH ROW EXECUTE FUNCTION private.guard_reviewed_invoice_intake();
CREATE TRIGGER reviewed_invoice_line_guard BEFORE INSERT OR UPDATE OR DELETE ON public.invoice_lines FOR EACH ROW EXECUTE FUNCTION private.guard_reviewed_invoice_intake();
CREATE TRIGGER reviewed_invoice_match_guard BEFORE INSERT OR UPDATE OR DELETE ON public.match_reviews FOR EACH ROW EXECUTE FUNCTION private.guard_reviewed_invoice_intake();
CREATE TRIGGER reviewed_invoice_raw_guard BEFORE INSERT OR UPDATE OR DELETE ON public.raw_import_rows FOR EACH ROW EXECUTE FUNCTION private.guard_reviewed_invoice_intake();
CREATE TRIGGER reviewed_invoice_batch_guard BEFORE UPDATE OR DELETE ON public.import_batches FOR EACH ROW EXECUTE FUNCTION private.guard_reviewed_invoice_intake();
REVOKE ALL ON FUNCTION private.invoice_intake_preview_data(uuid,uuid,uuid,text,integer,text),private.invoice_intake_summary(uuid,uuid,uuid),private.guard_reviewed_invoice_intake() FROM PUBLIC,profitpilot_app;
REVOKE ALL ON FUNCTION private.api_invoice_intake_preview(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text,uuid,text,integer,text),
 private.api_invoice_intake_status(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text,uuid),
 private.api_invoice_intake_step(uuid,uuid,uuid,text,integer,text,text,text,bigint,bigint,text,bigint,text,text,text) FROM PUBLIC,profitpilot_app;
GRANT EXECUTE ON FUNCTION private.api_invoice_intake_preview(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text,uuid,text,integer,text),
 private.api_invoice_intake_status(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text,uuid),
 private.api_invoice_intake_step(uuid,uuid,uuid,text,integer,text,text,text,bigint,bigint,text,bigint,text,text,text) TO profitpilot_app;
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
  ) all_entries LIMIT 100001
 ), hashes AS (SELECT kind,encode(hash,'hex') AS h FROM entries)
 SELECT count(*),CASE WHEN count(*)<=100000 THEN encode(public.digest(convert_to('profitpilot-sensitive-recovery-v15:'||coalesce(string_agg(kind||':'||h,',' ORDER BY kind COLLATE "C",h COLLATE "C"),''),'UTF8'),'sha256'),'hex') END
 INTO total,result FROM hashes;
 IF total>100000 OR result IS NULL THEN RAISE EXCEPTION 'Sensitive recovery inventory exceeds reviewed capacity' USING ERRCODE='54000'; END IF;
 RETURN result;
END $fn$;

REVOKE ALL ON FUNCTION private.sensitive_recovery_fingerprint() FROM PUBLIC,profitpilot_app;
CREATE OR REPLACE FUNCTION private.verify_security_catalog()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT digest=private.security_catalog_digest() FROM private.security_catalog_baseline WHERE revision=68),false)
$fn$;
INSERT INTO private.security_catalog_baseline(singleton,revision,digest) VALUES(true,68,private.security_catalog_digest());
COMMIT;

-- Distinct business-wide overhead classification; explicit site, contract,
-- baseline, exact cents, one active source chain. No report inclusion yet.
BEGIN;
DO $check$ BEGIN IF private.verify_security_catalog() IS DISTINCT FROM true THEN RAISE EXCEPTION 'Prior catalog does not verify'; END IF; END $check$;
ALTER TABLE private.supplier_cost_orders DROP CONSTRAINT supplier_cost_orders_classification_check,
 ADD CONSTRAINT supplier_cost_orders_classification_check CHECK(classification IN ('direct_site','overhead_pending','business_overhead_pending','payroll_overlap','excluded'));
ALTER TABLE private.shared_cost_orders DROP CONSTRAINT shared_cost_orders_source_kind_check,
 ADD CONSTRAINT shared_cost_orders_source_kind_check CHECK(source_kind IN ('payroll','overhead','business_overhead'));
CREATE OR REPLACE FUNCTION private.api_supplier_cost_step(t uuid,b uuid,o uuid,intake text,classification text,evidence text,scope text,step text,
 auth bigint,iat bigint,session_digest text,expiry bigint,nonce text,key_id text,signature text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE actor uuid; accepted_scope text; q private.supplier_cost_orders%ROWTYPE; n integer;
BEGIN
 actor:=private.security_work_actor(t,o,'privileged_operation',scope,step,auth,iat,session_digest,expiry,nonce,key_id,signature);
 IF b IS NULL OR intake IS NULL OR intake !~ '^[a-f0-9]{64}$' OR classification IS NULL OR classification NOT IN ('direct_site','overhead_pending','business_overhead_pending','payroll_overlap','excluded')
 OR evidence IS NULL OR evidence !~ '^[a-f0-9]{64}$' OR evidence=repeat('0',64)
 OR scope IS DISTINCT FROM encode(public.digest(convert_to('supplier-cost-v1'||E'\n'||b||E'\n'||intake||E'\n'||classification||E'\n'||evidence,'UTF8'),'sha256'),'hex')
 THEN RAISE EXCEPTION 'Cost scope denied' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('profitpilot-workspace:'||t::text,0));
 SELECT i.scope_digest INTO accepted_scope FROM private.invoice_intake_receipts r
 JOIN private.invoice_intake_orders i ON i.tenant_id=r.tenant_id AND i.batch_id=r.batch_id AND i.order_id=r.order_id
 JOIN public.import_batches batch ON batch.tenant_id=r.tenant_id AND batch.id=r.batch_id
 WHERE r.tenant_id=t AND r.batch_id=b AND batch.status='accepted' AND batch.source_type='supplier_invoice'
 AND i.preview->>'sourceType'='supplier_invoice' AND i.preview->>'costClassification'='direct_site_candidate';
 IF accepted_scope IS DISTINCT FROM intake THEN RAISE EXCEPTION 'Accepted supplier source unavailable' USING ERRCODE='42501'; END IF;
 SELECT count(*)::integer INTO n FROM private.invoice_intake_lines l JOIN public.invoices h ON h.tenant_id=l.tenant_id AND h.id=l.invoice_id
 WHERE l.tenant_id=t AND l.batch_id=b AND h.direction='supplier';
 IF n<1 OR n>200 OR EXISTS(SELECT 1 FROM private.invoice_intake_lines l JOIN public.invoices h ON h.tenant_id=l.tenant_id AND h.id=l.invoice_id
 WHERE l.tenant_id=t AND l.batch_id=b AND h.direction<>'supplier') THEN RAISE EXCEPTION 'Invalid supplier source lines' USING ERRCODE='23514'; END IF;
 IF step<>'request' THEN
  SELECT * INTO q FROM private.supplier_cost_orders WHERE tenant_id=t AND batch_id=b AND order_id=o AND scope_digest=scope;
  IF NOT FOUND THEN RAISE EXCEPTION 'Cost classification review unavailable' USING ERRCODE='42501'; END IF;
 END IF;
 IF step<>'reject' AND EXISTS(SELECT 1 FROM private.supplier_cost_receipts WHERE tenant_id=t AND batch_id=b)
 THEN RAISE EXCEPTION 'Supplier cost already classified' USING ERRCODE='23514'; END IF;
 IF step='request' AND (SELECT count(*) FROM private.supplier_cost_orders WHERE tenant_id=t AND batch_id=b)>=20 THEN RAISE EXCEPTION 'Cost review capacity reached' USING ERRCODE='54000'; END IF;
 PERFORM private.record_security_work(t,o,'privileged_operation',scope,step,auth,iat,session_digest,expiry,nonce,key_id,signature);
 IF step='request' THEN
  INSERT INTO private.supplier_cost_orders(tenant_id,batch_id,order_id,intake_scope,classification,evidence_digest,scope_digest) VALUES(t,b,o,intake,classification,evidence,scope);
 ELSIF step='consume' THEN
  INSERT INTO private.supplier_cost_receipts(tenant_id,batch_id,order_id) VALUES(t,b,o);
  INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,metadata)
  VALUES(t,actor,'supplier_cost_classified','import_batch',b,jsonb_build_object('scopeDigest',scope,'classification',classification));
 END IF;
 PERFORM private.sensitive_api_fresh(auth,expiry);
 RETURN private.supplier_cost_summary(t,b,o);
END $fn$;
CREATE OR REPLACE FUNCTION private.shared_cost_source(p_tenant uuid,p_kind text,p_source uuid) RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog SET timezone='UTC' AS $fn$
DECLARE result jsonb;
BEGIN
 IF p_kind='payroll' THEN
  SELECT jsonb_build_object('kind','payroll','sourceId',a.id,'siteId',a.site_id,'runId',r.id,'periodStart',p.period_start,'periodEnd',p.period_end,'amount',a.amount::text,'currency',p.currency,'evidenceDigest',cr.evidence_digest)
  INTO result FROM public.allocation_lines a
  JOIN public.allocation_runs r ON r.tenant_id=a.tenant_id AND r.id=a.allocation_run_id
  JOIN public.payroll_pools p ON p.tenant_id=r.tenant_id AND p.id=r.payroll_pool_id
  JOIN private.payroll_confirmation_receipts cr ON cr.tenant_id=r.tenant_id AND cr.allocation_run_id=r.id
  WHERE a.tenant_id=p_tenant AND a.id=p_source AND a.site_id IS NOT NULL AND a.amount>0 AND a.bucket_type IN ('direct','approved_allocated')
  AND r.status='confirmed' AND p.currency='AUD' AND NOT EXISTS(SELECT 1 FROM private.payroll_supersessions x WHERE x.tenant_id=r.tenant_id AND x.old_run_id=r.id);
 ELSIF p_kind IN ('overhead','business_overhead') THEN
  SELECT jsonb_build_object('kind',p_kind,'sourceId',l.id,'siteId',m.site_id,'batchId',k.batch_id,'classificationOrder',q.order_id,'periodStart',m.service_period_start,'periodEnd',m.service_period_end,'amount',l.amount::text,'currency',h.currency,'taxBasis',h.tax_basis,'evidenceDigest',q.evidence_digest)||CASE WHEN p_kind='business_overhead' THEN jsonb_build_object('businessId',si.business_id) ELSE '{}'::jsonb END
  INTO result FROM private.invoice_intake_lines k JOIN public.invoice_lines l ON l.tenant_id=k.tenant_id AND l.id=k.line_id
  JOIN public.invoices h ON h.tenant_id=l.tenant_id AND h.id=l.invoice_id
  JOIN public.match_reviews m ON m.tenant_id=k.tenant_id AND m.id=k.match_id AND m.invoice_line_id=l.id
  JOIN public.sites si ON si.tenant_id=m.tenant_id AND si.id=m.site_id
  JOIN private.supplier_cost_receipts r ON r.tenant_id=k.tenant_id AND r.batch_id=k.batch_id
  JOIN private.supplier_cost_orders q ON q.tenant_id=r.tenant_id AND q.batch_id=r.batch_id AND q.order_id=r.order_id
  WHERE k.tenant_id=p_tenant AND k.line_id=p_source AND q.classification=CASE WHEN p_kind='business_overhead' THEN 'business_overhead_pending' ELSE 'overhead_pending' END AND h.direction='supplier'
  AND m.decision='confirmed' AND m.site_id IS NOT NULL AND m.service_period_start IS NOT NULL AND m.service_period_end IS NOT NULL
  AND l.amount>0 AND h.currency='AUD' AND h.tax_basis<>'unknown';
 END IF;
 RETURN result;
END $fn$;
CREATE OR REPLACE FUNCTION private.api_shared_cost_step(p_tenant uuid,p_kind text,p_source uuid,p_order uuid,p_shares jsonb,p_evidence text,p_scope text,p_step text,
 p_auth bigint,p_iat bigint,p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $fn$
DECLARE actor uuid; src jsonb; existing private.shared_cost_orders%ROWTYPE; item jsonb; target text; baseline text; amount text; target_site text; sort_key text; prev text:=''; total numeric:=0; canonical text;
BEGIN
 actor:=private.security_work_actor(p_tenant,p_order,'privileged_operation',p_scope,p_step,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 IF p_kind IS NULL OR p_kind NOT IN ('payroll','overhead','business_overhead') OR p_source IS NULL OR p_evidence IS NULL OR p_evidence !~ '^[a-f0-9]{64}$' OR p_evidence=repeat('0',64)
 OR jsonb_typeof(p_shares) IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'Shared scope denied' USING ERRCODE='42501'; END IF;
 IF jsonb_array_length(p_shares) NOT BETWEEN 1 AND 100 OR octet_length(p_shares::text)>24000 THEN RAISE EXCEPTION 'Shared allocation capacity' USING ERRCODE='54000'; END IF;
 -- Same lock order as calculations: payroll correction then workspace.
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('payroll-correction:'||p_tenant::text,0));
 PERFORM pg_advisory_xact_lock(hashtextextended('profitpilot-workspace:'||p_tenant::text,0));
 src:=private.shared_cost_source(p_tenant,p_kind,p_source);
 IF src IS NULL THEN RAISE EXCEPTION 'Active reviewed source unavailable' USING ERRCODE='42501'; END IF;
 canonical:='shared-cost-v1'||E'\n'||p_kind||E'\n'||p_source||E'\n'||p_evidence;
 FOR item IN SELECT value FROM jsonb_array_elements(p_shares) LOOP
  IF jsonb_typeof(item) IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'Invalid share' USING ERRCODE='23514'; END IF;
  IF jsonb_array_length(item)<>(CASE WHEN p_kind='business_overhead' THEN 4 ELSE 3 END) OR jsonb_typeof(item->(CASE WHEN p_kind='business_overhead' THEN 3 ELSE 2 END)) IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'Invalid share' USING ERRCODE='23514'; END IF;
  IF p_kind='business_overhead' THEN
   target_site:=item->>0;target:=item->>1;baseline:=item->>2;amount:=item->>3;
   IF (target_site IS NULL)<>(target IS NULL) OR (target_site IS NOT NULL AND
    (jsonb_typeof(item->0) IS DISTINCT FROM 'string' OR target_site !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'))
   THEN RAISE EXCEPTION 'Invalid target site' USING ERRCODE='23514'; END IF;
  ELSE target_site:=src->>'siteId';target:=item->>0;baseline:=item->>1;amount:=item->>2; END IF;
  IF amount IS NULL OR amount !~ '^(0|[1-9][0-9]{0,11})[.][0-9]{2}$' OR amount='0.00'
  OR (target IS NULL)<>(baseline IS NULL) THEN RAISE EXCEPTION 'Invalid share' USING ERRCODE='23514'; END IF;
  IF target IS NULL THEN
   IF item->0 IS DISTINCT FROM 'null'::jsonb OR item->1 IS DISTINCT FROM 'null'::jsonb OR (p_kind='business_overhead' AND item->2 IS DISTINCT FROM 'null'::jsonb) THEN RAISE EXCEPTION 'Invalid remainder' USING ERRCODE='23514'; END IF;
   target:='~';baseline:='~';IF p_kind='business_overhead' THEN target_site:='~'; END IF;
  ELSE
   IF jsonb_typeof(item->(CASE WHEN p_kind='business_overhead' THEN 1 ELSE 0 END)) IS DISTINCT FROM 'string' OR jsonb_typeof(item->(CASE WHEN p_kind='business_overhead' THEN 2 ELSE 1 END)) IS DISTINCT FROM 'string'
   OR target !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
   OR baseline !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
   THEN RAISE EXCEPTION 'Invalid target' USING ERRCODE='23514'; END IF;
   IF NOT EXISTS(SELECT 1 FROM private.workspace_records a JOIN public.contract_versions v ON v.tenant_id=a.tenant_id AND v.contract_id=a.parent_id
    JOIN public.contracts c ON c.tenant_id=v.tenant_id AND c.id=v.contract_id
    JOIN public.sites s ON s.tenant_id=c.tenant_id AND s.business_id=c.business_id AND s.id=a.related_id
    WHERE a.tenant_id=p_tenant AND a.kind='contract_site' AND a.parent_id=target::uuid AND a.related_id=target_site::uuid
    AND (p_kind<>'business_overhead' OR c.business_id=(src->>'businessId')::uuid)
    AND v.id=baseline::uuid AND v.approved_at IS NOT NULL AND v.approved_by IS NOT NULL AND v.currency='AUD' AND v.tax_basis<>'unknown'
    AND v.effective_from<=(src->>'periodStart')::date AND (v.effective_to IS NULL OR v.effective_to>=(src->>'periodEnd')::date)
    AND (p_kind='payroll' OR v.tax_basis=src->>'taxBasis'))
   THEN RAISE EXCEPTION 'Approved contract target unavailable' USING ERRCODE='42501'; END IF;
  END IF;
  sort_key:=CASE WHEN p_kind='business_overhead' THEN target_site||','||target ELSE target END;
  IF sort_key COLLATE "C"<=prev COLLATE "C" THEN RAISE EXCEPTION 'Duplicate or unordered share' USING ERRCODE='23514'; END IF;
  prev:=sort_key;total:=total+amount::numeric;
  canonical:=canonical||E'\n'||CASE WHEN p_kind='business_overhead' THEN target_site||',' ELSE '' END||target||','||baseline||','||amount;
 END LOOP;
 IF total IS DISTINCT FROM (src->>'amount')::numeric THEN RAISE EXCEPTION 'Allocation must reconcile exactly' USING ERRCODE='23514'; END IF;
 IF p_scope IS DISTINCT FROM encode(public.digest(convert_to(canonical,'UTF8'),'sha256'),'hex') THEN RAISE EXCEPTION 'Shared scope denied' USING ERRCODE='42501'; END IF;
 IF p_step<>'request' THEN
  SELECT * INTO existing FROM private.shared_cost_orders WHERE tenant_id=p_tenant AND order_id=p_order AND source_kind=p_kind AND source_id=p_source AND scope_digest=p_scope;
  IF NOT FOUND OR existing.source_snapshot IS DISTINCT FROM src THEN RAISE EXCEPTION 'Reviewed source changed' USING ERRCODE='42501'; END IF;
 END IF;
 IF p_step<>'reject' AND EXISTS(SELECT 1 FROM private.shared_cost_receipts WHERE tenant_id=p_tenant AND source_kind=p_kind AND source_id=p_source)
 THEN RAISE EXCEPTION 'Source already allocated' USING ERRCODE='23514'; END IF;
 IF p_step='request' AND (SELECT count(*) FROM private.shared_cost_orders WHERE tenant_id=p_tenant AND source_kind=p_kind AND source_id=p_source)>=20 THEN RAISE EXCEPTION 'Review capacity reached' USING ERRCODE='54000'; END IF;
 PERFORM private.record_security_work(p_tenant,p_order,'privileged_operation',p_scope,p_step,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 IF p_step='request' THEN
  INSERT INTO private.shared_cost_orders(tenant_id,order_id,source_kind,source_id,source_snapshot,shares,evidence_digest,scope_digest)
  VALUES(p_tenant,p_order,p_kind,p_source,src,p_shares,p_evidence,p_scope);
 ELSIF p_step='consume' THEN
  INSERT INTO private.shared_cost_receipts(tenant_id,source_kind,source_id,order_id) VALUES(p_tenant,p_kind,p_source,p_order);
  INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,metadata)
  VALUES(p_tenant,actor,'shared_cost_allocated','shared_cost_source',p_source,jsonb_build_object('kind',p_kind,'scopeDigest',p_scope,'orderId',p_order));
 END IF;
 PERFORM private.sensitive_api_fresh(p_auth,p_expires);
 RETURN private.shared_cost_summary(p_tenant,p_kind,p_source,p_order);
END $fn$;
CREATE OR REPLACE FUNCTION private.api_shared_cost_correction_step(p_tenant uuid,p_kind text,p_source uuid,p_order uuid,p_replaces uuid,p_shares jsonb,p_evidence text,p_scope text,p_step text,
 p_auth bigint,p_iat bigint,p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $fn$
DECLARE actor uuid; src jsonb; active_order uuid; prior_shares jsonb; existing private.shared_cost_orders%ROWTYPE; item jsonb; target text; baseline text; amount text; target_site text; sort_key text; prev text:=''; total numeric:=0; canonical text;
BEGIN
 actor:=private.security_work_actor(p_tenant,p_order,'privileged_operation',p_scope,p_step,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 IF p_kind IS NULL OR p_kind NOT IN ('payroll','overhead','business_overhead') OR p_source IS NULL OR p_evidence IS NULL OR p_evidence !~ '^[a-f0-9]{64}$' OR p_evidence=repeat('0',64)
 OR jsonb_typeof(p_shares) IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'Shared scope denied' USING ERRCODE='42501'; END IF;
 IF jsonb_array_length(p_shares) NOT BETWEEN 1 AND 100 OR octet_length(p_shares::text)>24000 THEN RAISE EXCEPTION 'Shared allocation capacity' USING ERRCODE='54000'; END IF;
 -- Same lock order as calculations: payroll correction then workspace.
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('payroll-correction:'||p_tenant::text,0));
 PERFORM pg_advisory_xact_lock(hashtextextended('profitpilot-workspace:'||p_tenant::text,0));
 SELECT r.order_id,q.shares INTO active_order,prior_shares FROM private.active_shared_cost_receipts r
 JOIN private.shared_cost_orders q ON q.tenant_id=r.tenant_id AND q.order_id=r.order_id
 WHERE r.tenant_id=p_tenant AND r.source_kind=p_kind AND r.source_id=p_source;
 IF p_replaces IS NULL OR active_order IS DISTINCT FROM p_replaces OR p_order=p_replaces THEN RAISE EXCEPTION 'Stale correction predecessor' USING ERRCODE='23514'; END IF;
 IF prior_shares IS NOT DISTINCT FROM p_shares THEN RAISE EXCEPTION 'Correction must change allocation' USING ERRCODE='23514'; END IF;
 src:=private.shared_cost_source(p_tenant,p_kind,p_source);
 IF src IS NULL THEN RAISE EXCEPTION 'Active reviewed source unavailable' USING ERRCODE='42501'; END IF;
 canonical:='shared-cost-correction-v1'||E'\n'||p_kind||E'\n'||p_source||E'\n'||p_replaces||E'\n'||p_evidence;
 FOR item IN SELECT value FROM jsonb_array_elements(p_shares) LOOP
  IF jsonb_typeof(item) IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'Invalid share' USING ERRCODE='23514'; END IF;
  IF jsonb_array_length(item)<>(CASE WHEN p_kind='business_overhead' THEN 4 ELSE 3 END) OR jsonb_typeof(item->(CASE WHEN p_kind='business_overhead' THEN 3 ELSE 2 END)) IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'Invalid share' USING ERRCODE='23514'; END IF;
  IF p_kind='business_overhead' THEN
   target_site:=item->>0;target:=item->>1;baseline:=item->>2;amount:=item->>3;
   IF (target_site IS NULL)<>(target IS NULL) OR (target_site IS NOT NULL AND
    (jsonb_typeof(item->0) IS DISTINCT FROM 'string' OR target_site !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'))
   THEN RAISE EXCEPTION 'Invalid target site' USING ERRCODE='23514'; END IF;
  ELSE target_site:=src->>'siteId';target:=item->>0;baseline:=item->>1;amount:=item->>2; END IF;
  IF amount IS NULL OR amount !~ '^(0|[1-9][0-9]{0,11})[.][0-9]{2}$' OR amount='0.00'
  OR (target IS NULL)<>(baseline IS NULL) THEN RAISE EXCEPTION 'Invalid share' USING ERRCODE='23514'; END IF;
  IF target IS NULL THEN
   IF item->0 IS DISTINCT FROM 'null'::jsonb OR item->1 IS DISTINCT FROM 'null'::jsonb OR (p_kind='business_overhead' AND item->2 IS DISTINCT FROM 'null'::jsonb) THEN RAISE EXCEPTION 'Invalid remainder' USING ERRCODE='23514'; END IF;
   target:='~';baseline:='~';IF p_kind='business_overhead' THEN target_site:='~'; END IF;
  ELSE
   IF jsonb_typeof(item->(CASE WHEN p_kind='business_overhead' THEN 1 ELSE 0 END)) IS DISTINCT FROM 'string' OR jsonb_typeof(item->(CASE WHEN p_kind='business_overhead' THEN 2 ELSE 1 END)) IS DISTINCT FROM 'string'
   OR target !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
   OR baseline !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
   THEN RAISE EXCEPTION 'Invalid target' USING ERRCODE='23514'; END IF;
   IF NOT EXISTS(SELECT 1 FROM private.workspace_records a JOIN public.contract_versions v ON v.tenant_id=a.tenant_id AND v.contract_id=a.parent_id
    JOIN public.contracts c ON c.tenant_id=v.tenant_id AND c.id=v.contract_id
    JOIN public.sites s ON s.tenant_id=c.tenant_id AND s.business_id=c.business_id AND s.id=a.related_id
    WHERE a.tenant_id=p_tenant AND a.kind='contract_site' AND a.parent_id=target::uuid AND a.related_id=target_site::uuid
    AND (p_kind<>'business_overhead' OR c.business_id=(src->>'businessId')::uuid)
    AND v.id=baseline::uuid AND v.approved_at IS NOT NULL AND v.approved_by IS NOT NULL AND v.currency='AUD' AND v.tax_basis<>'unknown'
    AND v.effective_from<=(src->>'periodStart')::date AND (v.effective_to IS NULL OR v.effective_to>=(src->>'periodEnd')::date)
    AND (p_kind='payroll' OR v.tax_basis=src->>'taxBasis'))
   THEN RAISE EXCEPTION 'Approved contract target unavailable' USING ERRCODE='42501'; END IF;
  END IF;
  sort_key:=CASE WHEN p_kind='business_overhead' THEN target_site||','||target ELSE target END;
  IF sort_key COLLATE "C"<=prev COLLATE "C" THEN RAISE EXCEPTION 'Duplicate or unordered share' USING ERRCODE='23514'; END IF;
  prev:=sort_key;total:=total+amount::numeric;
  canonical:=canonical||E'\n'||CASE WHEN p_kind='business_overhead' THEN target_site||',' ELSE '' END||target||','||baseline||','||amount;
 END LOOP;
 IF total IS DISTINCT FROM (src->>'amount')::numeric THEN RAISE EXCEPTION 'Allocation must reconcile exactly' USING ERRCODE='23514'; END IF;
 IF p_scope IS DISTINCT FROM encode(public.digest(convert_to(canonical,'UTF8'),'sha256'),'hex') THEN RAISE EXCEPTION 'Shared scope denied' USING ERRCODE='42501'; END IF;
 IF p_step<>'request' THEN
  SELECT * INTO existing FROM private.shared_cost_orders WHERE tenant_id=p_tenant AND order_id=p_order AND source_kind=p_kind AND source_id=p_source AND scope_digest=p_scope;
  IF NOT FOUND OR existing.source_snapshot IS DISTINCT FROM src OR existing.replaces_order_id IS DISTINCT FROM p_replaces THEN RAISE EXCEPTION 'Reviewed source changed' USING ERRCODE='42501'; END IF;
 END IF;

 IF p_step='request' AND (SELECT count(*) FROM private.shared_cost_orders WHERE tenant_id=p_tenant AND source_kind=p_kind AND source_id=p_source)>=20 THEN RAISE EXCEPTION 'Review capacity reached' USING ERRCODE='54000'; END IF;
 PERFORM private.record_security_work(p_tenant,p_order,'privileged_operation',p_scope,p_step,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 IF p_step='request' THEN
  INSERT INTO private.shared_cost_orders(tenant_id,order_id,source_kind,source_id,source_snapshot,shares,evidence_digest,scope_digest,replaces_order_id)
  VALUES(p_tenant,p_order,p_kind,p_source,src,p_shares,p_evidence,p_scope,p_replaces);
 ELSIF p_step='consume' THEN
  INSERT INTO private.shared_cost_revisions(tenant_id,source_kind,source_id,prior_order_id,new_order_id) VALUES(p_tenant,p_kind,p_source,p_replaces,p_order);
  INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,metadata)
  VALUES(p_tenant,actor,'shared_cost_corrected','shared_cost_source',p_source,jsonb_build_object('kind',p_kind,'scopeDigest',p_scope,'orderId',p_order,'priorOrderId',p_replaces));
 END IF;
 PERFORM private.sensitive_api_fresh(p_auth,p_expires);
 RETURN private.shared_cost_summary(p_tenant,p_kind,p_source,p_order);
END $fn$;
CREATE OR REPLACE FUNCTION private.api_shared_cost_status(p_tenant uuid,p_order uuid,p_action text,p_scope text,p_auth bigint,p_iat bigint,p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text,p_kind text,p_source uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE result jsonb;
BEGIN
 IF p_kind IS NULL OR p_kind NOT IN ('payroll','overhead','business_overhead') OR p_action IS DISTINCT FROM 'shared_cost_status'
 OR p_scope IS DISTINCT FROM encode(public.digest(convert_to('shared-cost-status-v1'||E'\n'||p_kind||E'\n'||p_source,'UTF8'),'sha256'),'hex') THEN RAISE EXCEPTION 'Shared status denied' USING ERRCODE='42501'; END IF;
 PERFORM private.sensitive_api_actor(p_tenant,p_order,p_action,p_scope,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 result:=private.shared_cost_summary(p_tenant,p_kind,p_source,p_order);
 PERFORM private.sensitive_api_fresh(p_auth,p_expires);RETURN result;
END $fn$;
CREATE OR REPLACE FUNCTION private.supplier_cost_snapshot(t uuid,c uuid,s uuid,starts date,ends date,baseline uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $fn$
DECLARE result jsonb; basis text;
BEGIN
 IF private.current_tenant_id() IS DISTINCT FROM t OR coalesce(private.current_actor_role(),'') NOT IN ('owner','admin','analyst','reviewer')
 OR c IS NULL OR s IS NULL OR starts IS NULL OR ends IS NULL OR ends<starts OR NOT isfinite(starts) OR NOT isfinite(ends)
 OR NOT private.workspace_contract_site_allowed(t,c,s) THEN RAISE EXCEPTION 'Supplier summary denied' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('profitpilot-workspace:'||t::text,0));
 SELECT v.tax_basis INTO basis FROM public.contract_versions v JOIN public.contracts co ON co.tenant_id=v.tenant_id AND co.id=v.contract_id
 JOIN public.sites si ON si.tenant_id=co.tenant_id AND si.business_id=co.business_id AND si.id=s
 WHERE v.tenant_id=t AND v.contract_id=c AND v.id=baseline AND v.approved_at IS NOT NULL AND v.approved_by IS NOT NULL
 AND v.effective_from<=starts AND (v.effective_to IS NULL OR v.effective_to>=ends) AND v.currency='AUD' AND v.tax_basis<>'unknown';
 IF NOT FOUND THEN RAISE EXCEPTION 'Supplier calculation baseline unavailable' USING ERRCODE='23514'; END IF;
 WITH candidates AS (
 SELECT m.id match_id,l.id line_id,h.id invoice_id,k.batch_id,k.raw_row_id,k.baseline_id,l.amount,h.currency,h.tax_basis,
 m.service_period_start p_start,m.service_period_end p_end,r.order_id,q.scope_digest,q.evidence_digest,
 coalesce(q.classification,'pending') classification
 FROM public.match_reviews m JOIN public.invoice_lines l ON l.tenant_id=m.tenant_id AND l.id=m.invoice_line_id
 JOIN public.invoices h ON h.tenant_id=l.tenant_id AND h.id=l.invoice_id
 LEFT JOIN private.invoice_intake_lines k ON k.tenant_id=m.tenant_id AND k.line_id=l.id AND k.match_id=m.id
 LEFT JOIN private.supplier_cost_receipts r ON r.tenant_id=k.tenant_id AND r.batch_id=k.batch_id
 LEFT JOIN private.supplier_cost_orders q ON q.tenant_id=r.tenant_id AND q.batch_id=r.batch_id AND q.order_id=r.order_id
 WHERE m.tenant_id=t AND m.contract_id=c AND m.site_id=s AND m.decision='confirmed' AND h.direction='supplier'
 AND (m.service_period_start IS NULL OR m.service_period_end IS NULL OR (m.service_period_start<=ends AND m.service_period_end>=starts))
 ORDER BY m.id LIMIT 10001
 )
 SELECT jsonb_build_object('directCost',coalesce(sum(amount) FILTER(WHERE classification='direct_site'),0)::numeric(30,2)::text,
 'directCount',count(*) FILTER(WHERE classification='direct_site'),
 'excludedCount',count(*) FILTER(WHERE classification IN ('excluded','payroll_overlap')),
 'pendingCount',count(*) FILTER(WHERE classification IN ('pending','overhead_pending','business_overhead_pending')),
 'invalid',count(*)>10000 OR coalesce(bool_or(classification='direct_site' AND
 (p_start IS NULL OR p_end IS NULL OR p_start<starts OR p_end>ends OR p_end<p_start OR amount<=0 OR currency<>'AUD'
 OR tax_basis IS DISTINCT FROM basis OR baseline_id IS DISTINCT FROM baseline OR order_id IS NULL)),false),
 'lines',coalesce(jsonb_agg(jsonb_build_array(match_id,line_id,invoice_id,batch_id,raw_row_id,baseline_id,amount::text,currency,tax_basis,p_start,p_end,order_id,scope_digest,evidence_digest,classification) ORDER BY match_id),'[]'::jsonb))
 INTO result FROM candidates;
 RETURN result;
END $fn$;
CREATE OR REPLACE FUNCTION private.verify_security_catalog() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT digest=private.security_catalog_digest() FROM private.security_catalog_baseline WHERE revision=76),false)
$fn$;
INSERT INTO private.security_catalog_baseline(singleton,revision,digest) VALUES(true,76,private.security_catalog_digest());
COMMIT;

-- Non-site payroll is not business-scoped at intake. An independent reviewer
-- must attest exact managed site/contract shares; no inferred allocation.
BEGIN;
DO $check$ BEGIN IF private.verify_security_catalog() IS DISTINCT FROM true THEN RAISE EXCEPTION 'Prior catalog does not verify'; END IF; END $check$;
ALTER TABLE private.shared_cost_orders DROP CONSTRAINT shared_cost_orders_source_kind_check,
 ADD CONSTRAINT shared_cost_orders_source_kind_check CHECK(source_kind IN ('payroll','overhead','business_overhead','non_site_payroll'));
CREATE OR REPLACE FUNCTION private.shared_cost_source(p_tenant uuid,p_kind text,p_source uuid) RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog SET timezone='UTC' AS $fn$
DECLARE result jsonb;
BEGIN
 IF p_kind IN ('payroll','non_site_payroll') THEN
  SELECT jsonb_build_object('kind',p_kind,'sourceId',a.id,'siteId',a.site_id,'runId',r.id,'periodStart',p.period_start,'periodEnd',p.period_end,'amount',a.amount::text,'currency',p.currency,'evidenceDigest',cr.evidence_digest)
  INTO result FROM public.allocation_lines a
  JOIN public.allocation_runs r ON r.tenant_id=a.tenant_id AND r.id=a.allocation_run_id
  JOIN public.payroll_pools p ON p.tenant_id=r.tenant_id AND p.id=r.payroll_pool_id
  JOIN private.payroll_confirmation_receipts cr ON cr.tenant_id=r.tenant_id AND cr.allocation_run_id=r.id
  WHERE a.tenant_id=p_tenant AND a.id=p_source AND a.amount>0 AND ((p_kind='payroll' AND a.site_id IS NOT NULL AND a.bucket_type IN ('direct','approved_allocated')) OR (p_kind='non_site_payroll' AND a.site_id IS NULL AND a.bucket_type='non_site'))
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
 IF p_kind IS NULL OR p_kind NOT IN ('payroll','overhead','business_overhead','non_site_payroll') OR p_source IS NULL OR p_evidence IS NULL OR p_evidence !~ '^[a-f0-9]{64}$' OR p_evidence=repeat('0',64)
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
  IF jsonb_array_length(item)<>(CASE WHEN p_kind IN ('business_overhead','non_site_payroll') THEN 4 ELSE 3 END) OR jsonb_typeof(item->(CASE WHEN p_kind IN ('business_overhead','non_site_payroll') THEN 3 ELSE 2 END)) IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'Invalid share' USING ERRCODE='23514'; END IF;
  IF p_kind IN ('business_overhead','non_site_payroll') THEN
   target_site:=item->>0;target:=item->>1;baseline:=item->>2;amount:=item->>3;
   IF (target_site IS NULL)<>(target IS NULL) OR (target_site IS NOT NULL AND
    (jsonb_typeof(item->0) IS DISTINCT FROM 'string' OR target_site !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'))
   THEN RAISE EXCEPTION 'Invalid target site' USING ERRCODE='23514'; END IF;
  ELSE target_site:=src->>'siteId';target:=item->>0;baseline:=item->>1;amount:=item->>2; END IF;
  IF amount IS NULL OR amount !~ '^(0|[1-9][0-9]{0,11})[.][0-9]{2}$' OR amount='0.00'
  OR (target IS NULL)<>(baseline IS NULL) THEN RAISE EXCEPTION 'Invalid share' USING ERRCODE='23514'; END IF;
  IF target IS NULL THEN
   IF item->0 IS DISTINCT FROM 'null'::jsonb OR item->1 IS DISTINCT FROM 'null'::jsonb OR (p_kind IN ('business_overhead','non_site_payroll') AND item->2 IS DISTINCT FROM 'null'::jsonb) THEN RAISE EXCEPTION 'Invalid remainder' USING ERRCODE='23514'; END IF;
   target:='~';baseline:='~';IF p_kind IN ('business_overhead','non_site_payroll') THEN target_site:='~'; END IF;
  ELSE
   IF jsonb_typeof(item->(CASE WHEN p_kind IN ('business_overhead','non_site_payroll') THEN 1 ELSE 0 END)) IS DISTINCT FROM 'string' OR jsonb_typeof(item->(CASE WHEN p_kind IN ('business_overhead','non_site_payroll') THEN 2 ELSE 1 END)) IS DISTINCT FROM 'string'
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
    AND (p_kind IN ('payroll','non_site_payroll') OR v.tax_basis=src->>'taxBasis'))
   THEN RAISE EXCEPTION 'Approved contract target unavailable' USING ERRCODE='42501'; END IF;
  END IF;
  sort_key:=CASE WHEN p_kind IN ('business_overhead','non_site_payroll') THEN target_site||','||target ELSE target END;
  IF sort_key COLLATE "C"<=prev COLLATE "C" THEN RAISE EXCEPTION 'Duplicate or unordered share' USING ERRCODE='23514'; END IF;
  prev:=sort_key;total:=total+amount::numeric;
  canonical:=canonical||E'\n'||CASE WHEN p_kind IN ('business_overhead','non_site_payroll') THEN target_site||',' ELSE '' END||target||','||baseline||','||amount;
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
 IF p_kind IS NULL OR p_kind NOT IN ('payroll','overhead','business_overhead','non_site_payroll') OR p_source IS NULL OR p_evidence IS NULL OR p_evidence !~ '^[a-f0-9]{64}$' OR p_evidence=repeat('0',64)
 OR jsonb_typeof(p_shares) IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'Shared scope denied' USING ERRCODE='42501'; END IF;
 IF jsonb_array_length(p_shares) NOT BETWEEN 1 AND 100 OR octet_length(p_shares::text)>24000 THEN RAISE EXCEPTION 'Shared allocation capacity' USING ERRCODE='54000'; END IF;
 -- Same lock order as calculations: payroll correction then workspace.
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('payroll-correction:'||p_tenant::text,0));
 PERFORM pg_advisory_xact_lock(hashtextextended('profitpilot-workspace:'||p_tenant::text,0));
 SELECT r.order_id,q.shares INTO active_order,prior_shares FROM private.active_shared_cost_receipts r
 JOIN private.shared_cost_orders q ON q.tenant_id=r.tenant_id AND q.order_id=r.order_id
 WHERE r.tenant_id=p_tenant AND r.source_kind=p_kind AND r.source_id=p_source;
 IF p_replaces IS NULL OR active_order IS DISTINCT FROM p_replaces OR p_order=p_replaces THEN RAISE EXCEPTION 'Stale correction predecessor' USING ERRCODE='23514'; END IF;
 IF p_step<>'reject' AND EXISTS(SELECT 1 FROM private.invoice_credit_orders q JOIN private.invoice_credit_receipts r ON r.tenant_id=q.tenant_id AND r.order_id=q.order_id WHERE q.tenant_id=p_tenant AND q.allocation_order_id=p_replaces AND q.reverses_order_id IS NULL AND NOT EXISTS(SELECT 1 FROM private.invoice_credit_receipts v WHERE v.tenant_id=q.tenant_id AND v.reverses_order_id=q.order_id))
 THEN RAISE EXCEPTION 'Reverse active shared credits before correcting allocation' USING ERRCODE='23514'; END IF;
 IF prior_shares IS NOT DISTINCT FROM p_shares THEN RAISE EXCEPTION 'Correction must change allocation' USING ERRCODE='23514'; END IF;
 src:=private.shared_cost_source(p_tenant,p_kind,p_source);
 IF src IS NULL THEN RAISE EXCEPTION 'Active reviewed source unavailable' USING ERRCODE='42501'; END IF;
 canonical:='shared-cost-correction-v1'||E'\n'||p_kind||E'\n'||p_source||E'\n'||p_replaces||E'\n'||p_evidence;
 FOR item IN SELECT value FROM jsonb_array_elements(p_shares) LOOP
  IF jsonb_typeof(item) IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'Invalid share' USING ERRCODE='23514'; END IF;
  IF jsonb_array_length(item)<>(CASE WHEN p_kind IN ('business_overhead','non_site_payroll') THEN 4 ELSE 3 END) OR jsonb_typeof(item->(CASE WHEN p_kind IN ('business_overhead','non_site_payroll') THEN 3 ELSE 2 END)) IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'Invalid share' USING ERRCODE='23514'; END IF;
  IF p_kind IN ('business_overhead','non_site_payroll') THEN
   target_site:=item->>0;target:=item->>1;baseline:=item->>2;amount:=item->>3;
   IF (target_site IS NULL)<>(target IS NULL) OR (target_site IS NOT NULL AND
    (jsonb_typeof(item->0) IS DISTINCT FROM 'string' OR target_site !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'))
   THEN RAISE EXCEPTION 'Invalid target site' USING ERRCODE='23514'; END IF;
  ELSE target_site:=src->>'siteId';target:=item->>0;baseline:=item->>1;amount:=item->>2; END IF;
  IF amount IS NULL OR amount !~ '^(0|[1-9][0-9]{0,11})[.][0-9]{2}$' OR amount='0.00'
  OR (target IS NULL)<>(baseline IS NULL) THEN RAISE EXCEPTION 'Invalid share' USING ERRCODE='23514'; END IF;
  IF target IS NULL THEN
   IF item->0 IS DISTINCT FROM 'null'::jsonb OR item->1 IS DISTINCT FROM 'null'::jsonb OR (p_kind IN ('business_overhead','non_site_payroll') AND item->2 IS DISTINCT FROM 'null'::jsonb) THEN RAISE EXCEPTION 'Invalid remainder' USING ERRCODE='23514'; END IF;
   target:='~';baseline:='~';IF p_kind IN ('business_overhead','non_site_payroll') THEN target_site:='~'; END IF;
  ELSE
   IF jsonb_typeof(item->(CASE WHEN p_kind IN ('business_overhead','non_site_payroll') THEN 1 ELSE 0 END)) IS DISTINCT FROM 'string' OR jsonb_typeof(item->(CASE WHEN p_kind IN ('business_overhead','non_site_payroll') THEN 2 ELSE 1 END)) IS DISTINCT FROM 'string'
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
    AND (p_kind IN ('payroll','non_site_payroll') OR v.tax_basis=src->>'taxBasis'))
   THEN RAISE EXCEPTION 'Approved contract target unavailable' USING ERRCODE='42501'; END IF;
  END IF;
  sort_key:=CASE WHEN p_kind IN ('business_overhead','non_site_payroll') THEN target_site||','||target ELSE target END;
  IF sort_key COLLATE "C"<=prev COLLATE "C" THEN RAISE EXCEPTION 'Duplicate or unordered share' USING ERRCODE='23514'; END IF;
  prev:=sort_key;total:=total+amount::numeric;
  canonical:=canonical||E'\n'||CASE WHEN p_kind IN ('business_overhead','non_site_payroll') THEN target_site||',' ELSE '' END||target||','||baseline||','||amount;
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
 IF p_kind IS NULL OR p_kind NOT IN ('payroll','overhead','business_overhead','non_site_payroll') OR p_action IS DISTINCT FROM 'shared_cost_status'
 OR p_scope IS DISTINCT FROM encode(public.digest(convert_to('shared-cost-status-v1'||E'\n'||p_kind||E'\n'||p_source,'UTF8'),'sha256'),'hex') THEN RAISE EXCEPTION 'Shared status denied' USING ERRCODE='42501'; END IF;
 PERFORM private.sensitive_api_actor(p_tenant,p_order,p_action,p_scope,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 result:=private.shared_cost_summary(p_tenant,p_kind,p_source,p_order);
 PERFORM private.sensitive_api_fresh(p_auth,p_expires);RETURN result;
END $fn$;

CREATE FUNCTION private.non_site_payroll_snapshot(t uuid,c uuid,s uuid,starts date,ends date,baseline uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $fn$
DECLARE result jsonb;
BEGIN
 IF private.current_tenant_id() IS DISTINCT FROM t OR coalesce(private.current_actor_role(),'') NOT IN ('owner','admin','analyst','reviewer')
 OR c IS NULL OR s IS NULL OR starts IS NULL OR ends IS NULL OR ends<starts OR NOT isfinite(starts) OR NOT isfinite(ends)
 OR NOT private.workspace_contract_site_allowed(t,c,s) THEN RAISE EXCEPTION 'Non-site payroll scope denied' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('payroll-correction:'||t::text,0));
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('profitpilot-workspace:'||t::text,0));
 IF NOT EXISTS(SELECT 1 FROM public.contract_versions v JOIN public.contracts co ON co.tenant_id=v.tenant_id AND co.id=v.contract_id
 JOIN public.sites si ON si.tenant_id=co.tenant_id AND si.business_id=co.business_id AND si.id=s
 WHERE v.tenant_id=t AND v.contract_id=c AND v.id=baseline AND v.approved_at IS NOT NULL AND v.approved_by IS NOT NULL
 AND v.effective_from<=starts AND (v.effective_to IS NULL OR v.effective_to>=ends) AND v.currency='AUD' AND v.tax_basis<>'unknown')
 THEN RAISE EXCEPTION 'Non-site payroll baseline unavailable' USING ERRCODE='23514'; END IF;
 WITH sources AS MATERIALIZED (
 SELECT a.id FROM public.allocation_lines a JOIN public.allocation_runs r ON r.tenant_id=a.tenant_id AND r.id=a.allocation_run_id
 JOIN public.payroll_pools p ON p.tenant_id=r.tenant_id AND p.id=r.payroll_pool_id
 WHERE a.tenant_id=t AND a.site_id IS NULL AND a.bucket_type='non_site' AND a.amount>0
 AND r.status='confirmed' AND p.period_start<=ends AND p.period_end>=starts
 AND NOT EXISTS(SELECT 1 FROM private.payroll_supersessions x WHERE x.tenant_id=r.tenant_id AND x.old_run_id=r.id)
 ORDER BY a.id LIMIT 10001
 ), facts AS MATERIALIZED (
 SELECT x.id,private.shared_cost_source(t,'non_site_payroll',x.id) actual,q.order_id,q.source_snapshot,q.shares,q.scope_digest,q.evidence_digest
 FROM sources x LEFT JOIN private.active_shared_cost_receipts r ON r.tenant_id=t AND r.source_kind='non_site_payroll' AND r.source_id=x.id
 LEFT JOIN private.shared_cost_orders q ON q.tenant_id=r.tenant_id AND q.source_kind=r.source_kind AND q.source_id=r.source_id AND q.order_id=r.order_id
 ), assessed AS (
 SELECT f.*,coalesce((SELECT sum((v->>3)::numeric) FROM jsonb_array_elements(f.shares) v WHERE v->>0=s::text AND v->>1=c::text AND v->>2=baseline::text),0) chosen,
 coalesce((SELECT sum((v->>3)::numeric) FROM jsonb_array_elements(f.shares) v WHERE v->0='null'::jsonb),0) remainder,
 EXISTS(SELECT 1 FROM jsonb_array_elements(f.shares) v WHERE v->>0=s::text AND v->>1=c::text AND v->>2 IS DISTINCT FROM baseline::text) wrong_baseline
 FROM facts f
 )
 SELECT jsonb_build_object('cost',coalesce(sum(chosen),0)::numeric(30,2)::text,'unallocatedCost',coalesce(sum(remainder),0)::numeric(30,2)::text,
 'sourceCount',count(*),'missingCount',count(*) FILTER(WHERE order_id IS NULL),'invalid',count(*)>10000 OR coalesce(bool_or(actual IS NULL OR
 (order_id IS NOT NULL AND actual IS DISTINCT FROM source_snapshot) OR (actual->>'periodStart')::date<starts OR (actual->>'periodEnd')::date>ends OR actual->>'currency'<>'AUD' OR wrong_baseline),false),
 'lines',coalesce(jsonb_agg(jsonb_build_array('non_site_payroll',id,actual,order_id,shares,scope_digest,evidence_digest,chosen::numeric(30,2)::text,remainder::numeric(30,2)::text) ORDER BY id),'[]'::jsonb))
 INTO result FROM assessed;RETURN result;
END $fn$;
CREATE FUNCTION private.site_non_site_payroll_summary(t uuid,c uuid,s uuid,starts date,ends date,baseline uuid) RETURNS jsonb
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT x-'lines' FROM (SELECT private.non_site_payroll_snapshot(t,c,s,starts,ends,baseline) x) a
$fn$;
REVOKE ALL ON FUNCTION private.non_site_payroll_snapshot(uuid,uuid,uuid,date,date,uuid),private.site_non_site_payroll_summary(uuid,uuid,uuid,date,date,uuid) FROM PUBLIC,profitpilot_app;
GRANT EXECUTE ON FUNCTION private.site_non_site_payroll_summary(uuid,uuid,uuid,date,date,uuid) TO profitpilot_app;

CREATE OR REPLACE FUNCTION private.capture_calculation_sources() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $fn$
DECLARE snap jsonb; baseline uuid; baselines integer; revenue numeric; cost numeric; ic integer; ac integer; reviewed integer;
 bad boolean; digest_value text; supplier jsonb; supplier_total numeric:=0; shared jsonb; business jsonb; credits jsonb; overhead_credits jsonb; non_site jsonb;
BEGIN
 IF NEW.formula_version NOT IN ('0.2.0','0.3.0','0.4.0','0.5.0','0.6.0','0.7.0','0.8.0') THEN RETURN NEW; END IF;
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
 IF NEW.formula_version IN ('0.3.0','0.4.0','0.5.0','0.6.0','0.7.0','0.8.0') THEN
  supplier:=private.supplier_cost_snapshot(NEW.tenant_id,NEW.contract_id,NEW.site_id,NEW.period_start,NEW.period_end,baseline);
  supplier_total:=(supplier->>'directCost')::numeric;
  IF NEW.formula_version IN ('0.4.0','0.5.0','0.6.0','0.7.0','0.8.0') THEN
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
  IF NEW.formula_version IN ('0.4.0','0.5.0','0.6.0','0.7.0','0.8.0') THEN
   snap:=snap||jsonb_build_object('format','profitpilot-source-trace-v3','shared',shared);
   cost:=cost+(shared->>'overheadCost')::numeric;
  END IF;
 END IF;
 IF NEW.formula_version IN ('0.5.0','0.6.0','0.7.0','0.8.0') THEN
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
 IF (credits->>'invalid')::boolean OR (NEW.formula_version NOT IN ('0.6.0','0.7.0','0.8.0') AND (credits->>'creditCount')::integer>0)
 THEN RAISE EXCEPTION 'Calculation source snapshot changed or does not reconcile' USING ERRCODE='23514'; END IF;
 IF NEW.formula_version IN ('0.6.0','0.7.0','0.8.0') THEN
  IF NEW.outputs->>'customerCredit' IS DISTINCT FROM credits->>'customerCredit' OR NEW.outputs->>'supplierCredit' IS DISTINCT FROM credits->>'supplierCredit'
  OR NEW.outputs->>'creditReversalCount' IS DISTINCT FROM credits->>'reversalCount'
  OR NEW.outputs->>'creditCount' IS DISTINCT FROM credits->>'creditCount' OR NEW.outputs->>'grossRevenue' IS DISTINCT FROM revenue::numeric(30,2)::text
  THEN RAISE EXCEPTION 'Calculation source snapshot changed or does not reconcile' USING ERRCODE='23514'; END IF;
  snap:=snap||jsonb_build_object('format','profitpilot-source-trace-v5','credits',credits,'grossRevenue',revenue::numeric(30,2)::text);
  revenue:=revenue-(credits->>'customerCredit')::numeric;
  cost:=cost-(credits->>'supplierCredit')::numeric;
 END IF;
 overhead_credits:=private.shared_overhead_credit_snapshot(NEW.tenant_id,NEW.contract_id,NEW.site_id,NEW.period_start,NEW.period_end,baseline);
 IF (overhead_credits->>'invalid')::boolean OR (NEW.formula_version NOT IN ('0.7.0','0.8.0') AND (overhead_credits->>'eventCount')::integer>0) THEN RAISE EXCEPTION 'Shared credit source snapshot changed or does not reconcile' USING ERRCODE='23514'; END IF;
 IF NEW.formula_version IN ('0.7.0','0.8.0') THEN
  IF NEW.outputs->>'siteOverheadCredit' IS DISTINCT FROM overhead_credits->>'siteCredit'
   OR NEW.outputs->>'businessOverheadCredit' IS DISTINCT FROM overhead_credits->>'businessCredit'
   OR NEW.outputs->>'sharedCreditEventCount' IS DISTINCT FROM overhead_credits->>'eventCount'
   OR NEW.outputs->>'siteRemainderCredit' IS DISTINCT FROM overhead_credits->>'siteRemainderCredit'
   OR NEW.outputs->>'businessRemainderCredit' IS DISTINCT FROM overhead_credits->>'businessRemainderCredit'
  THEN RAISE EXCEPTION 'Shared credit amount does not reconcile' USING ERRCODE='23514'; END IF;
  cost:=cost-(overhead_credits->>'siteCredit')::numeric-(overhead_credits->>'businessCredit')::numeric;
  snap:=snap||jsonb_build_object('format','profitpilot-source-trace-v6','overheadCredits',overhead_credits);
 END IF;
 IF NEW.formula_version='0.8.0' THEN
  non_site:=private.non_site_payroll_snapshot(NEW.tenant_id,NEW.contract_id,NEW.site_id,NEW.period_start,NEW.period_end,baseline);
  IF (non_site->>'invalid')::boolean OR (non_site->>'missingCount')::integer<>0
   OR NEW.outputs->>'nonSitePayrollCost' IS DISTINCT FROM non_site->>'cost'
   OR NEW.outputs->>'nonSitePayrollSourceCount' IS DISTINCT FROM non_site->>'sourceCount'
   OR NEW.outputs->>'unallocatedNonSitePayroll' IS DISTINCT FROM non_site->>'unallocatedCost'
  THEN RAISE EXCEPTION 'Non-site payroll source snapshot changed or does not reconcile' USING ERRCODE='23514'; END IF;
  cost:=cost+(non_site->>'cost')::numeric;
  snap:=snap||jsonb_build_object('format','profitpilot-source-trace-v7','nonSitePayroll',non_site);
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
CREATE OR REPLACE FUNCTION private.guard_traced_calculation() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
BEGIN
 IF OLD.formula_version IN ('0.2.0','0.3.0','0.4.0','0.5.0','0.6.0','0.7.0','0.8.0') OR EXISTS(SELECT 1 FROM private.calculation_source_receipts WHERE calculation_id=OLD.id)
 THEN RAISE EXCEPTION 'Traced calculation is immutable' USING ERRCODE='55000'; END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;RETURN NEW;
END $fn$;
CREATE OR REPLACE FUNCTION private.calculation_trace_projection(p_tenant uuid,p_run uuid) RETURNS jsonb
LANGUAGE sql STABLE SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT jsonb_build_object('status','captured','format',source_snapshot->>'format','digest',snapshot_digest,'baselineId',baseline_id,
 'invoiceLineCount',invoice_count,'reviewedInvoiceLineCount',reviewed_invoice_count,'allocationLineCount',allocation_count,'capturedAt',captured_at)
 ||CASE WHEN source_snapshot->>'format' IN ('profitpilot-source-trace-v2','profitpilot-source-trace-v3','profitpilot-source-trace-v4','profitpilot-source-trace-v5','profitpilot-source-trace-v6','profitpilot-source-trace-v7') THEN jsonb_build_object(
 'payrollCost',source_snapshot->>'payrollCost','supplierCost',source_snapshot->'supplier'->>'directCost',
 'supplierLineCount',(source_snapshot->'supplier'->>'directCount')::integer,
 'supplierExcludedLineCount',(source_snapshot->'supplier'->>'excludedCount')::integer,
 'supplierPendingLineCount',(source_snapshot->'supplier'->>'pendingCount')::integer) ELSE '{}'::jsonb END
 ||CASE WHEN source_snapshot->>'format' IN ('profitpilot-source-trace-v3','profitpilot-source-trace-v4','profitpilot-source-trace-v5','profitpilot-source-trace-v6','profitpilot-source-trace-v7') THEN jsonb_build_object(
 'overheadCost',source_snapshot->'shared'->>'overheadCost','sharedSourceCount',(source_snapshot->'shared'->>'sourceCount')::integer,
 'unallocatedSharedCost',source_snapshot->'shared'->>'unallocatedSiteCost') ELSE '{}'::jsonb END
 ||CASE WHEN source_snapshot->>'format' IN ('profitpilot-source-trace-v4','profitpilot-source-trace-v5','profitpilot-source-trace-v6','profitpilot-source-trace-v7') THEN jsonb_build_object(
 'businessOverheadCost',source_snapshot->'businessOverhead'->>'cost',
 'businessOverheadSourceCount',(source_snapshot->'businessOverhead'->>'sourceCount')::integer,
 'unallocatedBusinessOverhead',source_snapshot->'businessOverhead'->>'unallocatedCost') ELSE '{}'::jsonb END
 ||CASE WHEN source_snapshot->>'format' IN ('profitpilot-source-trace-v5','profitpilot-source-trace-v6','profitpilot-source-trace-v7') THEN jsonb_build_object('grossRevenue',source_snapshot->>'grossRevenue',
 'customerCredit',source_snapshot->'credits'->>'customerCredit','supplierCredit',source_snapshot->'credits'->>'supplierCredit','creditCount',(source_snapshot->'credits'->>'creditCount')::integer,'creditReversalCount',coalesce((source_snapshot->'credits'->>'reversalCount')::integer,0)) ELSE '{}'::jsonb END
 ||CASE WHEN source_snapshot->>'format' IN ('profitpilot-source-trace-v6','profitpilot-source-trace-v7') THEN jsonb_build_object(
 'siteOverheadCredit',source_snapshot->'overheadCredits'->>'siteCredit','businessOverheadCredit',source_snapshot->'overheadCredits'->>'businessCredit',
 'siteRemainderCredit',source_snapshot->'overheadCredits'->>'siteRemainderCredit','businessRemainderCredit',source_snapshot->'overheadCredits'->>'businessRemainderCredit',
 'sharedCreditEventCount',(source_snapshot->'overheadCredits'->>'eventCount')::integer) ELSE '{}'::jsonb END
 ||CASE WHEN source_snapshot->>'format'='profitpilot-source-trace-v7' THEN jsonb_build_object(
 'nonSitePayrollCost',source_snapshot->'nonSitePayroll'->>'cost','nonSitePayrollSourceCount',(source_snapshot->'nonSitePayroll'->>'sourceCount')::integer,
 'unallocatedNonSitePayroll',source_snapshot->'nonSitePayroll'->>'unallocatedCost') ELSE '{}'::jsonb END
 FROM private.calculation_source_receipts WHERE tenant_id=p_tenant AND calculation_id=p_run),jsonb_build_object('status','legacy_unavailable'))
$fn$;
CREATE OR REPLACE FUNCTION private.assert_shared_calculation_current(t uuid,r uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog AS $fn$
BEGIN
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('profitpilot-workspace:'||t::text,0));
 IF EXISTS(SELECT 1 FROM private.calculation_source_receipts c
 CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN c.source_snapshot->>'format' IN ('profitpilot-source-trace-v3','profitpilot-source-trace-v4','profitpilot-source-trace-v5','profitpilot-source-trace-v6','profitpilot-source-trace-v7') THEN (c.source_snapshot->'shared'->'lines')||coalesce(c.source_snapshot->'businessOverhead'->'lines','[]'::jsonb)||coalesce(c.source_snapshot->'nonSitePayroll'->'lines','[]'::jsonb) ELSE '[]'::jsonb END) l
 JOIN private.shared_cost_revisions x ON x.tenant_id=t AND x.source_kind=l->>0 AND x.source_id::text=l->>1 AND x.prior_order_id::text=l->>3
 WHERE c.tenant_id=t AND c.calculation_id=r)
 THEN RAISE EXCEPTION 'Calculation requires reconciliation after shared cost correction' USING ERRCODE='P4503'; END IF;
END $fn$;
CREATE OR REPLACE FUNCTION private.api_financial_coverage(t uuid,c uuid,action text,scope text,auth bigint,iat bigint,session_digest text,expiry bigint,nonce text,key_id text,signature text,s uuid,starts date,ends date)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $fn$
DECLARE actor uuid; baseline uuid; n integer; tax text; supplier jsonb; shared jsonb; business jsonb; credits jsonb; credit_review jsonb; overhead_credits jsonb; non_site jsonb; imports jsonb; payroll jsonb; invoices jsonb; pending jsonb; blockers jsonb:='[]'::jsonb; gaps jsonb; result jsonb;
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
  overhead_credits:=private.shared_overhead_credit_snapshot(t,c,s,starts,ends,baseline);
  non_site:=private.non_site_payroll_snapshot(t,c,s,starts,ends,baseline);
  WITH pending_orders AS MATERIALIZED (
   SELECT q.order_id,q.amount,q.reverses_order_id,d.decision FROM private.invoice_credit_orders q
   JOIN private.security_work_orders w ON w.tenant_id=q.tenant_id AND w.id=q.order_id
   LEFT JOIN private.security_work_decisions d ON d.tenant_id=q.tenant_id AND d.order_id=q.order_id
   LEFT JOIN private.invoice_credit_receipts r ON r.tenant_id=q.tenant_id AND r.order_id=q.order_id
   WHERE q.tenant_id=t AND ((q.allocation_order_id IS NULL AND q.source_snapshot->>'contractId'=c::text AND q.source_snapshot->>'siteId'=s::text) OR (q.allocation_order_id IS NOT NULL AND ((q.source_snapshot->>'kind'='overhead' AND q.source_snapshot->>'siteId'=s::text) OR (q.source_snapshot->>'kind'='business_overhead' AND q.source_snapshot->>'businessId'=(SELECT si.business_id::text FROM public.sites si WHERE si.tenant_id=t AND si.id=s)))))
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
  IF (credits->>'invalid')::boolean OR (overhead_credits->>'invalid')::boolean THEN blockers:=blockers||'"CREDIT_SCOPE_INVALID"'::jsonb; END IF;
  gaps:=jsonb_build_array('EXTERNAL_SOURCE_COMPLETENESS_UNVERIFIED','CREDITS_AND_ADJUSTMENTS_NOT_RECONCILED','TENANT_WIDE_COSTS_NOT_ATTRIBUTED');
  IF (credit_review->>'pendingCount')::integer>0 THEN gaps:=gaps||'"CREDIT_REVIEW_OUTSTANDING"'::jsonb; END IF;
  IF (non_site->>'missingCount')::integer>0 OR (non_site->>'invalid')::boolean OR (non_site->>'unallocatedCost')::numeric>0 THEN gaps:=gaps||'"NON_SITE_PAYROLL_RECONCILIATION_OUTSTANDING"'::jsonb; END IF;
  IF (imports->>'unresolvedCount')::integer>0 OR (imports->>'acceptedWithoutMaterializationCount')::integer>0 OR (imports->>'failedOrRejectedCount')::integer>0 OR (imports->>'unknownPeriodCount')::integer>0 THEN gaps:=gaps||'"IMPORT_RECONCILIATION_OUTSTANDING"'::jsonb; END IF;
  IF (payroll->>'unconfirmedPoolCount')::integer>0 OR (payroll->>'nonSiteAmountAUD')::numeric>0 OR (payroll->>'excludedAmountAUD')::numeric>0 OR (payroll->>'residualAmountAUD')::numeric>0 OR (payroll->>'partialPeriodPoolCount')::integer>0 OR (payroll->>'nonAudPoolCount')::integer>0 THEN gaps:=gaps||'"TENANT_PAYROLL_RECONCILIATION_OUTSTANDING"'::jsonb; END IF;
  IF (pending->>'unclassifiedCount')::integer>0 THEN gaps:=gaps||'"SUPPLIER_CLASSIFICATION_OUTSTANDING"'::jsonb; END IF;
  IF (invoices->>'pendingCount')::integer>0 OR (invoices->>'unreviewedConfirmedCount')::integer>0 OR (invoices->>'rejectedCount')::integer>0 THEN gaps:=gaps||'"INVOICE_RECONCILIATION_OUTSTANDING"'::jsonb; END IF;
  IF (shared->>'unallocatedSiteCost')::numeric>0 OR (business->>'unallocatedCost')::numeric>0 THEN gaps:=gaps||'"REVIEWED_UNALLOCATED_REMAINDER"'::jsonb; END IF;
  result:=jsonb_build_object('format','profitpilot-financial-coverage-v1','contractId',c,'siteId',s,'baselineId',baseline,'periodStart',starts,'periodEnd',ends,'status',CASE WHEN blockers='[]'::jsonb THEN 'indicative_only' ELSE 'blocked' END,'canAttemptCalculation',blockers='[]'::jsonb,'definitiveProfitAvailable',false,'blockers',blockers,'gaps',gaps,
   'scopeInvoices',invoices,'recordedCredits',credits-'lines','sharedOverheadCredits',overhead_credits-'lines','nonSitePayroll',non_site-'lines','canAttemptNonSiteCalculation',blockers='[]'::jsonb AND NOT (non_site->>'invalid')::boolean AND (non_site->>'missingCount')::integer=0,'creditReview',credit_review,'tenantImports',imports,'tenantPayroll',payroll,'tenantSupplier',pending,
   'shared',shared-'lines','businessOverhead',business-'lines'-'businessId',
   'missingNonSiteSources',(SELECT coalesce(jsonb_agg(jsonb_build_object('kind',x->>0,'sourceId',x->>1,'amount',x->2->>'amount')),'[]'::jsonb) FROM (SELECT x FROM jsonb_array_elements(non_site->'lines') x WHERE x->>3 IS NULL LIMIT 100) q),
   'missingSharedSources',(SELECT coalesce(jsonb_agg(jsonb_build_object('kind',x->>0,'sourceId',x->>1,'amount',x->2->>'amount')),'[]'::jsonb) FROM (SELECT x FROM jsonb_array_elements((shared->'lines')||(business->'lines')) x WHERE x->>3 IS NULL LIMIT 100) q));
 END IF;
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,metadata) VALUES(t,actor,'financial_coverage_read','contract',c,jsonb_build_object('siteId',s,'periodStart',starts,'periodEnd',ends,'status',result->>'status'));
 PERFORM private.sensitive_api_fresh(auth,expiry);
 RETURN result||jsonb_build_object('asOf',clock_timestamp(),'notice','Point-in-time diagnostic only. Tenant-wide amounts are contextual and not attributable to this contract; omitted sources and external accounting completeness remain unverified. Calculation revalidates current inputs.');
END $fn$;
CREATE OR REPLACE FUNCTION private.verify_security_catalog() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT digest=private.security_catalog_digest() FROM private.security_catalog_baseline WHERE revision=82),false)
$fn$;
INSERT INTO private.security_catalog_baseline(singleton,revision,digest) VALUES(true,82,private.security_catalog_digest());
COMMIT;

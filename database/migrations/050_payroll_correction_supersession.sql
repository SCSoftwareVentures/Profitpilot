-- Confirmed payroll corrections by atomic supersession, never in-place editing.
-- Operator-only candidate path: no new customer API or direct table grants.
BEGIN;
DO $check$ BEGIN
 IF private.verify_security_catalog() IS DISTINCT FROM true THEN RAISE EXCEPTION 'Prior security catalog does not verify'; END IF;
END $check$;
CREATE TABLE private.payroll_correction_reservations(
 tenant_id uuid NOT NULL,order_id uuid NOT NULL,old_run_id uuid NOT NULL,new_run_id uuid NOT NULL,proposal_id uuid NOT NULL,
 reason_code text NOT NULL CHECK(reason_code IN ('allocation_error','source_correction','duplicate_source','privacy_correction')),
 evidence_digest text NOT NULL CHECK(evidence_digest ~ '^[a-f0-9]{64}$' AND evidence_digest<>repeat('0',64)),
 scope_digest text NOT NULL CHECK(scope_digest ~ '^[a-f0-9]{64}$' AND scope_digest<>repeat('0',64)),
 reserved_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,order_id),UNIQUE(tenant_id,new_run_id),
 UNIQUE(tenant_id,order_id,old_run_id,new_run_id),
 FOREIGN KEY(tenant_id,order_id) REFERENCES private.security_work_orders(tenant_id,id),
 FOREIGN KEY(tenant_id,old_run_id) REFERENCES private.payroll_confirmation_receipts(tenant_id,allocation_run_id),
 FOREIGN KEY(tenant_id,new_run_id) REFERENCES public.allocation_runs(tenant_id,id),
 FOREIGN KEY(tenant_id,proposal_id) REFERENCES private.payroll_proposal_reviews(tenant_id,id),
 CHECK(old_run_id<>new_run_id)
);
CREATE TABLE private.payroll_supersessions(
 tenant_id uuid NOT NULL,order_id uuid NOT NULL,old_run_id uuid NOT NULL,new_run_id uuid NOT NULL,
 period_start date NOT NULL,period_end date NOT NULL,superseded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,old_run_id), UNIQUE(tenant_id,new_run_id), UNIQUE(tenant_id,order_id),
 FOREIGN KEY(tenant_id,order_id,old_run_id,new_run_id) REFERENCES private.payroll_correction_reservations(tenant_id,order_id,old_run_id,new_run_id),
 FOREIGN KEY(tenant_id,order_id) REFERENCES private.security_work_consumptions(tenant_id,order_id),
 FOREIGN KEY(tenant_id,new_run_id) REFERENCES private.payroll_confirmation_receipts(tenant_id,allocation_run_id) DEFERRABLE INITIALLY DEFERRED,
 CHECK(old_run_id<>new_run_id AND period_end>=period_start)
);
REVOKE ALL ON private.payroll_correction_reservations,private.payroll_supersessions FROM PUBLIC,profitpilot_app;
CREATE TRIGGER payroll_correction_reservation_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON private.payroll_correction_reservations FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();
CREATE TRIGGER payroll_supersession_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON private.payroll_supersessions FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();

-- A designated replacement cannot enter ordinary confirmation; its exact
-- supersession and new confirmation receipt must commit together.
CREATE FUNCTION private.guard_payroll_replacement_confirmation()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
BEGIN
 IF NEW.status='confirmed' AND EXISTS(SELECT 1 FROM private.payroll_correction_reservations WHERE tenant_id=NEW.tenant_id AND new_run_id=NEW.id)
 AND NOT EXISTS(SELECT 1 FROM private.payroll_supersessions WHERE tenant_id=NEW.tenant_id AND new_run_id=NEW.id) THEN
  RAISE EXCEPTION 'Replacement confirmation requires atomic supersession' USING ERRCODE='42501'; END IF;
 RETURN NEW;
END $fn$;
CREATE TRIGGER allocation_runs_replacement_guard BEFORE INSERT OR UPDATE ON public.allocation_runs FOR EACH ROW EXECUTE FUNCTION private.guard_payroll_replacement_confirmation();

CREATE FUNCTION private.payroll_correction_scope(p_tenant uuid,p_old uuid,p_proposal uuid,p_reason text,p_evidence text)
RETURNS text LANGUAGE plpgsql SET search_path=pg_catalog SET timezone='UTC' AS $fn$
DECLARE old_receipt private.payroll_confirmation_receipts%ROWTYPE; proposed private.payroll_proposal_reviews%ROWTYPE;
 old_pool public.payroll_pools%ROWTYPE; new_pool public.payroll_pools%ROWTYPE; old_amount numeric; new_digest text;
BEGIN
 PERFORM private.payroll_review_actor(p_tenant,true);
 IF coalesce(private.current_actor_role(),'') NOT IN ('owner','admin') OR p_old IS NULL OR p_proposal IS NULL
 OR p_reason IS NULL OR p_reason NOT IN ('allocation_error','source_correction','duplicate_source','privacy_correction')
 OR p_evidence IS NULL OR p_evidence !~ '^[a-f0-9]{64}$' OR p_evidence=repeat('0',64)
 THEN RAISE EXCEPTION 'Payroll correction authority denied' USING ERRCODE='42501'; END IF;
 SELECT * INTO old_receipt FROM private.payroll_confirmation_receipts WHERE tenant_id=p_tenant AND allocation_run_id=p_old;
 IF NOT FOUND OR EXISTS(SELECT 1 FROM private.payroll_supersessions WHERE tenant_id=p_tenant AND old_run_id=p_old) THEN
  RAISE EXCEPTION 'Payroll correction target unavailable' USING ERRCODE='42501'; END IF;
 SELECT * INTO proposed FROM private.payroll_proposal_reviews WHERE tenant_id=p_tenant AND id=p_proposal FOR UPDATE;
 IF NOT FOUND OR proposed.allocation_run_id=p_old OR EXISTS(SELECT 1 FROM private.payroll_proposal_decisions WHERE tenant_id=p_tenant AND proposal_id=p_proposal) THEN
  RAISE EXCEPTION 'Replacement proposal unavailable' USING ERRCODE='42501'; END IF;
 new_digest:=private.payroll_review_digest(p_tenant,proposed.allocation_run_id);
 IF new_digest IS DISTINCT FROM proposed.evidence_digest THEN RAISE EXCEPTION 'Replacement evidence changed' USING ERRCODE='23514'; END IF;
 SELECT p.* INTO old_pool FROM public.allocation_runs r JOIN public.payroll_pools p ON p.tenant_id=r.tenant_id AND p.id=r.payroll_pool_id
 WHERE r.tenant_id=p_tenant AND r.id=p_old AND r.status='confirmed';
 IF NOT FOUND THEN RAISE EXCEPTION 'Correction target unavailable' USING ERRCODE='42501'; END IF;
 SELECT p.* INTO new_pool FROM public.allocation_runs r JOIN public.payroll_pools p ON p.tenant_id=r.tenant_id AND p.id=r.payroll_pool_id
 WHERE r.tenant_id=p_tenant AND r.id=proposed.allocation_run_id AND r.status='review';
 IF NOT FOUND OR new_pool.id=old_pool.id OR new_pool.batch_id=old_pool.batch_id
 OR ROW(new_pool.period_start,new_pool.period_end,new_pool.currency) IS DISTINCT FROM ROW(old_pool.period_start,old_pool.period_end,old_pool.currency)
 THEN RAISE EXCEPTION 'Replacement must have distinct source and matching period/currency' USING ERRCODE='23514'; END IF;
 RETURN encode(public.digest(convert_to(jsonb_build_array('payroll-correction-v1',p_tenant,p_old,old_receipt.evidence_digest,p_proposal,proposed.allocation_run_id,new_digest,p_reason,p_evidence)::text,'UTF8'),'sha256'),'hex');
END $fn$;

CREATE FUNCTION private.request_payroll_correction(
 p_tenant uuid,p_order uuid,p_old uuid,p_proposal uuid,p_reason text,p_evidence text,p_scope text,
 p_auth bigint,p_iat bigint,p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE replacement uuid;
BEGIN
 PERFORM private.security_work_actor(p_tenant,p_order,'privileged_operation',p_scope,'request',p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 PERFORM pg_advisory_xact_lock(hashtextextended('payroll-correction:'||p_tenant::text,0));
 IF private.payroll_correction_scope(p_tenant,p_old,p_proposal,p_reason,p_evidence) IS DISTINCT FROM p_scope THEN
  RAISE EXCEPTION 'Payroll correction scope changed' USING ERRCODE='42501'; END IF;
 SELECT allocation_run_id INTO replacement FROM private.payroll_proposal_reviews WHERE tenant_id=p_tenant AND id=p_proposal;
 PERFORM private.record_security_work(p_tenant,p_order,'privileged_operation',p_scope,'request',p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 INSERT INTO private.payroll_correction_reservations(tenant_id,order_id,old_run_id,new_run_id,proposal_id,reason_code,evidence_digest,scope_digest)
 VALUES(p_tenant,p_order,p_old,replacement,p_proposal,p_reason,p_evidence,p_scope);
END $fn$;

-- Both separate proofs are required: a dual-approved correction order and
-- a recent-MFA confirmation of the actual reviewed replacement proposal.
CREATE FUNCTION private.execute_payroll_correction(
 p_tenant uuid,p_order uuid,p_scope text,p_auth bigint,p_iat bigint,p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text,
 p_confirm_nonce text,p_confirm_signature text)
RETURNS uuid LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE actor uuid; q private.payroll_correction_reservations%ROWTYPE; p public.payroll_pools%ROWTYPE; d text; confirmed uuid;
BEGIN
 actor:=private.security_work_actor(p_tenant,p_order,'privileged_operation',p_scope,'consume',p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 PERFORM pg_advisory_xact_lock(hashtextextended('payroll-correction:'||p_tenant::text,0));
 SELECT * INTO q FROM private.payroll_correction_reservations WHERE tenant_id=p_tenant AND order_id=p_order FOR UPDATE;
 IF NOT FOUND OR q.scope_digest IS DISTINCT FROM p_scope
 OR private.payroll_correction_scope(p_tenant,q.old_run_id,q.proposal_id,q.reason_code,q.evidence_digest) IS DISTINCT FROM p_scope THEN
  RAISE EXCEPTION 'Payroll correction scope changed' USING ERRCODE='42501'; END IF;
 SELECT p2.* INTO p FROM public.allocation_runs r JOIN public.payroll_pools p2 ON p2.tenant_id=r.tenant_id AND p2.id=r.payroll_pool_id
 WHERE r.tenant_id=p_tenant AND r.id=q.new_run_id;
 SELECT evidence_digest INTO d FROM private.payroll_proposal_reviews WHERE tenant_id=p_tenant AND id=q.proposal_id;
 PERFORM private.record_security_work(p_tenant,p_order,'privileged_operation',p_scope,'consume',p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 INSERT INTO private.payroll_supersessions(tenant_id,order_id,old_run_id,new_run_id,period_start,period_end)
 VALUES(p_tenant,p_order,q.old_run_id,q.new_run_id,p.period_start,p.period_end);
 confirmed:=private.confirm_payroll_proposal_attested(p_tenant,q.proposal_id,d,p_auth,p_iat,p_session,p_expires,p_confirm_nonce,p_key,p_confirm_signature);
 IF confirmed IS DISTINCT FROM q.new_run_id THEN RAISE EXCEPTION 'Wrong payroll replacement' USING ERRCODE='23514'; END IF;
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,metadata)
 VALUES(p_tenant,actor,'payroll_record_superseded','allocation_run',q.old_run_id,jsonb_build_object('replacementRunId',confirmed,'orderId',p_order,'reasonCode',q.reason_code));
 RETURN confirmed;
END $fn$;

-- Existing saved calculations are snapshots. Conservatively refuse stale
-- overlapping calculations across the entire tenant, rather than returning
-- figures computed from superseded payroll. Recalculate from active records.
CREATE FUNCTION private.assert_calculation_not_superseded(p_tenant uuid,p_start date,p_end date,p_created timestamptz)
RETURNS void LANGUAGE plpgsql STABLE SET search_path=pg_catalog AS $fn$
BEGIN
 IF EXISTS(SELECT 1 FROM private.payroll_supersessions WHERE tenant_id=p_tenant
  AND period_start<=p_end AND period_end>=p_start AND superseded_at>=p_created)
 THEN RAISE EXCEPTION 'Calculation requires reconciliation after payroll correction' USING ERRCODE='P4502'; END IF;
END $fn$;
REVOKE ALL ON FUNCTION private.guard_payroll_replacement_confirmation(),private.payroll_correction_scope(uuid,uuid,uuid,text,text),
 private.request_payroll_correction(uuid,uuid,uuid,uuid,text,text,text,bigint,bigint,text,bigint,text,text,text),
 private.execute_payroll_correction(uuid,uuid,text,bigint,bigint,text,bigint,text,text,text,text,text),
 private.assert_calculation_not_superseded(uuid,date,date,timestamptz) FROM PUBLIC,profitpilot_app;

CREATE OR REPLACE FUNCTION private.site_payroll_summary(p_tenant uuid,p_site uuid,p_start date,p_end date)
RETURNS TABLE(partial_count bigint,amount numeric,line_count bigint,currency_count bigint,payroll_currency text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE actor uuid;
BEGIN
 IF p_tenant IS NULL OR private.current_tenant_id() IS DISTINCT FROM p_tenant OR coalesce(private.current_actor_role(),'') NOT IN ('owner','admin','analyst','reviewer') THEN
  RAISE EXCEPTION 'Payroll summary authority denied' USING ERRCODE='42501';
 END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('payroll-correction:'||p_tenant::text,0));
 actor:=private.consume_financial_access_budget(p_tenant,'payroll_summary');
 IF p_site IS NULL OR p_start IS NULL OR p_end IS NULL OR NOT isfinite(p_start) OR NOT isfinite(p_end) OR p_end<p_start
 OR NOT EXISTS(SELECT 1 FROM public.sites WHERE tenant_id=p_tenant AND id=p_site) THEN
  RAISE EXCEPTION 'Invalid payroll summary scope' USING ERRCODE='22023';
 END IF;
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id)
 VALUES(p_tenant,actor,'payroll_summary_accessed','site',p_site);
 RETURN QUERY SELECT
 count(*) FILTER(WHERE pp.period_start<=p_end AND pp.period_end>=p_start AND NOT (pp.period_start>=p_start AND pp.period_end<=p_end)),
 coalesce(sum(al.amount) FILTER(WHERE al.bucket_type IN ('direct','approved_allocated') AND pp.period_start>=p_start AND pp.period_end<=p_end),0)::numeric(14,2),
 count(*) FILTER(WHERE al.bucket_type IN ('direct','approved_allocated') AND pp.period_start>=p_start AND pp.period_end<=p_end),
 count(DISTINCT pp.currency) FILTER(WHERE al.bucket_type IN ('direct','approved_allocated') AND pp.period_start>=p_start AND pp.period_end<=p_end),
 min(pp.currency::text) FILTER(WHERE al.bucket_type IN ('direct','approved_allocated') AND pp.period_start>=p_start AND pp.period_end<=p_end)
 FROM public.allocation_lines al JOIN public.allocation_runs ar ON ar.id=al.allocation_run_id AND ar.tenant_id=al.tenant_id
 JOIN public.payroll_pools pp ON pp.id=ar.payroll_pool_id AND pp.tenant_id=ar.tenant_id
 WHERE al.tenant_id=p_tenant AND al.site_id=p_site AND ar.status='confirmed'
 AND pp.period_start<=p_end AND pp.period_end>=p_start
 AND NOT EXISTS(SELECT 1 FROM private.payroll_supersessions x WHERE x.tenant_id=ar.tenant_id AND x.old_run_id=ar.id);
END $fn$;

CREATE OR REPLACE FUNCTION private.read_calculation_summary(p_tenant uuid,p_run uuid)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE r public.calculation_runs%ROWTYPE; actor uuid;
BEGIN
 IF p_tenant IS NULL OR private.current_tenant_id() IS DISTINCT FROM p_tenant OR coalesce(private.current_actor_role(),'') NOT IN ('owner','admin','analyst','reviewer','read_only') THEN
  RAISE EXCEPTION 'Calculation read authority denied' USING ERRCODE='42501';
 END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('payroll-correction:'||p_tenant::text,0));
 actor:=private.consume_financial_access_budget(p_tenant,'calculation_read');
 SELECT * INTO r FROM public.calculation_runs WHERE tenant_id=p_tenant AND id=p_run;
 IF NOT FOUND THEN RETURN NULL; END IF;
 PERFORM private.assert_calculation_not_superseded(p_tenant,r.period_start,r.period_end,r.created_at);
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id)
 VALUES(p_tenant,actor,'calculation_summary_read','calculation_run',r.id);
 RETURN jsonb_build_object('id',r.id,'contract_id',r.contract_id,'site_id',r.site_id,
 'period_start',r.period_start,'period_end',r.period_end,'completeness',r.completeness,'created_at',r.created_at,
 'formula_version',CASE WHEN r.formula_version ~ '^[0-9]{1,4}[.][0-9]{1,4}[.][0-9]{1,4}$' THEN r.formula_version ELSE NULL END,
 'outputs',jsonb_build_object('currency',CASE WHEN r.outputs->>'currency' ~ '^[A-Z]{3}$' THEN r.outputs->>'currency' ELSE NULL END,
 'revenue',private.safe_export_money(r.outputs->'revenue'),
 'deliveryCost',private.safe_export_money(r.outputs->'deliveryCost'),
 'indicativeContribution',private.safe_export_money(r.outputs->'indicativeContribution'),
 'contribution',CASE WHEN r.completeness='complete' THEN private.safe_export_money(r.outputs->'contribution') ELSE NULL END,
 'marginPercent',CASE WHEN r.completeness='complete' THEN private.safe_export_money(r.outputs->'marginPercent') ELSE NULL END,
 'completeness',r.completeness,'limitations',jsonb_build_array('Management calculation only; not statutory or audited profit.','Source records and arbitrary stored notes are not included.')));
END $fn$;

CREATE OR REPLACE FUNCTION private.export_calculation_summary(p_tenant uuid,p_run uuid,p_purpose text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE record_row public.calculation_runs%ROWTYPE; actor uuid; event_id uuid; summary jsonb;
BEGIN
 IF p_tenant IS NULL OR p_run IS NULL OR private.current_tenant_id() IS DISTINCT FROM p_tenant
 OR coalesce(private.current_actor_role(),'') NOT IN ('owner','admin') THEN
  RAISE EXCEPTION 'Export authority denied' USING ERRCODE='42501';
 END IF;
 IF p_purpose IS NULL OR p_purpose NOT IN ('internal_review','customer_reporting','accountant_review') THEN
  RAISE EXCEPTION 'Invalid export purpose' USING ERRCODE='22023';
 END IF;
 SELECT u.id INTO actor FROM public.users u
 JOIN public.tenant_memberships tm ON tm.user_id=u.id
 JOIN public.tenants t ON t.id=tm.tenant_id
 WHERE u.auth_subject=nullif(current_setting('app.tenant_subject',true),'')
 AND u.status='active' AND tm.tenant_id=p_tenant AND tm.status='active'
 AND tm.role IN ('owner','admin') AND t.status='active'
 FOR SHARE OF u,tm,t;
 IF NOT FOUND THEN RAISE EXCEPTION 'Export authority denied' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('payroll-correction:'||p_tenant::text,0));
 PERFORM private.consume_financial_access_budget(p_tenant,'calculation_export');
 SELECT * INTO record_row FROM public.calculation_runs WHERE tenant_id=p_tenant AND id=p_run;
 IF NOT FOUND THEN RETURN NULL; END IF;
 PERFORM private.assert_calculation_not_superseded(p_tenant,record_row.period_start,record_row.period_end,record_row.created_at);
 INSERT INTO private.calculation_export_events(tenant_id,actor_user_id,calculation_id,purpose)
 VALUES(p_tenant,actor,p_run,p_purpose) RETURNING id INTO event_id;
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,metadata)
 VALUES(p_tenant,actor,'calculation_summary_exported','calculation_run',p_run,jsonb_build_object('purpose',p_purpose,'exportId',event_id));
 summary:=jsonb_build_object(
  'exportId',event_id,'calculationId',record_row.id,'contractId',record_row.contract_id,'siteId',record_row.site_id,
  'periodStart',record_row.period_start,'periodEnd',record_row.period_end,
  'completeness',record_row.completeness,
  'currency',CASE WHEN (record_row.outputs->>'currency') ~ '^[A-Z]{3}$' THEN record_row.outputs->>'currency' ELSE NULL END,
  'revenue',private.safe_export_money(record_row.outputs->'revenue'),
  'deliveryCost',private.safe_export_money(record_row.outputs->'deliveryCost'),
  'indicativeContribution',private.safe_export_money(record_row.outputs->'indicativeContribution'),
  'contribution',CASE WHEN record_row.completeness='complete' THEN private.safe_export_money(record_row.outputs->'contribution') ELSE NULL END,
  'marginPercent',CASE WHEN record_row.completeness='complete' THEN private.safe_export_money(record_row.outputs->'marginPercent') ELSE NULL END,
  'notice','Management calculation only; not audited or statutory profit.'
 );
 RETURN summary;
END $fn$;

CREATE OR REPLACE FUNCTION private.payroll_api_summary(p_tenant uuid,p_proposal uuid)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE pr private.payroll_proposal_reviews%ROWTYPE; outcome text; result jsonb;
BEGIN
 SELECT * INTO pr FROM private.payroll_proposal_reviews WHERE tenant_id=p_tenant AND id=p_proposal FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Proposal unavailable' USING ERRCODE='42501'; END IF;
 IF EXISTS(SELECT 1 FROM private.payroll_supersessions WHERE tenant_id=p_tenant AND old_run_id=pr.allocation_run_id) THEN
  RETURN jsonb_build_object('proposalId',pr.id,'evidenceDigest',pr.evidence_digest,'status','superseded'); END IF;
 SELECT decision INTO outcome FROM private.payroll_proposal_decisions WHERE tenant_id=p_tenant AND proposal_id=p_proposal;
 IF outcome='reviewed' AND NOT EXISTS(SELECT 1 FROM private.payroll_confirmation_receipts WHERE tenant_id=p_tenant AND proposal_id=p_proposal AND evidence_digest=pr.evidence_digest) THEN
  RETURN jsonb_build_object('proposalId',pr.id,'evidenceDigest',pr.evidence_digest,'status','reviewed_not_confirmed'); END IF;
 IF outcome='rejected' THEN RETURN jsonb_build_object('proposalId',pr.id,'evidenceDigest',pr.evidence_digest,'status','rejected'); END IF;
 IF outcome IS NULL AND private.payroll_review_digest(p_tenant,pr.allocation_run_id) IS DISTINCT FROM pr.evidence_digest THEN
  RAISE EXCEPTION 'Proposal evidence changed' USING ERRCODE='23514'; END IF;
 SELECT jsonb_build_object('proposalId',pr.id,'allocationRunId',r.id,'evidenceDigest',pr.evidence_digest,
  'status',CASE WHEN r.status='confirmed' THEN 'confirmed' WHEN outcome='reviewed' THEN 'reviewed' ELSE 'pending_review' END,
  'currency',p.currency,'periodStart',p.period_start,'periodEnd',p.period_end,
  'total',p.total_amount::text,'direct',r.direct_amount::text,'allocated',r.allocated_amount::text,
  'nonSite',r.non_site_amount::text,'excluded',r.excluded_amount::text,'residual',r.residual_amount::text)
 INTO result FROM public.allocation_runs r JOIN public.payroll_pools p ON p.tenant_id=r.tenant_id AND p.id=r.payroll_pool_id
 WHERE r.tenant_id=p_tenant AND r.id=pr.allocation_run_id;
 IF result IS NULL THEN RAISE EXCEPTION 'Proposal unavailable' USING ERRCODE='42501'; END IF;
 RETURN result;
END $fn$;

CREATE OR REPLACE FUNCTION private.verify_security_catalog()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT digest=private.security_catalog_digest() FROM private.security_catalog_baseline WHERE revision=50),false)
$fn$;
INSERT INTO private.security_catalog_baseline(singleton,revision,digest) VALUES(true,50,private.security_catalog_digest());
COMMIT;

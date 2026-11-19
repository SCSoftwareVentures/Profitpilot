-- Materialize deterministic candidate site allocation from accepted source facts.
-- No guessed site, no direct-coded claim, no automatic financial confirmation.
BEGIN;
DO $check$ BEGIN
 IF private.verify_security_catalog() IS DISTINCT FROM true THEN RAISE EXCEPTION 'Prior security catalog does not verify'; END IF;
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
 IF p_action IS NULL OR p_action NOT IN ('payroll_submit','payroll_read','account_read','account_correct_email','invoice_disposal_preview','privacy_case_request','privacy_case_status','privacy_case_intake','privacy_case_acknowledge','privacy_case_resolve','privacy_case_refuse','payroll_correction_preview','payroll_correction_status','privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status','privacy_key_revoke','payroll_intake_preview','payroll_intake_status','payroll_allocation_build','payroll_allocation_status')
 OR (p_action IN ('privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status','privacy_key_revoke','payroll_intake_preview','payroll_intake_status','payroll_allocation_build','payroll_allocation_status') AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('payroll_correction_preview','payroll_correction_status') AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('privacy_case_intake','privacy_case_acknowledge','privacy_case_resolve','privacy_case_refuse') AND actor_role NOT IN ('owner','admin'))
 OR (p_action='payroll_submit' AND actor_role NOT IN ('owner','admin','analyst'))
 OR (p_action='payroll_read' AND actor_role NOT IN ('owner','admin','reviewer'))
 OR (p_action='invoice_disposal_preview' AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('account_read','account_correct_email') AND p_target<>p_tenant)
 THEN RAISE EXCEPTION 'Sensitive operation denied' USING ERRCODE='42501'; END IF;
 now_s:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 IF p_scope IS NULL OR p_scope !~ '^[a-f0-9]{64}$'
 OR (p_action IN ('account_correct_email','privacy_case_request','privacy_case_intake','privacy_case_resolve','privacy_case_refuse','payroll_correction_preview','privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status','privacy_key_revoke','payroll_intake_preview','payroll_intake_status','payroll_allocation_build','payroll_allocation_status') AND p_scope=repeat('0',64))
 OR (p_action NOT IN ('account_correct_email','privacy_case_request','privacy_case_intake','privacy_case_resolve','privacy_case_refuse','payroll_correction_preview','privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status','privacy_key_revoke','payroll_intake_preview','payroll_intake_status','payroll_allocation_build','payroll_allocation_status') AND p_scope<>repeat('0',64))
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








CREATE TABLE private.payroll_allocation_builds(
 tenant_id uuid NOT NULL,pool_id uuid NOT NULL,run_id uuid NOT NULL,actor_id uuid NOT NULL,
 scope_digest text NOT NULL CHECK(scope_digest ~ '^[a-f0-9]{64}$' AND scope_digest<>repeat('0',64)),
 proposal_id uuid,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,run_id),UNIQUE(tenant_id,pool_id,scope_digest),
 FOREIGN KEY(tenant_id,pool_id) REFERENCES private.payroll_intake_receipts(tenant_id,pool_id),
 FOREIGN KEY(tenant_id,run_id) REFERENCES public.allocation_runs(tenant_id,id),
 FOREIGN KEY(tenant_id,actor_id) REFERENCES public.tenant_memberships(tenant_id,user_id),
 FOREIGN KEY(tenant_id,proposal_id) REFERENCES private.payroll_proposal_reviews(tenant_id,id)
);
CREATE INDEX payroll_allocation_builds_pool_idx ON private.payroll_allocation_builds(tenant_id,pool_id);
REVOKE ALL ON private.payroll_allocation_builds FROM PUBLIC,profitpilot_app;
CREATE TRIGGER payroll_allocation_builds_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON private.payroll_allocation_builds FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();

-- A sealed candidate can only advance from review to receipt-backed confirmation.
CREATE FUNCTION private.guard_sealed_payroll_candidate()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE t uuid; r uuid;
BEGIN
 IF TG_TABLE_NAME='allocation_lines' THEN t:=NEW.tenant_id;r:=NEW.allocation_run_id;
 ELSE t:=OLD.tenant_id;r:=OLD.id; END IF;
 IF EXISTS(SELECT 1 FROM private.payroll_allocation_builds WHERE tenant_id=t AND run_id=r) THEN
  IF TG_TABLE_NAME='allocation_runs' AND TG_OP='UPDATE' THEN
   IF OLD.status='review' AND NEW.status='confirmed' AND OLD.reviewer_id IS NULL AND NEW.reviewer_id IS NOT NULL
   AND (to_jsonb(OLD)-ARRAY['status','reviewer_id'])=(to_jsonb(NEW)-ARRAY['status','reviewer_id'])
   AND EXISTS(SELECT 1 FROM private.payroll_confirmation_receipts WHERE tenant_id=t AND allocation_run_id=r AND reviewer_id=NEW.reviewer_id)
   THEN RETURN NEW; END IF;
  END IF;
  RAISE EXCEPTION 'Sealed payroll candidate is immutable' USING ERRCODE='55000';
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $fn$;
CREATE TRIGGER sealed_payroll_candidate_run BEFORE UPDATE OR DELETE ON public.allocation_runs FOR EACH ROW EXECUTE FUNCTION private.guard_sealed_payroll_candidate();
CREATE TRIGGER sealed_payroll_candidate_line BEFORE INSERT ON public.allocation_lines FOR EACH ROW EXECUTE FUNCTION private.guard_sealed_payroll_candidate();
REVOKE ALL ON FUNCTION private.guard_sealed_payroll_candidate() FROM PUBLIC,profitpilot_app;

CREATE FUNCTION private.payroll_allocation_build_summary(p_tenant uuid,p_pool uuid,p_run uuid)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE result jsonb;
BEGIN
 SELECT jsonb_build_object('poolId',b.pool_id,'allocationRunId',b.run_id,'proposalId',b.proposal_id,
 'evidenceDigest',pr.evidence_digest,'status',CASE
 WHEN EXISTS(SELECT 1 FROM private.payroll_supersessions x WHERE x.tenant_id=b.tenant_id AND x.old_run_id=b.run_id) THEN 'superseded'
 WHEN r.status='confirmed' THEN 'confirmed'
 WHEN d.decision='rejected' THEN 'rejected'
 WHEN r.residual_amount>0 THEN 'needs_allocation' ELSE 'pending_review' END,
 'total',p.total_amount::text,'currency',p.currency,'periodStart',p.period_start,'periodEnd',p.period_end,
 'direct',r.direct_amount::text,'allocated',r.allocated_amount::text,'nonSite',r.non_site_amount::text,
 'excluded',r.excluded_amount::text,'residual',r.residual_amount::text,'allocationConfirmed',r.status='confirmed' AND NOT EXISTS(SELECT 1 FROM private.payroll_supersessions x WHERE x.tenant_id=b.tenant_id AND x.old_run_id=b.run_id))
 INTO result FROM private.payroll_allocation_builds b
 JOIN public.allocation_runs r ON r.tenant_id=b.tenant_id AND r.id=b.run_id AND r.payroll_pool_id=b.pool_id
 JOIN public.payroll_pools p ON p.tenant_id=b.tenant_id AND p.id=b.pool_id
 LEFT JOIN private.payroll_proposal_reviews pr ON pr.tenant_id=b.tenant_id AND pr.id=b.proposal_id
 LEFT JOIN private.payroll_proposal_decisions d ON d.tenant_id=pr.tenant_id AND d.proposal_id=pr.id
 WHERE b.tenant_id=p_tenant AND b.pool_id=p_pool AND b.run_id=p_run;
 IF result IS NULL THEN RAISE EXCEPTION 'Allocation candidate unavailable' USING ERRCODE='42501'; END IF;
 RETURN result;
END $fn$;

CREATE FUNCTION private.api_payroll_allocation_build(
 p_tenant uuid,p_run uuid,p_action text,p_scope text,p_auth bigint,p_iat bigint,p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text,
 p_pool uuid,p_lines jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $fn$
DECLARE actor uuid; p public.payroll_pools%ROWTYPE; intake private.payroll_intake_receipts%ROWTYPE;
 item jsonb; canonical text; source_id uuid; source_amount numeric; site uuid; bucket text; value_text text; amount_value numeric;
 allocated numeric:=0; non_site numeric:=0; excluded numeric:=0; residual numeric; proposal uuid; line_digest text; duplicate_keys text[]:='{}'; line_key text;
BEGIN
 IF p_action IS DISTINCT FROM 'payroll_allocation_build' OR p_pool IS NULL OR p_run IS NULL
 OR p_lines IS NULL OR jsonb_typeof(p_lines)<>'array' OR octet_length(p_lines::text)>95000
 THEN RAISE EXCEPTION 'Allocation candidate denied' USING ERRCODE='23514'; END IF;
 IF jsonb_array_length(p_lines)>400 THEN RAISE EXCEPTION 'Allocation candidate exceeds capacity' USING ERRCODE='23514'; END IF;
 actor:=private.sensitive_api_actor(p_tenant,p_run,p_action,p_scope,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 canonical:='payroll-allocation-build-v1'||E'\n'||p_pool;
 FOR item IN SELECT value FROM jsonb_array_elements(p_lines) LOOP
  IF jsonb_typeof(item)<>'object' OR NOT(item ?& ARRAY['sourceRowKey','bucket','siteId','amount','evidenceRef'])
  OR (item-ARRAY['sourceRowKey','bucket','siteId','amount','evidenceRef'])<>'{}'::jsonb
  OR jsonb_typeof(item->'sourceRowKey') IS DISTINCT FROM 'string'
  OR jsonb_typeof(item->'bucket') IS DISTINCT FROM 'string'
  OR jsonb_typeof(item->'amount') IS DISTINCT FROM 'string'
  OR jsonb_typeof(item->'evidenceRef') IS DISTINCT FROM 'string'
  OR item->>'sourceRowKey' !~ '^ppr_[a-f0-9]{64}$' OR item->>'sourceRowKey'='ppr_'||repeat('0',64)
  OR item->>'bucket' NOT IN ('approved_allocated','non_site','excluded')
  OR item->>'amount' !~ '^(0|[1-9][0-9]{0,11})[.][0-9]{2}$' OR item->>'amount'='0.00'
  OR item->>'evidenceRef' !~ '^ev_[a-f0-9]{60}$' OR item->>'evidenceRef'='ev_'||repeat('0',60)
  THEN RAISE EXCEPTION 'Allocation mapping rejected' USING ERRCODE='23514'; END IF;
  IF item->>'bucket'='approved_allocated' THEN
   IF jsonb_typeof(item->'siteId') IS DISTINCT FROM 'string' OR item->>'siteId' !~ '^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$'
   THEN RAISE EXCEPTION 'Allocation site rejected' USING ERRCODE='23514'; END IF;
  ELSIF jsonb_typeof(item->'siteId') IS DISTINCT FROM 'null' THEN RAISE EXCEPTION 'Non-site mapping rejected' USING ERRCODE='23514'; END IF;
  line_key:=(item->>'sourceRowKey')||','||(item->>'bucket')||','||coalesce(item->>'siteId','');
  IF line_key=ANY(duplicate_keys) THEN RAISE EXCEPTION 'Duplicate allocation mapping' USING ERRCODE='23514'; END IF;
  duplicate_keys:=array_append(duplicate_keys,line_key);
  canonical:=canonical||E'\n'||line_key||','||(item->>'amount')||','||(item->>'evidenceRef');
 END LOOP;
 IF p_scope IS DISTINCT FROM encode(public.digest(convert_to(canonical,'UTF8'),'sha256'),'hex') THEN RAISE EXCEPTION 'Allocation mapping scope denied' USING ERRCODE='42501'; END IF;
 -- Same source inputs have one financial pool, bounded immutable candidate versions.
 PERFORM pg_advisory_xact_lock(hashtextextended('payroll-correction:'||p_tenant::text,0));
 SELECT * INTO intake FROM private.payroll_intake_receipts WHERE tenant_id=p_tenant AND pool_id=p_pool;
 IF NOT FOUND THEN RAISE EXCEPTION 'Reviewed source unavailable' USING ERRCODE='42501'; END IF;
 PERFORM 1 FROM public.import_batches WHERE tenant_id=p_tenant AND id=intake.batch_id AND status='accepted' FOR UPDATE;
 IF NOT FOUND OR EXISTS(SELECT 1 FROM private.import_disposal_controls WHERE tenant_id=p_tenant AND batch_id=intake.batch_id AND hold_active)
 OR EXISTS(SELECT 1 FROM private.import_disposal_tombstones WHERE tenant_id=p_tenant AND batch_id=intake.batch_id)
 THEN RAISE EXCEPTION 'Reviewed source held' USING ERRCODE='23514'; END IF;
 SELECT * INTO p FROM public.payroll_pools WHERE tenant_id=p_tenant AND id=p_pool FOR UPDATE;
 IF NOT FOUND OR p.currency<>'AUD' OR p.total_amount<>intake.total_amount
 OR EXISTS(SELECT 1 FROM public.allocation_runs WHERE tenant_id=p_tenant AND payroll_pool_id=p_pool AND status='confirmed')
 THEN RAISE EXCEPTION 'Pool unavailable for candidate creation' USING ERRCODE='23514'; END IF;
 IF EXISTS(SELECT 1 FROM public.allocation_runs WHERE tenant_id=p_tenant AND id=p_run)
 THEN RAISE EXCEPTION 'Candidate ID already exists' USING ERRCODE='23505'; END IF;
 IF (SELECT count(*) FROM private.payroll_allocation_builds WHERE tenant_id=p_tenant AND pool_id=p_pool)>=20
 THEN RAISE EXCEPTION 'Candidate version limit reached' USING ERRCODE='54000'; END IF;
 IF (SELECT count(*) FROM public.payroll_source_rows WHERE tenant_id=p_tenant AND payroll_pool_id=p_pool)<>intake.row_count
 OR (SELECT coalesce(sum(amount),0) FROM public.payroll_source_rows WHERE tenant_id=p_tenant AND payroll_pool_id=p_pool)<>intake.total_amount
 THEN RAISE EXCEPTION 'Source intake does not reconcile' USING ERRCODE='23514'; END IF;
 INSERT INTO public.allocation_runs(id,tenant_id,payroll_pool_id,method_version,status,residual_amount)
 VALUES(p_run,p_tenant,p_pool,'reviewed-mapping-v1','draft',p.total_amount);
 FOR item IN SELECT value FROM jsonb_array_elements(p_lines) LOOP
  SELECT s.id,s.amount INTO source_id,source_amount FROM public.payroll_source_rows s
  WHERE s.tenant_id=p_tenant AND s.payroll_pool_id=p_pool AND s.source_row_key=item->>'sourceRowKey';
  IF NOT FOUND THEN RAISE EXCEPTION 'Allocation source unavailable' USING ERRCODE='23514'; END IF;
  bucket:=item->>'bucket';site:=(item->>'siteId')::uuid;value_text:=item->>'amount';amount_value:=value_text::numeric;
  IF site IS NOT NULL THEN
   PERFORM 1 FROM public.sites WHERE tenant_id=p_tenant AND id=site AND status='active' FOR SHARE;
   IF NOT FOUND THEN RAISE EXCEPTION 'Allocation site unavailable' USING ERRCODE='23514'; END IF;
  END IF;
  IF amount_value>source_amount THEN RAISE EXCEPTION 'Allocation exceeds source' USING ERRCODE='23514'; END IF;
  INSERT INTO public.allocation_lines(tenant_id,allocation_run_id,site_id,bucket_type,amount,source_ref,payroll_source_row_id)
  VALUES(p_tenant,p_run,site,bucket,amount_value,item->>'evidenceRef',source_id);
  CASE bucket WHEN 'approved_allocated' THEN allocated:=allocated+amount_value;
   WHEN 'non_site' THEN non_site:=non_site+amount_value; ELSE excluded:=excluded+amount_value; END CASE;
 END LOOP;
 -- Compute every residual from stored immutable source rows; callers cannot
 -- submit residual lines or force a balancing number.
 INSERT INTO public.allocation_lines(tenant_id,allocation_run_id,site_id,bucket_type,amount,source_ref,payroll_source_row_id)
 SELECT p_tenant,p_run,NULL,'unallocated',s.amount-coalesce(l.used,0),NULL,s.id
 FROM public.payroll_source_rows s
 LEFT JOIN (SELECT payroll_source_row_id,sum(amount) used FROM public.allocation_lines WHERE tenant_id=p_tenant AND allocation_run_id=p_run GROUP BY payroll_source_row_id) l ON l.payroll_source_row_id=s.id
 WHERE s.tenant_id=p_tenant AND s.payroll_pool_id=p_pool AND s.amount>coalesce(l.used,0);
 residual:=p.total_amount-allocated-non_site-excluded;
 IF residual<0 OR (SELECT coalesce(sum(amount),0) FROM public.allocation_lines WHERE tenant_id=p_tenant AND allocation_run_id=p_run)<>p.total_amount
 THEN RAISE EXCEPTION 'Candidate reconciliation failed' USING ERRCODE='23514'; END IF;
 UPDATE public.allocation_runs SET allocated_amount=allocated,non_site_amount=non_site,excluded_amount=excluded,residual_amount=residual,
 status=CASE WHEN residual=0 THEN 'review' ELSE 'draft' END WHERE tenant_id=p_tenant AND id=p_run;
 IF residual=0 THEN proposal:=private.submit_payroll_proposal(p_tenant,p_run); END IF;
 -- Bind actual persisted rows in the recovery inventory; no caller controls the digest.
 SELECT encode(public.digest(convert_to(coalesce(jsonb_agg(jsonb_build_array(l.payroll_source_row_id,l.site_id,l.bucket_type,l.amount::text,l.source_ref)
 ORDER BY l.payroll_source_row_id,l.bucket_type,l.site_id,l.source_ref),'[]'::jsonb)::text,'UTF8'),'sha256'),'hex') INTO line_digest
 FROM public.allocation_lines l WHERE l.tenant_id=p_tenant AND l.allocation_run_id=p_run;
 INSERT INTO private.payroll_allocation_builds(tenant_id,pool_id,run_id,actor_id,scope_digest,proposal_id)
 VALUES(p_tenant,p_pool,p_run,actor,p_scope,proposal);
 PERFORM private.sensitive_api_fresh(p_auth,p_expires);
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,metadata)
 VALUES(p_tenant,actor,'payroll_allocation_candidate_built','allocation_run',p_run,jsonb_build_object('lineDigest',line_digest));
 RETURN private.payroll_allocation_build_summary(p_tenant,p_pool,p_run);
END $fn$;

CREATE FUNCTION private.api_payroll_allocation_status(
 p_tenant uuid,p_run uuid,p_action text,p_scope text,p_auth bigint,p_iat bigint,p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text,p_pool uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE result jsonb;
BEGIN
 IF p_action IS DISTINCT FROM 'payroll_allocation_status' OR p_scope IS DISTINCT FROM encode(public.digest(convert_to('payroll-allocation-status-v1'||E'\n'||p_pool,'UTF8'),'sha256'),'hex')
 THEN RAISE EXCEPTION 'Allocation status denied' USING ERRCODE='42501'; END IF;
 PERFORM private.sensitive_api_actor(p_tenant,p_run,p_action,p_scope,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 result:=private.payroll_allocation_build_summary(p_tenant,p_pool,p_run);
 PERFORM private.sensitive_api_fresh(p_auth,p_expires);
 RETURN result;
END $fn$;
CREATE OR REPLACE FUNCTION private.guard_managed_payroll_confirmation()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
BEGIN
 IF NEW.status<>'confirmed' THEN RETURN NEW; END IF;
 PERFORM 1 FROM public.payroll_pools WHERE tenant_id=NEW.tenant_id AND id=NEW.payroll_pool_id FOR UPDATE;
 IF (EXISTS(SELECT 1 FROM private.payroll_intake_receipts WHERE tenant_id=NEW.tenant_id AND pool_id=NEW.payroll_pool_id) OR EXISTS(SELECT 1 FROM private.payroll_proposal_reviews pr JOIN public.allocation_runs ar
  ON ar.tenant_id=pr.tenant_id AND ar.id=pr.allocation_run_id
  WHERE ar.tenant_id=NEW.tenant_id AND ar.payroll_pool_id=NEW.payroll_pool_id))
 AND NOT EXISTS(
  SELECT 1 FROM private.payroll_confirmation_receipts c JOIN private.payroll_proposal_reviews pr
   ON pr.tenant_id=c.tenant_id AND pr.id=c.proposal_id AND pr.allocation_run_id=c.allocation_run_id AND pr.evidence_digest=c.evidence_digest
  JOIN private.payroll_proposal_decisions d ON d.tenant_id=c.tenant_id AND d.proposal_id=c.proposal_id
   AND d.reviewer_id=c.reviewer_id AND d.decision='reviewed'
  WHERE c.tenant_id=NEW.tenant_id AND c.allocation_run_id=NEW.id AND c.reviewer_id=NEW.reviewer_id
 ) THEN RAISE EXCEPTION 'Managed payroll requires a session-attested confirmation receipt' USING ERRCODE='42501'; END IF;
 RETURN NEW;
END $fn$;
REVOKE ALL ON FUNCTION private.payroll_allocation_build_summary(uuid,uuid,uuid),private.api_payroll_allocation_build(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text,uuid,jsonb),
 private.api_payroll_allocation_status(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text,uuid) FROM PUBLIC,profitpilot_app;
GRANT EXECUTE ON FUNCTION private.api_payroll_allocation_build(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text,uuid,jsonb),
 private.api_payroll_allocation_status(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text,uuid) TO profitpilot_app;
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
  ) all_entries LIMIT 100001
 ), hashes AS (SELECT kind,encode(hash,'hex') AS h FROM entries)
 SELECT count(*),CASE WHEN count(*)<=100000 THEN encode(public.digest(convert_to('profitpilot-sensitive-recovery-v12:'||coalesce(string_agg(kind||':'||h,',' ORDER BY kind COLLATE "C",h COLLATE "C"),''),'UTF8'),'sha256'),'hex') END
 INTO total,result FROM hashes;
 IF total>100000 OR result IS NULL THEN RAISE EXCEPTION 'Sensitive recovery inventory exceeds reviewed capacity' USING ERRCODE='54000'; END IF;
 RETURN result;
END $fn$;

REVOKE ALL ON FUNCTION private.sensitive_recovery_fingerprint() FROM PUBLIC,profitpilot_app;
CREATE OR REPLACE FUNCTION private.verify_security_catalog()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT digest=private.security_catalog_digest() FROM private.security_catalog_baseline WHERE revision=65),false)
$fn$;
INSERT INTO private.security_catalog_baseline(singleton,revision,digest) VALUES(true,65,private.security_catalog_digest());
COMMIT;

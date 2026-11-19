-- Separate, batch-wide independently reviewed cost disposition. No payment
-- authorisation, no claim that evidence hashes prove real-world disjointness.
BEGIN;
DO $check$ BEGIN IF private.verify_security_catalog() IS DISTINCT FROM true THEN RAISE EXCEPTION 'Prior catalog does not verify'; END IF; END $check$;
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
 IF p_action IS NULL OR p_action NOT IN ('payroll_submit','payroll_read','account_read','account_correct_email','invoice_disposal_preview','privacy_case_request','privacy_case_status','privacy_case_intake','privacy_case_acknowledge','privacy_case_resolve','privacy_case_refuse','payroll_correction_preview','payroll_correction_status','privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status','privacy_key_revoke','payroll_intake_preview','payroll_intake_status','payroll_allocation_build','payroll_allocation_status','workspace_create','workspace_read','workspace_version_status','workspace_job_write','workspace_job_read','invoice_intake_preview','invoice_intake_status','supplier_cost_status')
 OR (p_action IN ('privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status','privacy_key_revoke','payroll_intake_preview','payroll_intake_status','payroll_allocation_build','payroll_allocation_status','workspace_create','workspace_read','workspace_version_status','workspace_job_write','workspace_job_read','invoice_intake_preview','invoice_intake_status','supplier_cost_status') AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('payroll_correction_preview','payroll_correction_status') AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('privacy_case_intake','privacy_case_acknowledge','privacy_case_resolve','privacy_case_refuse') AND actor_role NOT IN ('owner','admin'))
 OR (p_action='payroll_submit' AND actor_role NOT IN ('owner','admin','analyst'))
 OR (p_action='payroll_read' AND actor_role NOT IN ('owner','admin','reviewer'))
 OR (p_action='invoice_disposal_preview' AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('account_read','account_correct_email') AND p_target<>p_tenant)
 THEN RAISE EXCEPTION 'Sensitive operation denied' USING ERRCODE='42501'; END IF;
 now_s:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 IF p_scope IS NULL OR p_scope !~ '^[a-f0-9]{64}$'
 OR (p_action IN ('account_correct_email','privacy_case_request','privacy_case_intake','privacy_case_resolve','privacy_case_refuse','payroll_correction_preview','privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status','privacy_key_revoke','payroll_intake_preview','payroll_intake_status','payroll_allocation_build','payroll_allocation_status','workspace_create','workspace_read','workspace_version_status','workspace_job_write','workspace_job_read','invoice_intake_preview','invoice_intake_status','supplier_cost_status') AND p_scope=repeat('0',64))
 OR (p_action NOT IN ('account_correct_email','privacy_case_request','privacy_case_intake','privacy_case_resolve','privacy_case_refuse','payroll_correction_preview','privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status','privacy_key_revoke','payroll_intake_preview','payroll_intake_status','payroll_allocation_build','payroll_allocation_status','workspace_create','workspace_read','workspace_version_status','workspace_job_write','workspace_job_read','invoice_intake_preview','invoice_intake_status','supplier_cost_status') AND p_scope<>repeat('0',64))
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

CREATE TABLE private.supplier_cost_orders(
 tenant_id uuid NOT NULL,batch_id uuid NOT NULL,order_id uuid NOT NULL,
 intake_scope text NOT NULL CHECK(intake_scope ~ '^[a-f0-9]{64}$'),
 classification text NOT NULL CHECK(classification IN ('direct_site','overhead_pending','payroll_overlap','excluded')),
 evidence_digest text NOT NULL CHECK(evidence_digest ~ '^[a-f0-9]{64}$' AND evidence_digest<>repeat('0',64)),
 scope_digest text NOT NULL CHECK(scope_digest ~ '^[a-f0-9]{64}$'),
 PRIMARY KEY(tenant_id,order_id),UNIQUE(tenant_id,batch_id,order_id),
 FOREIGN KEY(tenant_id,batch_id) REFERENCES private.invoice_intake_receipts(tenant_id,batch_id)
);
CREATE TABLE private.supplier_cost_receipts(
 tenant_id uuid NOT NULL,batch_id uuid NOT NULL,order_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,batch_id),UNIQUE(tenant_id,order_id),
 FOREIGN KEY(tenant_id,batch_id,order_id) REFERENCES private.supplier_cost_orders(tenant_id,batch_id,order_id)
);
REVOKE ALL ON private.supplier_cost_orders,private.supplier_cost_receipts FROM PUBLIC,profitpilot_app;
CREATE TRIGGER supplier_cost_order_frozen BEFORE UPDATE OR DELETE OR TRUNCATE ON private.supplier_cost_orders FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();
CREATE TRIGGER supplier_cost_receipt_frozen BEFORE UPDATE OR DELETE OR TRUNCATE ON private.supplier_cost_receipts FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();
CREATE FUNCTION private.supplier_cost_summary(t uuid,b uuid,o uuid) RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE result jsonb;
BEGIN
 SELECT jsonb_build_object('batchId',q.batch_id,'orderId',q.order_id,'intakeScopeDigest',q.intake_scope,'classification',q.classification,'evidenceDigest',q.evidence_digest,'scopeDigest',q.scope_digest,
 'status',CASE WHEN r.order_id=q.order_id THEN 'classified' WHEN r.order_id IS NOT NULL THEN 'superseded' WHEN d.decision='rejected' THEN 'rejected'
 WHEN d.expires_at<=clock_timestamp() OR (d.order_id IS NULL AND w.requested_at+interval '24 hours'<=clock_timestamp()) THEN 'expired'
 WHEN d.decision='approved' THEN 'approved_pending_record' ELSE 'requested' END,'includedInCalculation',false,'paymentAuthorized',false)
 INTO result FROM private.supplier_cost_orders q JOIN private.security_work_orders w ON w.tenant_id=q.tenant_id AND w.id=q.order_id
 LEFT JOIN private.security_work_decisions d ON d.tenant_id=q.tenant_id AND d.order_id=q.order_id
 LEFT JOIN private.supplier_cost_receipts r ON r.tenant_id=q.tenant_id AND r.batch_id=q.batch_id
 WHERE q.tenant_id=t AND q.batch_id=b AND q.order_id=o;
 IF result IS NULL THEN RAISE EXCEPTION 'Cost classification unavailable' USING ERRCODE='42501'; END IF;RETURN result;
END $fn$;
CREATE FUNCTION private.api_supplier_cost_step(t uuid,b uuid,o uuid,intake text,classification text,evidence text,scope text,step text,
 auth bigint,iat bigint,session_digest text,expiry bigint,nonce text,key_id text,signature text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE actor uuid; accepted_scope text; q private.supplier_cost_orders%ROWTYPE; n integer;
BEGIN
 actor:=private.security_work_actor(t,o,'privileged_operation',scope,step,auth,iat,session_digest,expiry,nonce,key_id,signature);
 IF b IS NULL OR intake IS NULL OR intake !~ '^[a-f0-9]{64}$' OR classification IS NULL OR classification NOT IN ('direct_site','overhead_pending','payroll_overlap','excluded')
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
CREATE FUNCTION private.api_supplier_cost_status(t uuid,o uuid,action text,scope text,auth bigint,iat bigint,session_digest text,expiry bigint,nonce text,key_id text,signature text,b uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE result jsonb;
BEGIN
 IF action IS DISTINCT FROM 'supplier_cost_status' OR scope IS DISTINCT FROM encode(public.digest(convert_to('supplier-cost-status-v1'||E'\n'||b,'UTF8'),'sha256'),'hex')
 THEN RAISE EXCEPTION 'Cost status denied' USING ERRCODE='42501'; END IF;
 PERFORM private.sensitive_api_actor(t,o,action,scope,auth,iat,session_digest,expiry,nonce,key_id,signature);
 result:=private.supplier_cost_summary(t,b,o);
 PERFORM private.sensitive_api_fresh(auth,expiry);RETURN result;
END $fn$;
REVOKE ALL ON FUNCTION private.supplier_cost_summary(uuid,uuid,uuid),private.api_supplier_cost_step(uuid,uuid,uuid,text,text,text,text,text,bigint,bigint,text,bigint,text,text,text),private.api_supplier_cost_status(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text,uuid) FROM PUBLIC,profitpilot_app;
GRANT EXECUTE ON FUNCTION private.api_supplier_cost_step(uuid,uuid,uuid,text,text,text,text,text,bigint,bigint,text,bigint,text,text,text),private.api_supplier_cost_status(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text,uuid) TO profitpilot_app;

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
  ) all_entries LIMIT 100001
 ), hashes AS (SELECT kind,encode(hash,'hex') AS h FROM entries)
 SELECT count(*),CASE WHEN count(*)<=100000 THEN encode(public.digest(convert_to('profitpilot-sensitive-recovery-v17:'||coalesce(string_agg(kind||':'||h,',' ORDER BY kind COLLATE "C",h COLLATE "C"),''),'UTF8'),'sha256'),'hex') END
 INTO total,result FROM hashes;
 IF total>100000 OR result IS NULL THEN RAISE EXCEPTION 'Sensitive recovery inventory exceeds reviewed capacity' USING ERRCODE='54000'; END IF;
 RETURN result;
END $fn$;
REVOKE ALL ON FUNCTION private.sensitive_recovery_fingerprint() FROM PUBLIC,profitpilot_app;
CREATE OR REPLACE FUNCTION private.verify_security_catalog()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT digest=private.security_catalog_digest() FROM private.security_catalog_baseline WHERE revision=71),false)
$fn$;
INSERT INTO private.security_catalog_baseline(singleton,revision,digest) VALUES(true,71,private.security_catalog_digest());
COMMIT;

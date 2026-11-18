-- Reviewed pre-minimized payroll source intake. No public upload, raw payroll
-- extracts, production permissions, allocation approval or statutory decisions.
BEGIN;
DO $check$ BEGIN
 IF private.verify_security_catalog() IS DISTINCT FROM true THEN RAISE EXCEPTION 'Prior security catalog does not verify'; END IF;
END $check$;
CREATE TABLE private.payroll_intake_receipts(
 tenant_id uuid NOT NULL,batch_id uuid NOT NULL,pool_id uuid NOT NULL,order_id uuid NOT NULL,
 source_namespace uuid NOT NULL,
 file_digest text NOT NULL CHECK(file_digest ~ '^[a-f0-9]{64}$' AND file_digest<>repeat('0',64)),
 authority_digest text NOT NULL CHECK(authority_digest ~ '^[a-f0-9]{64}$' AND authority_digest<>repeat('0',64)),
 policy_digest text NOT NULL CHECK(policy_digest ~ '^[a-f0-9]{64}$' AND policy_digest<>repeat('0',64)),
 control_digest text NOT NULL CHECK(control_digest ~ '^[a-f0-9]{64}$' AND control_digest<>repeat('0',64)),
 scope_digest text NOT NULL CHECK(scope_digest ~ '^[a-f0-9]{64}$' AND scope_digest<>repeat('0',64)),
 row_count integer NOT NULL CHECK(row_count BETWEEN 1 AND 200),
 total_amount numeric(14,2) NOT NULL CHECK(total_amount>=0),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,batch_id),UNIQUE(tenant_id,pool_id),UNIQUE(tenant_id,order_id),
 FOREIGN KEY(tenant_id,batch_id) REFERENCES public.import_batches(tenant_id,id),
 FOREIGN KEY(tenant_id,pool_id) REFERENCES public.payroll_pools(tenant_id,id),
 FOREIGN KEY(tenant_id,order_id) REFERENCES private.security_work_consumptions(tenant_id,order_id)
);
REVOKE ALL ON private.payroll_intake_receipts FROM PUBLIC,profitpilot_app;
CREATE TRIGGER payroll_intake_receipts_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON private.payroll_intake_receipts
 FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();

-- No arbitrary column names or unminimized identifiers. Input is the exact
-- canonical three-column offline export, reconstructed independently in SQL.
CREATE FUNCTION private.payroll_intake_scope(
 p_tenant uuid,p_batch uuid,p_pool uuid,p_order uuid,p_namespace uuid,p_total text,p_count integer,
 p_authority text,p_policy text,p_control text,p_rows jsonb)
RETURNS text LANGUAGE plpgsql SET search_path=pg_catalog SET timezone='UTC' AS $fn$
DECLARE b public.import_batches%ROWTYPE; item jsonb; h text; amount_total numeric:=0; source_key text; seen text[]:='{}'; canonical text:='source_row_key,amount,currency'||E'\n'; file_digest text;
BEGIN
 IF p_tenant IS NULL OR p_batch IS NULL OR p_pool IS NULL OR p_order IS NULL OR p_namespace IS NULL
 OR private.current_tenant_id() IS DISTINCT FROM p_tenant OR coalesce(private.current_actor_role(),'') NOT IN ('owner','admin')
 OR private.lock_tenant_available(p_tenant) IS DISTINCT FROM true
 THEN RAISE EXCEPTION 'Payroll intake denied' USING ERRCODE='42501'; END IF;
 IF p_total IS NULL OR p_total !~ '^(0|[1-9][0-9]{0,11})[.][0-9]{2}$' OR p_count IS NULL OR p_count NOT BETWEEN 1 AND 200
 OR p_rows IS NULL OR jsonb_typeof(p_rows)<>'array' OR octet_length(p_rows::text)>65536
 THEN RAISE EXCEPTION 'Payroll source format rejected' USING ERRCODE='23514'; END IF;
 IF jsonb_array_length(p_rows)<>p_count THEN RAISE EXCEPTION 'Payroll row count mismatch' USING ERRCODE='23514'; END IF;
 FOREACH h IN ARRAY ARRAY[p_authority,p_policy,p_control] LOOP
  IF h IS NULL OR h !~ '^[a-f0-9]{64}$' OR h=repeat('0',64) THEN RAISE EXCEPTION 'Payroll evidence rejected' USING ERRCODE='23514'; END IF;
 END LOOP;
 PERFORM pg_advisory_xact_lock(hashtextextended('profitpilot-payroll-intake:'||p_tenant::text,0));
 SELECT * INTO b FROM public.import_batches WHERE tenant_id=p_tenant AND id=p_batch FOR UPDATE;
 IF NOT FOUND OR b.source_type<>'payroll' OR b.status<>'registered'
 OR b.source_period_start IS NULL OR b.source_period_end IS NULL OR NOT isfinite(b.source_period_start) OR NOT isfinite(b.source_period_end)
 OR b.source_period_end<b.source_period_start OR b.source_period_end-b.source_period_start>366
 OR b.file_name<>'minimized-payroll-v1.csv' OR b.permission_ref<>'reviewed-payroll-authority'
 OR EXISTS(SELECT 1 FROM private.import_disposal_controls WHERE tenant_id=p_tenant AND batch_id=p_batch AND hold_active)
 OR EXISTS(SELECT 1 FROM private.import_disposal_tombstones WHERE tenant_id=p_tenant AND batch_id=p_batch)
 OR EXISTS(SELECT 1 FROM private.quarantined_files WHERE tenant_id=p_tenant AND batch_id=p_batch)
 OR EXISTS(SELECT 1 FROM public.raw_import_rows WHERE tenant_id=p_tenant AND batch_id=p_batch)
 OR EXISTS(SELECT 1 FROM public.payroll_pools WHERE tenant_id=p_tenant AND (batch_id=p_batch OR id=p_pool OR (period_start<=b.source_period_end AND period_end>=b.source_period_start)))
 THEN RAISE EXCEPTION 'Payroll intake unavailable or overlapping period' USING ERRCODE='23514'; END IF;
 FOR item IN SELECT value FROM jsonb_array_elements(p_rows) LOOP
  IF jsonb_typeof(item)<>'object' OR NOT(item ?& ARRAY['source_row_key','amount','currency']) OR (item-ARRAY['source_row_key','amount','currency'])<>'{}'::jsonb
  OR jsonb_typeof(item->'source_row_key') IS DISTINCT FROM 'string' OR jsonb_typeof(item->'amount') IS DISTINCT FROM 'string'
  OR jsonb_typeof(item->'currency') IS DISTINCT FROM 'string'
  OR item->>'source_row_key' !~ '^ppr_[a-f0-9]{64}$' OR item->>'source_row_key'='ppr_'||repeat('0',64)
  OR item->>'amount' !~ '^(0|[1-9][0-9]{0,11})[.][0-9]{2}$' OR item->>'currency'<>'AUD'
  THEN RAISE EXCEPTION 'Payroll source row rejected' USING ERRCODE='23514'; END IF;
  source_key:=item->>'source_row_key';
  IF source_key=ANY(seen) OR EXISTS(SELECT 1 FROM public.payroll_source_rows s WHERE s.tenant_id=p_tenant AND s.source_row_key=source_key)
  THEN RAISE EXCEPTION 'Duplicate payroll source row; correction required' USING ERRCODE='23514'; END IF;
  seen:=array_append(seen,source_key);amount_total:=amount_total+(item->>'amount')::numeric;
  canonical:=canonical||source_key||','||(item->>'amount')||',AUD'||E'\n';
 END LOOP;
 file_digest:=encode(public.digest(convert_to(canonical,'UTF8'),'sha256'),'hex');
 IF amount_total<>p_total::numeric OR file_digest IS DISTINCT FROM b.file_sha256 THEN RAISE EXCEPTION 'Payroll source control mismatch' USING ERRCODE='23514'; END IF;
 RETURN encode(public.digest(convert_to(jsonb_build_array('profitpilot-payroll-intake-v1',p_tenant,p_batch,p_pool,p_order,p_namespace,b.source_period_start,b.source_period_end,file_digest,p_total,p_count,p_authority,p_policy,p_control)::text,'UTF8'),'sha256'),'hex');
END $fn$;

CREATE FUNCTION private.record_payroll_intake(
 p_tenant uuid,p_batch uuid,p_pool uuid,p_order uuid,p_namespace uuid,p_total text,p_count integer,p_authority text,p_policy text,p_control text,p_rows jsonb,p_scope text,p_step text,
 p_auth bigint,p_iat bigint,p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE actor uuid; b public.import_batches%ROWTYPE;
BEGIN
 actor:=private.security_work_actor(p_tenant,p_order,'privileged_operation',p_scope,p_step,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 IF private.payroll_intake_scope(p_tenant,p_batch,p_pool,p_order,p_namespace,p_total,p_count,p_authority,p_policy,p_control,p_rows) IS DISTINCT FROM p_scope
 THEN RAISE EXCEPTION 'Payroll intake scope changed' USING ERRCODE='42501'; END IF;
 PERFORM private.record_security_work(p_tenant,p_order,'privileged_operation',p_scope,p_step,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 IF p_step='consume' THEN
  SELECT * INTO b FROM public.import_batches WHERE tenant_id=p_tenant AND id=p_batch;
  INSERT INTO public.payroll_pools(id,tenant_id,batch_id,period_start,period_end,total_amount,currency,source_ref)
   VALUES(p_pool,p_tenant,p_batch,b.source_period_start,b.source_period_end,p_total::numeric,'AUD','reviewed-payroll-intake-v1');
  INSERT INTO public.raw_import_rows(tenant_id,batch_id,row_number,payload)
   SELECT p_tenant,p_batch,n::integer,value FROM jsonb_array_elements(p_rows) WITH ORDINALITY r(value,n);
  INSERT INTO public.payroll_source_rows(tenant_id,payroll_pool_id,raw_import_row_id,source_row_key,row_sha256,amount,currency)
   SELECT p_tenant,p_pool,r.id,r.payload->>'source_row_key',
   encode(public.digest(convert_to((r.payload->>'source_row_key')||E'\n'||(r.payload->>'amount')||E'\nAUD','UTF8'),'sha256'),'hex'),
   (r.payload->>'amount')::numeric,'AUD'
   FROM public.raw_import_rows r WHERE r.tenant_id=p_tenant AND r.batch_id=p_batch;
  UPDATE public.import_batches SET status='accepted' WHERE tenant_id=p_tenant AND id=p_batch;
  INSERT INTO private.payroll_intake_receipts(tenant_id,batch_id,pool_id,order_id,source_namespace,file_digest,authority_digest,policy_digest,control_digest,scope_digest,row_count,total_amount)
   VALUES(p_tenant,p_batch,p_pool,p_order,p_namespace,b.file_sha256,p_authority,p_policy,p_control,p_scope,p_count,p_total::numeric);
  PERFORM private.sensitive_api_fresh(p_auth,p_expires);
  INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id)
   VALUES(p_tenant,actor,'payroll_source_intake_accepted','import_batch',p_batch);
 END IF;
END $fn$;

-- Freeze managed source facts immediately, not only after allocation confirmation.
CREATE FUNCTION private.guard_reviewed_payroll_intake()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE t uuid; b uuid; p uuid;
BEGIN
 IF TG_TABLE_NAME='payroll_source_rows' THEN
  t:=NEW.tenant_id;p:=NEW.payroll_pool_id;
 ELSIF TG_TABLE_NAME='payroll_pools' THEN
  IF TG_OP='INSERT' THEN t:=NEW.tenant_id;b:=NEW.batch_id;p:=NEW.id; ELSE t:=OLD.tenant_id;b:=OLD.batch_id;p:=OLD.id; END IF;
 ELSIF TG_TABLE_NAME='raw_import_rows' THEN
  IF TG_OP='INSERT' THEN t:=NEW.tenant_id;b:=NEW.batch_id; ELSE t:=OLD.tenant_id;b:=OLD.batch_id; END IF;
 ELSE t:=OLD.tenant_id;b:=OLD.id;
 END IF;
 IF EXISTS(SELECT 1 FROM private.payroll_intake_receipts WHERE tenant_id=t AND (batch_id=b OR pool_id=p))
 THEN RAISE EXCEPTION 'Reviewed payroll source is immutable' USING ERRCODE='55000'; END IF;
 IF TG_OP='UPDATE' AND TG_TABLE_NAME='raw_import_rows' THEN
  IF EXISTS(SELECT 1 FROM private.payroll_intake_receipts WHERE tenant_id=NEW.tenant_id AND batch_id=NEW.batch_id)
  THEN RAISE EXCEPTION 'Reviewed payroll source is immutable' USING ERRCODE='55000'; END IF;
 END IF;
 IF TG_OP='UPDATE' AND TG_TABLE_NAME='payroll_pools' THEN
  IF EXISTS(SELECT 1 FROM private.payroll_intake_receipts WHERE tenant_id=NEW.tenant_id AND (batch_id=NEW.batch_id OR pool_id=NEW.id))
  THEN RAISE EXCEPTION 'Reviewed payroll source is immutable' USING ERRCODE='55000'; END IF;
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;RETURN NEW;
END $fn$;
-- Runtime invoice rows must not need direct access to the private receipt table.
-- Scope the trigger execution identity without exposing any query capability.
ALTER FUNCTION private.guard_reviewed_payroll_intake() SECURITY DEFINER;
CREATE TRIGGER reviewed_payroll_raw_guard BEFORE INSERT OR UPDATE OR DELETE ON public.raw_import_rows
 FOR EACH ROW EXECUTE FUNCTION private.guard_reviewed_payroll_intake();
CREATE TRIGGER reviewed_payroll_pool_guard BEFORE INSERT OR UPDATE OR DELETE ON public.payroll_pools
 FOR EACH ROW EXECUTE FUNCTION private.guard_reviewed_payroll_intake();
CREATE TRIGGER reviewed_payroll_source_guard BEFORE INSERT ON public.payroll_source_rows
 FOR EACH ROW EXECUTE FUNCTION private.guard_reviewed_payroll_intake();
CREATE TRIGGER reviewed_payroll_batch_guard BEFORE UPDATE OR DELETE ON public.import_batches
 FOR EACH ROW EXECUTE FUNCTION private.guard_reviewed_payroll_intake();
REVOKE ALL ON FUNCTION private.payroll_intake_scope(uuid,uuid,uuid,uuid,uuid,text,integer,text,text,text,jsonb),
 private.record_payroll_intake(uuid,uuid,uuid,uuid,uuid,text,integer,text,text,text,jsonb,text,text,bigint,bigint,text,bigint,text,text,text),
 private.guard_reviewed_payroll_intake() FROM PUBLIC,profitpilot_app;
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
  ) all_entries LIMIT 100001
 ), hashes AS (SELECT kind,encode(hash,'hex') AS h FROM entries)
 SELECT count(*),CASE WHEN count(*)<=100000 THEN encode(public.digest(convert_to('profitpilot-sensitive-recovery-v10:'||coalesce(string_agg(kind||':'||h,',' ORDER BY kind COLLATE "C",h COLLATE "C"),''),'UTF8'),'sha256'),'hex') END
 INTO total,result FROM hashes;
 IF total>100000 OR result IS NULL THEN RAISE EXCEPTION 'Sensitive recovery inventory exceeds reviewed capacity' USING ERRCODE='54000'; END IF;
 RETURN result;
END $fn$;

REVOKE ALL ON FUNCTION private.sensitive_recovery_fingerprint() FROM PUBLIC,profitpilot_app;
CREATE OR REPLACE FUNCTION private.verify_security_catalog()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT digest=private.security_catalog_digest() FROM private.security_catalog_baseline WHERE revision=63),false)
$fn$;
INSERT INTO private.security_catalog_baseline(singleton,revision,digest) VALUES(true,63,private.security_catalog_digest());
COMMIT;

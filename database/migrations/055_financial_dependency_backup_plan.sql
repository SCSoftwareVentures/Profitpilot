-- Candidate-only dependency and backup-plan verification. No destructive capability.
BEGIN;
DO $check$ BEGIN
 IF private.verify_security_catalog() IS DISTINCT FROM true THEN RAISE EXCEPTION 'Prior security catalog does not verify'; END IF;
END $check$;

CREATE TABLE private.financial_backup_plans(
 tenant_id uuid NOT NULL,allocation_run_id uuid NOT NULL,order_id uuid NOT NULL,
 inventory_digest text NOT NULL CHECK(inventory_digest ~ '^[a-f0-9]{64}$' AND inventory_digest<>repeat('0',64)),
 disposition_digest text NOT NULL CHECK(disposition_digest ~ '^[a-f0-9]{64}$' AND disposition_digest<>repeat('0',64)),
 checked_on date NOT NULL CHECK(isfinite(checked_on)),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,order_id),
 FOREIGN KEY(tenant_id,allocation_run_id) REFERENCES private.payroll_confirmation_receipts(tenant_id,allocation_run_id),
 FOREIGN KEY(tenant_id,order_id) REFERENCES private.security_work_consumptions(tenant_id,order_id)
);
CREATE INDEX financial_backup_plans_run_idx ON private.financial_backup_plans(tenant_id,allocation_run_id,checked_on);
REVOKE ALL ON private.financial_backup_plans FROM PUBLIC,profitpilot_app;
CREATE TRIGGER financial_backup_plans_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON private.financial_backup_plans
 FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();

-- All dates are UTC engineering review dates, not a legal retention calculation.
-- A timely plan is an evidenced assertion only, not proof that backup media are erased.
CREATE FUNCTION private.financial_backup_plan_scope(p_tenant uuid,p_run uuid,p_inventory text,p_disposition text,p_checked date)
RETURNS text LANGUAGE plpgsql STABLE SET search_path=pg_catalog SET timezone='UTC' SET datestyle='ISO, YMD' AS $fn$
DECLARE receipt text;
BEGIN
 IF p_tenant IS NULL OR p_run IS NULL OR private.current_tenant_id() IS DISTINCT FROM p_tenant
 OR coalesce(private.current_actor_role(),'') NOT IN ('owner','admin')
 OR p_inventory IS NULL OR p_inventory !~ '^[a-f0-9]{64}$' OR p_inventory=repeat('0',64)
 OR p_disposition IS NULL OR p_disposition !~ '^[a-f0-9]{64}$' OR p_disposition=repeat('0',64)
 OR p_checked IS DISTINCT FROM (clock_timestamp() AT TIME ZONE 'UTC')::date
 THEN RAISE EXCEPTION 'Backup plan scope denied' USING ERRCODE='42501'; END IF;
 SELECT evidence_digest INTO receipt FROM private.payroll_confirmation_receipts WHERE tenant_id=p_tenant AND allocation_run_id=p_run;
 IF NOT FOUND THEN RAISE EXCEPTION 'Backup plan scope denied' USING ERRCODE='42501'; END IF;
 RETURN encode(public.digest(convert_to(jsonb_build_array('profitpilot-financial-backup-plan-v1',p_tenant,p_run,receipt,p_inventory,p_disposition,p_checked)::text,'UTF8'),'sha256'),'hex');
END $fn$;

CREATE FUNCTION private.record_financial_backup_plan(
 p_tenant uuid,p_order uuid,p_run uuid,p_inventory text,p_disposition text,p_checked date,
 p_scope text,p_step text,p_auth bigint,p_iat bigint,p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
BEGIN
 PERFORM private.security_work_actor(p_tenant,p_order,'privileged_operation',p_scope,p_step,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 PERFORM pg_advisory_xact_lock(hashtextextended('financial-retention:'||p_tenant::text||':'||p_run::text,0));
 IF private.financial_backup_plan_scope(p_tenant,p_run,p_inventory,p_disposition,p_checked) IS DISTINCT FROM p_scope THEN
  RAISE EXCEPTION 'Backup plan scope changed' USING ERRCODE='42501'; END IF;
 PERFORM private.record_security_work(p_tenant,p_order,'privileged_operation',p_scope,p_step,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 IF p_step='consume' THEN
  INSERT INTO private.financial_backup_plans(tenant_id,allocation_run_id,order_id,inventory_digest,disposition_digest,checked_on)
  VALUES(p_tenant,p_run,p_order,p_inventory,p_disposition,p_checked);
 END IF;
END $fn$;

-- Conservative diagnostic: no user-controlled claims of dependency clearance.
-- Overlapping tenant calculations are treated as dependencies even if stale;
-- supersession links, current payroll and batch-level holds are separately shown.
-- Immutable financial lineage and external copies are never certified clear here.
CREATE FUNCTION private.financial_retention_dependency_status(p_tenant uuid,p_run uuid)
RETURNS jsonb LANGUAGE plpgsql STABLE SET search_path=pg_catalog SET timezone='UTC' AS $fn$
DECLARE pool public.payroll_pools%ROWTYPE; active_use boolean; linked boolean; reports boolean; batch_hold boolean; plan_count bigint; plan_conflict boolean;
BEGIN
 SELECT p.* INTO pool FROM private.payroll_confirmation_receipts c
 JOIN public.allocation_runs r ON r.tenant_id=c.tenant_id AND r.id=c.allocation_run_id
 JOIN public.payroll_pools p ON p.tenant_id=r.tenant_id AND p.id=r.payroll_pool_id
 WHERE c.tenant_id=p_tenant AND c.allocation_run_id=p_run AND r.status='confirmed';
 IF NOT FOUND THEN RETURN jsonb_build_object('status','unavailable','authorizesDisposal',false); END IF;
 active_use:=NOT EXISTS(SELECT 1 FROM private.payroll_supersessions WHERE tenant_id=p_tenant AND old_run_id=p_run);
 linked:=EXISTS(SELECT 1 FROM private.payroll_correction_reservations WHERE tenant_id=p_tenant AND (old_run_id=p_run OR new_run_id=p_run))
 OR EXISTS(SELECT 1 FROM private.payroll_supersessions WHERE tenant_id=p_tenant AND (old_run_id=p_run OR new_run_id=p_run));
 reports:=EXISTS(SELECT 1 FROM public.calculation_runs WHERE tenant_id=p_tenant AND period_start<=pool.period_end AND period_end>=pool.period_start);
 batch_hold:=EXISTS(SELECT 1 FROM private.import_disposal_controls WHERE tenant_id=p_tenant AND batch_id=pool.batch_id AND hold_active);
 SELECT count(*),count(DISTINCT ROW(inventory_digest,disposition_digest))>1 INTO plan_count,plan_conflict
 FROM private.financial_backup_plans WHERE tenant_id=p_tenant AND allocation_run_id=p_run AND checked_on=CURRENT_DATE;
 RETURN jsonb_build_object('status','blocked','retention',private.financial_retention_status(p_tenant,p_run)->>'status',
  'currentPayroll',active_use,'correctionLineage',linked,'overlappingCalculations',reports,'batchHold',batch_hold,
  'immutableEvidenceDependency',true,'backupPlan',CASE WHEN plan_count=0 THEN 'missing-or-stale' WHEN plan_conflict THEN 'conflicting' ELSE 'recorded-unverified' END,
  'externalDependenciesVerified',false,'authorizesDisposal',false);
END $fn$;
REVOKE ALL ON FUNCTION private.financial_backup_plan_scope(uuid,uuid,text,text,date),
 private.record_financial_backup_plan(uuid,uuid,uuid,text,text,date,text,text,bigint,bigint,text,bigint,text,text,text),
 private.financial_retention_dependency_status(uuid,uuid) FROM PUBLIC,profitpilot_app;
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
  ) all_entries LIMIT 100001
 ), hashes AS (SELECT kind,encode(hash,'hex') AS h FROM entries)
 SELECT count(*),CASE WHEN count(*)<=100000 THEN encode(public.digest(convert_to('profitpilot-sensitive-recovery-v3:'||coalesce(string_agg(kind||':'||h,',' ORDER BY kind COLLATE "C",h COLLATE "C"),''),'UTF8'),'sha256'),'hex') END
 INTO total,result FROM hashes;
 IF total>100000 OR result IS NULL THEN RAISE EXCEPTION 'Sensitive recovery inventory exceeds reviewed capacity' USING ERRCODE='54000'; END IF;
 RETURN result;
END $fn$;

REVOKE ALL ON FUNCTION private.sensitive_recovery_fingerprint() FROM PUBLIC,profitpilot_app;
CREATE OR REPLACE FUNCTION private.verify_security_catalog()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT digest=private.security_catalog_digest() FROM private.security_catalog_baseline WHERE revision=55),false)
$fn$;
INSERT INTO private.security_catalog_baseline(singleton,revision,digest) VALUES(true,55,private.security_catalog_digest());
COMMIT;

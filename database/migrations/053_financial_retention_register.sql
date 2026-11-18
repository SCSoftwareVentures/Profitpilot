-- Candidate-only retention register. No execution path or disposal privilege.
BEGIN;
DO $check$ BEGIN
 IF private.verify_security_catalog() IS DISTINCT FROM true THEN RAISE EXCEPTION 'Prior security catalog does not verify'; END IF;
END $check$;
CREATE TABLE private.financial_retention_reviews(
 tenant_id uuid NOT NULL,allocation_run_id uuid NOT NULL,review_id uuid NOT NULL,
 evidence_digest text NOT NULL CHECK(evidence_digest ~ '^[a-f0-9]{64}$' AND evidence_digest<>repeat('0',64)),
 retain_through date NOT NULL CHECK(isfinite(retain_through)),
 reviewed_on date NOT NULL CHECK(isfinite(reviewed_on)),
 expires_on date NOT NULL CHECK(isfinite(expires_on) AND expires_on>reviewed_on),
 PRIMARY KEY(tenant_id,allocation_run_id,review_id),
 FOREIGN KEY(tenant_id,allocation_run_id) REFERENCES private.payroll_confirmation_receipts(tenant_id,allocation_run_id)
);
CREATE TABLE private.financial_retention_holds(
 tenant_id uuid NOT NULL,allocation_run_id uuid NOT NULL,hold_id uuid NOT NULL,
 evidence_digest text NOT NULL CHECK(evidence_digest ~ '^[a-f0-9]{64}$' AND evidence_digest<>repeat('0',64)),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,allocation_run_id,hold_id),
 FOREIGN KEY(tenant_id,allocation_run_id) REFERENCES private.payroll_confirmation_receipts(tenant_id,allocation_run_id)
);
REVOKE ALL ON private.financial_retention_reviews,private.financial_retention_holds FROM PUBLIC,profitpilot_app;
CREATE TRIGGER financial_retention_reviews_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON private.financial_retention_reviews FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();
CREATE TRIGGER financial_retention_holds_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON private.financial_retention_holds FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();
-- Internal diagnostic. No claim that submitted review evidence is genuine,
-- no hold release or deletion; missing confirmation, policy or hold completeness denies.
CREATE FUNCTION private.financial_retention_status(p_tenant uuid,p_run uuid)
RETURNS jsonb LANGUAGE plpgsql STABLE SET search_path=pg_catalog SET timezone='UTC' AS $fn$
DECLARE deadline date; total bigint; stale bigint; today date:=CURRENT_DATE;
BEGIN
 IF p_tenant IS NULL OR p_run IS NULL OR NOT EXISTS(SELECT 1 FROM private.payroll_confirmation_receipts WHERE tenant_id=p_tenant AND allocation_run_id=p_run) THEN
  RETURN jsonb_build_object('status','unavailable','authorizesDisposal',false);
 END IF;
 IF EXISTS(SELECT 1 FROM private.financial_retention_holds WHERE tenant_id=p_tenant AND allocation_run_id=p_run) THEN
  RETURN jsonb_build_object('status','hold-recorded','authorizesDisposal',false);
 END IF;
 SELECT count(*),count(*) FILTER(WHERE reviewed_on>today OR expires_on<=today),max(retain_through)
 INTO total,stale,deadline FROM private.financial_retention_reviews WHERE tenant_id=p_tenant AND allocation_run_id=p_run;
 IF total=0 OR stale>0 THEN RETURN jsonb_build_object('status','review-missing-or-stale','authorizesDisposal',false); END IF;
 IF deadline>=today THEN RETURN jsonb_build_object('status','retention-period-active','authorizesDisposal',false); END IF;
 RETURN jsonb_build_object('status','external-verification-required','authorizesDisposal',false);
END $fn$;
REVOKE ALL ON FUNCTION private.financial_retention_status(uuid,uuid) FROM PUBLIC,profitpilot_app;
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
  ) all_entries LIMIT 100001
 ), hashes AS (SELECT kind,encode(hash,'hex') AS h FROM entries)
 SELECT count(*),CASE WHEN count(*)<=100000 THEN encode(public.digest(convert_to('profitpilot-sensitive-recovery-v2:'||coalesce(string_agg(kind||':'||h,',' ORDER BY kind COLLATE "C",h COLLATE "C"),''),'UTF8'),'sha256'),'hex') END
 INTO total,result FROM hashes;
 IF total>100000 OR result IS NULL THEN RAISE EXCEPTION 'Sensitive recovery inventory exceeds reviewed capacity' USING ERRCODE='54000'; END IF;
 RETURN result;
END $fn$;

REVOKE ALL ON FUNCTION private.sensitive_recovery_fingerprint() FROM PUBLIC,profitpilot_app;
CREATE OR REPLACE FUNCTION private.verify_security_catalog()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT digest=private.security_catalog_digest() FROM private.security_catalog_baseline WHERE revision=53),false)
$fn$;
INSERT INTO private.security_catalog_baseline(singleton,revision,digest) VALUES(true,53,private.security_catalog_digest());
COMMIT;

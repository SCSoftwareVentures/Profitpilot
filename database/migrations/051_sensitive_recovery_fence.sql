-- Deny recovery when sensitive workflow or account correction state differs
-- from the independently signed authoritative source. No automatic replay
-- of approval, case outcome, financial correction or account data.
BEGIN;
DO $check$ BEGIN
 IF private.verify_security_catalog() IS DISTINCT FROM true THEN RAISE EXCEPTION 'Prior security catalog does not verify'; END IF;
END $check$;
CREATE FUNCTION private.sensitive_recovery_fingerprint()
RETURNS text LANGUAGE plpgsql STABLE SET search_path=pg_catalog SET timezone='UTC' AS $fn$
DECLARE total bigint; result text;
BEGIN
 WITH rows AS (
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
 ), hashes AS (SELECT kind,encode(hash,'hex') AS h FROM rows)
 SELECT count(*),CASE WHEN count(*)<=100000 THEN encode(public.digest(convert_to('profitpilot-sensitive-recovery-v1:'||coalesce(string_agg(kind||':'||h,',' ORDER BY kind COLLATE "C",h COLLATE "C"),''),'UTF8'),'sha256'),'hex') END
 INTO total,result FROM hashes;
 IF total>100000 OR result IS NULL THEN RAISE EXCEPTION 'Sensitive recovery inventory exceeds reviewed capacity' USING ERRCODE='54000'; END IF;
 RETURN result;
END $fn$;
REVOKE ALL ON FUNCTION private.sensitive_recovery_fingerprint() FROM PUBLIC,profitpilot_app;
CREATE OR REPLACE FUNCTION private.security_recovery_inventory()
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE inventory jsonb;
BEGIN
 IF private.verify_security_catalog() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'Recovery inventory unavailable: security catalogue drift' USING ERRCODE='55000';
 END IF;
 SELECT jsonb_build_object(
  'sensitive',jsonb_build_array(jsonb_build_object('digest',private.sensitive_recovery_fingerprint())),
  'tenants',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY id),'[]') FROM (SELECT id,status FROM public.tenants ORDER BY id LIMIT 100001) x),
  'users',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY id),'[]') FROM (SELECT id,status,encode(public.digest(convert_to(auth_subject,'UTF8'),'sha256'),'hex') AS subject_hash FROM public.users ORDER BY id LIMIT 100001) x),
  'memberships',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY tenant_id,user_id),'[]') FROM (SELECT tenant_id,user_id,role,status FROM public.tenant_memberships ORDER BY tenant_id,user_id LIMIT 100001) x),
  'cutoffs',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY user_id),'[]') FROM (SELECT user_id,revoked_through::text FROM private.identity_session_cutoffs ORDER BY user_id LIMIT 100001) x),
  'sessions',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY user_id,session_digest),'[]') FROM (SELECT user_id,session_digest FROM private.revoked_identity_sessions ORDER BY user_id,session_digest LIMIT 100001) x),
  'keys',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY key_id),'[]') FROM (SELECT key_id,active FROM private.tenant_context_keys ORDER BY key_id LIMIT 100001) x),
  'incidents',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY incident_id),'[]') FROM (SELECT incident_id,tenant_id,category,released_at IS NOT NULL AS released FROM private.tenant_emergency_incidents ORDER BY incident_id LIMIT 100001) x)
 ) INTO inventory;
 IF (SELECT sum(jsonb_array_length(value)) FROM jsonb_each(inventory))>100000 THEN
  RAISE EXCEPTION 'Security recovery inventory exceeds reviewed capacity' USING ERRCODE='54000';
 END IF;
 RETURN inventory;
END $fn$;

CREATE OR REPLACE FUNCTION private.verify_security_catalog()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT digest=private.security_catalog_digest() FROM private.security_catalog_baseline WHERE revision=51),false)
$fn$;
INSERT INTO private.security_catalog_baseline(singleton,revision,digest) VALUES(true,51,private.security_catalog_digest());
COMMIT;

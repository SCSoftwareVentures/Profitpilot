-- Private, scoped candidate authority for adding retention reviews and holds.
-- Does not grant runtime access, allow hold release or authorize disposal.
BEGIN;
DO $check$ BEGIN
 IF private.verify_security_catalog() IS DISTINCT FROM true THEN RAISE EXCEPTION 'Prior security catalog does not verify'; END IF;
END $check$;
CREATE FUNCTION private.retention_work_scope(p_tenant uuid,p_run uuid,p_action text,p_evidence text,p_through date,p_reviewed date,p_expiry date)
RETURNS text LANGUAGE plpgsql STABLE SET search_path=pg_catalog SET timezone='UTC' SET datestyle='ISO, YMD' AS $fn$
DECLARE receipt text; today date:=(clock_timestamp() AT TIME ZONE 'UTC')::date;
BEGIN
 IF p_tenant IS NULL OR p_run IS NULL OR private.current_tenant_id() IS DISTINCT FROM p_tenant
 OR coalesce(private.current_actor_role(),'') NOT IN ('owner','admin')
 OR p_action IS NULL OR p_action NOT IN ('review','hold')
 OR p_evidence IS NULL OR p_evidence !~ '^[a-f0-9]{64}$' OR p_evidence=repeat('0',64)
 THEN RAISE EXCEPTION 'Retention scope denied' USING ERRCODE='42501'; END IF;
 IF p_action='review' THEN
  IF p_through IS NULL OR p_reviewed IS NULL OR p_expiry IS NULL
  OR NOT isfinite(p_through) OR NOT isfinite(p_reviewed) OR NOT isfinite(p_expiry)
  OR p_reviewed>today OR p_expiry<=today OR p_expiry<=p_reviewed
  THEN RAISE EXCEPTION 'Retention dates denied' USING ERRCODE='42501'; END IF;
 ELSIF p_through IS NOT NULL OR p_reviewed IS NOT NULL OR p_expiry IS NOT NULL THEN
  RAISE EXCEPTION 'Hold scope denied' USING ERRCODE='42501';
 END IF;
 SELECT evidence_digest INTO receipt FROM private.payroll_confirmation_receipts WHERE tenant_id=p_tenant AND allocation_run_id=p_run;
 IF NOT FOUND THEN RAISE EXCEPTION 'Retention scope denied' USING ERRCODE='42501'; END IF;
 RETURN encode(public.digest(convert_to(jsonb_build_array('profitpilot-retention-work-v1',p_tenant,p_run,receipt,p_action,p_evidence,p_through,p_reviewed,p_expiry)::text,'UTF8'),'sha256'),'hex');
END $fn$;

CREATE FUNCTION private.record_retention_work(p_tenant uuid,p_order uuid,p_run uuid,p_action text,p_evidence text,
 p_through date,p_reviewed date,p_expiry date,p_scope text,p_step text,p_auth bigint,p_iat bigint,p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE actor uuid;
BEGIN
 actor:=private.security_work_actor(p_tenant,p_order,'privileged_operation',p_scope,p_step,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 IF p_action='hold' AND p_step IS DISTINCT FROM 'request' THEN RAISE EXCEPTION 'Hold release not supported' USING ERRCODE='42501'; END IF;
 IF private.retention_work_scope(p_tenant,p_run,p_action,p_evidence,p_through,p_reviewed,p_expiry) IS DISTINCT FROM p_scope THEN RAISE EXCEPTION 'Retention scope changed' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('financial-retention:'||p_tenant::text||':'||p_run::text,0));
 PERFORM private.record_security_work(p_tenant,p_order,'privileged_operation',p_scope,p_step,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 IF p_action='review' AND p_step='consume' THEN
  INSERT INTO private.financial_retention_reviews(tenant_id,allocation_run_id,review_id,evidence_digest,retain_through,reviewed_on,expires_on)
  VALUES(p_tenant,p_run,p_order,p_evidence,p_through,p_reviewed,p_expiry);
 ELSIF p_action='hold' THEN
  INSERT INTO private.financial_retention_holds(tenant_id,allocation_run_id,hold_id,evidence_digest)
  VALUES(p_tenant,p_run,p_order,p_evidence);
 END IF;
END $fn$;
REVOKE ALL ON FUNCTION private.retention_work_scope(uuid,uuid,text,text,date,date,date),
 private.record_retention_work(uuid,uuid,uuid,text,text,date,date,date,text,text,bigint,bigint,text,bigint,text,text,text) FROM PUBLIC,profitpilot_app;
CREATE OR REPLACE FUNCTION private.verify_security_catalog()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT digest=private.security_catalog_digest() FROM private.security_catalog_baseline WHERE revision=54),false)
$fn$;
INSERT INTO private.security_catalog_baseline(singleton,revision,digest) VALUES(true,54,private.security_catalog_digest());
COMMIT;

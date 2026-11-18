-- Recovery evidence must not be exported or signed from a drifted catalogue.
BEGIN;
DO $check$ BEGIN
 IF NOT private.verify_security_catalog() THEN RAISE EXCEPTION 'Prior security catalog does not verify'; END IF;
END $check$;

CREATE OR REPLACE FUNCTION private.security_recovery_inventory()
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE inventory jsonb;
BEGIN
 IF private.verify_security_catalog() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'Recovery inventory unavailable: security catalogue drift' USING ERRCODE='55000';
 END IF;
 SELECT jsonb_build_object(
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

CREATE OR REPLACE FUNCTION private.privacy_recovery_inventory()
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE disposals jsonb; expiries jsonb; holds jsonb;
BEGIN
 IF private.verify_security_catalog() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'Recovery inventory unavailable: security catalogue drift' USING ERRCODE='55000';
 END IF;
 SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY x.tenant_id,x.batch_id),'[]'::jsonb) INTO disposals
 FROM (SELECT tenant_id,batch_id,file_sha256,authority_ref,
 to_char(disposed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS disposed_at
 FROM private.import_disposal_tombstones ORDER BY tenant_id,batch_id LIMIT 100001) x;
 SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY x.tenant_id,x.batch_id),'[]'::jsonb) INTO expiries
 FROM (SELECT tenant_id,batch_id,file_sha256,
 to_char(disposed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS disposed_at
 FROM private.quarantine_expiry_receipts ORDER BY tenant_id,batch_id LIMIT 100001) x;
 SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY x.tenant_id,x.batch_id),'[]'::jsonb) INTO holds
 FROM (SELECT tenant_id,batch_id FROM private.import_disposal_controls WHERE hold_active ORDER BY tenant_id,batch_id LIMIT 100001) x;
 IF jsonb_array_length(disposals)+jsonb_array_length(expiries)+jsonb_array_length(holds)>100000 THEN
  RAISE EXCEPTION 'Privacy recovery inventory exceeds reviewed capacity' USING ERRCODE='54000';
 END IF;
 RETURN jsonb_build_object('disposals',disposals,'expiries',expiries,'holds',holds);
END $fn$;

CREATE OR REPLACE FUNCTION private.verify_security_catalog()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT digest=private.security_catalog_digest() FROM private.security_catalog_baseline WHERE revision=44),false)
$fn$;
INSERT INTO private.security_catalog_baseline(singleton,revision,digest) VALUES(true,44,private.security_catalog_digest());
COMMIT;

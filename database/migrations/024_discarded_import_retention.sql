-- Narrow purge of abandoned source payloads, not accepted financial records.
BEGIN;
CREATE TABLE private.discarded_import_retention_policies(
 tenant_id uuid NOT NULL REFERENCES public.tenants(id),
 source_type text NOT NULL CHECK(source_type IN ('payroll','customer_invoice','supplier_invoice')),
 revision uuid NOT NULL DEFAULT gen_random_uuid(),
 enabled boolean NOT NULL DEFAULT false,
 minimum_age_days integer NOT NULL CHECK(minimum_age_days BETWEEN 1 AND 36500),
 authority_reference text NOT NULL CHECK(length(btrim(authority_reference)) BETWEEN 3 AND 500),
 PRIMARY KEY(tenant_id,source_type)
);
CREATE TRIGGER discarded_import_policy_revision BEFORE INSERT OR UPDATE ON private.discarded_import_retention_policies
 FOR EACH ROW EXECUTE FUNCTION private.refresh_privacy_policy_revision();
CREATE TABLE private.discarded_import_purges(
 tenant_id uuid NOT NULL,
 batch_id uuid PRIMARY KEY,
 purged_at timestamptz NOT NULL,
 row_count integer NOT NULL CHECK(row_count>0),
 policy_revision uuid NOT NULL,
 source_type text NOT NULL,
 authorization_reference text NOT NULL CHECK(length(btrim(authorization_reference)) BETWEEN 3 AND 500),
 dependency_review_reference text NOT NULL CHECK(length(btrim(dependency_review_reference)) BETWEEN 3 AND 500),
 FOREIGN KEY(tenant_id,batch_id) REFERENCES public.import_batches(tenant_id,id) ON DELETE RESTRICT,
 CHECK(authorization_reference<>dependency_review_reference)
);
CREATE TABLE private.discarded_import_holds(
 tenant_id uuid PRIMARY KEY REFERENCES public.tenants(id),
 authority_reference text NOT NULL CHECK(length(btrim(authority_reference)) BETWEEN 3 AND 500)
);
ALTER TABLE private.discarded_import_retention_policies OWNER TO profitpilot_context_owner;
ALTER TABLE private.discarded_import_purges OWNER TO profitpilot_context_owner;
ALTER TABLE private.discarded_import_holds OWNER TO profitpilot_context_owner;
REVOKE ALL ON private.discarded_import_retention_policies,private.discarded_import_purges,private.discarded_import_holds FROM PUBLIC,profitpilot_app;
REVOKE UPDATE,DELETE,TRUNCATE ON public.raw_import_rows FROM profitpilot_app;
REVOKE DELETE,TRUNCATE ON public.import_batches FROM profitpilot_app;
GRANT SELECT,UPDATE(payload) ON public.raw_import_rows TO profitpilot_context_owner;
GRANT SELECT ON public.invoice_lines,public.payroll_pools TO profitpilot_context_owner;

CREATE FUNCTION private.lock_import_retention_tenant(p_tenant uuid) RETURNS void
LANGUAGE sql SET search_path=pg_catalog AS $fn$
 SELECT pg_advisory_xact_lock(hashtextextended('discarded-import-retention-v1:'||p_tenant::text,0))
$fn$;
ALTER FUNCTION private.lock_import_retention_tenant(uuid) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.lock_import_retention_tenant(uuid) FROM PUBLIC,profitpilot_app;
CREATE FUNCTION private.serialize_import_retention_hold() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,private AS $fn$
BEGIN
 IF TG_OP='DELETE' THEN PERFORM private.lock_import_retention_tenant(OLD.tenant_id);RETURN OLD;END IF;
 IF TG_OP='UPDATE' AND NEW.tenant_id IS DISTINCT FROM OLD.tenant_id THEN RAISE EXCEPTION 'Hold tenant cannot change';END IF;
 PERFORM private.lock_import_retention_tenant(NEW.tenant_id);
 RETURN NEW;
END
$fn$;
ALTER FUNCTION private.serialize_import_retention_hold() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.serialize_import_retention_hold() FROM PUBLIC,profitpilot_app;
CREATE TRIGGER discarded_import_hold_serialization BEFORE INSERT OR UPDATE OR DELETE ON private.discarded_import_holds
 FOR EACH ROW EXECUTE FUNCTION private.serialize_import_retention_hold();
CREATE TRIGGER subject_hold_import_serialization BEFORE INSERT OR UPDATE OR DELETE ON private.privacy_retention_holds
 FOR EACH ROW EXECUTE FUNCTION private.serialize_import_retention_hold();
CREATE TRIGGER request_hold_import_serialization BEFORE UPDATE OF status ON public.privacy_requests
 FOR EACH ROW WHEN (OLD.status IS DISTINCT FROM NEW.status AND (OLD.status='legal_hold' OR NEW.status='legal_hold'))
 EXECUTE FUNCTION private.serialize_import_retention_hold();

CREATE FUNCTION private.protect_purged_import_batch() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,private AS $fn$
BEGIN
 IF EXISTS(SELECT 1 FROM private.discarded_import_purges WHERE batch_id=OLD.id) THEN
  RAISE EXCEPTION 'Purged import batch is immutable' USING ERRCODE='55000';
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;END IF;
 RETURN NEW;
END
$fn$;
ALTER FUNCTION private.protect_purged_import_batch() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.protect_purged_import_batch() FROM PUBLIC,profitpilot_app;
CREATE TRIGGER purged_import_batch_guard BEFORE UPDATE OR DELETE ON public.import_batches
 FOR EACH ROW EXECUTE FUNCTION private.protect_purged_import_batch();

CREATE FUNCTION private.protect_purged_source_row() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
DECLARE batch_value uuid;
BEGIN
 IF TG_OP='INSERT' THEN batch_value:=NEW.batch_id; ELSE batch_value:=OLD.batch_id; END IF;
 -- All source row operations serialize with the batch purge.
 PERFORM 1 FROM public.import_batches WHERE id=batch_value FOR SHARE;
 IF EXISTS(SELECT 1 FROM private.discarded_import_purges WHERE batch_id=batch_value) THEN
  RAISE EXCEPTION 'Purged source row cannot be restored' USING ERRCODE='55000';
 END IF;
 IF TG_OP='UPDATE' AND (NEW.batch_id IS DISTINCT FROM OLD.batch_id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.id IS DISTINCT FROM OLD.id) THEN
  RAISE EXCEPTION 'Source row identity is immutable' USING ERRCODE='55000';
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;END IF;
 RETURN NEW;
END
$fn$;
ALTER FUNCTION private.protect_purged_source_row() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.protect_purged_source_row() FROM PUBLIC,profitpilot_app;
CREATE TRIGGER purged_source_row_guard BEFORE INSERT OR UPDATE OR DELETE ON public.raw_import_rows
 FOR EACH ROW EXECUTE FUNCTION private.protect_purged_source_row();

CREATE FUNCTION private.reject_purged_source_dependency() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
DECLARE batch_value uuid;
DECLARE source_row uuid;
BEGIN
 IF TG_TABLE_NAME='payroll_pools' THEN batch_value:=NEW.batch_id;
 ELSE
  IF TG_TABLE_NAME='mapping_decisions' THEN source_row:=NEW.raw_row_id; ELSE source_row:=NEW.source_row_id; END IF;
  IF source_row IS NULL THEN RETURN NEW;END IF;
  SELECT batch_id INTO batch_value FROM public.raw_import_rows WHERE id=source_row;
 END IF;
 IF batch_value IS NOT NULL THEN
  PERFORM 1 FROM public.import_batches WHERE id=batch_value FOR SHARE;
  IF EXISTS(SELECT 1 FROM private.discarded_import_purges WHERE batch_id=batch_value) THEN
   RAISE EXCEPTION 'Purged import cannot be used as source evidence' USING ERRCODE='55000';
  END IF;
 END IF;
 RETURN NEW;
END
$fn$;
ALTER FUNCTION private.reject_purged_source_dependency() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.reject_purged_source_dependency() FROM PUBLIC,profitpilot_app;
CREATE TRIGGER mapping_purged_source_guard BEFORE INSERT OR UPDATE OF raw_row_id ON public.mapping_decisions
 FOR EACH ROW EXECUTE FUNCTION private.reject_purged_source_dependency();
CREATE TRIGGER invoice_purged_source_guard BEFORE INSERT OR UPDATE OF source_row_id ON public.invoice_lines
 FOR EACH ROW EXECUTE FUNCTION private.reject_purged_source_dependency();
CREATE TRIGGER payroll_purged_source_guard BEFORE INSERT OR UPDATE OF batch_id ON public.payroll_pools
 FOR EACH ROW EXECUTE FUNCTION private.reject_purged_source_dependency();

CREATE FUNCTION private.purge_discarded_import(p_tenant uuid,p_batch uuid,p_authority text,p_dependency_review text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
DECLARE batch public.import_batches%ROWTYPE;
DECLARE policy private.discarded_import_retention_policies%ROWTYPE;
DECLARE n integer;
DECLARE at_time timestamptz;
BEGIN
 IF p_authority IS NULL OR p_dependency_review IS NULL OR length(btrim(p_authority)) NOT BETWEEN 3 AND 500
 OR length(btrim(p_dependency_review)) NOT BETWEEN 3 AND 500 OR btrim(p_authority)=btrim(p_dependency_review) THEN
  RAISE EXCEPTION 'Separate retention authorization and dependency review references required';
 END IF;
 PERFORM private.lock_import_retention_tenant(p_tenant);
 SELECT * INTO batch FROM public.import_batches WHERE tenant_id=p_tenant AND id=p_batch FOR UPDATE;
 IF NOT FOUND OR batch.status NOT IN ('rejected','failed') THEN RAISE EXCEPTION 'Only a discarded import is eligible';END IF;
 SELECT * INTO policy FROM private.discarded_import_retention_policies WHERE tenant_id=p_tenant AND source_type=batch.source_type FOR SHARE;
 IF NOT FOUND OR NOT policy.enabled THEN RAISE EXCEPTION 'Explicit source-specific retention policy required';END IF;
 at_time:=clock_timestamp();
 IF batch.created_at>at_time-make_interval(days=>policy.minimum_age_days)
 OR EXISTS(SELECT 1 FROM private.discarded_import_holds WHERE tenant_id=p_tenant)
 OR EXISTS(SELECT 1 FROM private.privacy_retention_holds WHERE tenant_id=p_tenant)
 OR EXISTS(SELECT 1 FROM public.privacy_requests WHERE tenant_id=p_tenant AND status IN ('requested','identity_verification','under_review','legal_hold')) THEN
  RAISE EXCEPTION 'Retention age, outstanding request or legal hold prevents import purge';
 END IF;
 IF EXISTS(SELECT 1 FROM private.discarded_import_purges WHERE batch_id=p_batch) THEN RAISE EXCEPTION 'Import already purged';END IF;
 PERFORM 1 FROM public.raw_import_rows WHERE tenant_id=p_tenant AND batch_id=p_batch ORDER BY id FOR UPDATE;
 IF EXISTS(SELECT 1 FROM public.mapping_decisions m JOIN public.raw_import_rows r ON r.id=m.raw_row_id WHERE r.tenant_id=p_tenant AND r.batch_id=p_batch)
 OR EXISTS(SELECT 1 FROM public.invoice_lines i JOIN public.raw_import_rows r ON r.id=i.source_row_id WHERE r.tenant_id=p_tenant AND r.batch_id=p_batch)
 OR EXISTS(SELECT 1 FROM public.payroll_pools WHERE tenant_id=p_tenant AND batch_id=p_batch) THEN
  RAISE EXCEPTION 'Referenced source evidence cannot be purged';
 END IF;
 -- Remove raw payloads only. Preserve original row identities, financial tables and import provenance.
 UPDATE public.raw_import_rows SET payload='{}'::jsonb WHERE tenant_id=p_tenant AND batch_id=p_batch;
 GET DIAGNOSTICS n=ROW_COUNT;
 IF n=0 THEN RAISE EXCEPTION 'No raw payload rows found';END IF;
 INSERT INTO private.discarded_import_purges(tenant_id,batch_id,purged_at,row_count,policy_revision,source_type,authorization_reference,dependency_review_reference)
 VALUES(p_tenant,p_batch,at_time,n,policy.revision,batch.source_type,btrim(p_authority),btrim(p_dependency_review));
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata)
 VALUES(p_tenant,NULL,'discarded_import_payload_purged','import_batch',p_batch,'Discarded source payloads removed under approved retention policy',
 jsonb_build_object('rowCount',n,'policyRevision',policy.revision));
 RETURN jsonb_build_object('batchId',p_batch,'payloadRowsRemoved',n,'completePersonalDataDeletion',false);
END
$fn$;
ALTER FUNCTION private.purge_discarded_import(uuid,uuid,text,text) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.purge_discarded_import(uuid,uuid,text,text) FROM PUBLIC,profitpilot_app;
CREATE OR REPLACE FUNCTION private.privacy_restore_state() RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
 SELECT jsonb_build_object(
 'markers',COALESCE((
 SELECT jsonb_agg(marker ORDER BY kind,id) FROM (
  SELECT 'closure'::text AS kind,c.user_id AS id,
  jsonb_build_object('kind','closure','id',c.user_id,'tenantId',c.tenant_id,'requestId',c.request_id,
   'at',extract(epoch FROM c.closed_at)::text,'emailErased',c.email_erased) AS marker
  FROM private.account_closures c
  UNION ALL
  SELECT 'redaction',r.id,jsonb_build_object('kind','redaction','id',r.id,'tenantId',r.tenant_id,
   'at',extract(epoch FROM r.details_redacted_at)::text)
  FROM public.privacy_requests r WHERE r.details_redacted_at IS NOT NULL
  UNION ALL
  SELECT 'session_cleanup',c.id,jsonb_build_object('kind','session_cleanup','id',c.id,'tenantId',c.tenant_id,'userId',c.user_id,
  'at',extract(epoch FROM c.cleaned_at)::text,'cutoff',extract(epoch FROM c.cutoff)::text)
  FROM private.closed_session_cleanups c
  UNION ALL SELECT 'provider_erasure',e.id,jsonb_build_object('kind','provider_erasure','id',e.id,'tenantId',e.tenant_id,
  'userId',e.user_id,'at',extract(epoch FROM e.verified_at)::text)
  FROM private.provider_erasure_receipts e
  UNION ALL SELECT 'import_purge',p.batch_id,jsonb_build_object('kind','import_purge','id',p.batch_id,'tenantId',p.tenant_id,
  'at',extract(epoch FROM p.purged_at)::text,'rowCount',p.row_count)
  FROM private.discarded_import_purges p
 ) m),'[]'::jsonb),
 'violations',COALESCE((
 SELECT jsonb_agg(jsonb_build_object('kind',v.kind,'id',v.id) ORDER BY v.kind,v.id)
 FROM (
  SELECT 'closure_state_mismatch'::text AS kind,c.user_id AS id FROM private.account_closures c
  LEFT JOIN public.users u ON u.id=c.user_id
  LEFT JOIN public.privacy_requests r ON r.id=c.request_id
  WHERE u.id IS NULL OR u.status<>'disabled' OR r.id IS NULL OR r.status<>'fulfilled'
  OR r.request_type<>'account_closure' OR r.subject_user_id<>c.user_id OR r.tenant_id<>c.tenant_id
  OR (c.email_erased AND u.email IS DISTINCT FROM 'erased-'||u.id::text||'@invalid.example')
  OR EXISTS(SELECT 1 FROM public.tenant_memberships m WHERE m.user_id=c.user_id AND m.status='active')
  OR EXISTS(SELECT 1 FROM private.auth_sessions s WHERE s.subject=u.auth_subject AND s.revoked_at IS NULL)
  UNION ALL SELECT 'redaction_state_mismatch',r.id FROM public.privacy_requests r
  WHERE r.details_redacted_at IS NOT NULL AND r.details IS DISTINCT FROM '[Removed under approved retention policy]'
  UNION ALL SELECT 'session_cleanup_mismatch',c.id FROM private.closed_session_cleanups c JOIN public.users u ON u.id=c.user_id
  WHERE EXISTS(SELECT 1 FROM private.auth_sessions s WHERE s.subject=u.auth_subject AND s.expires_at<=c.cutoff AND s.revoked_at<=c.cutoff)
  UNION ALL SELECT 'import_purge_mismatch',p.batch_id FROM private.discarded_import_purges p
  LEFT JOIN public.import_batches b ON b.id=p.batch_id AND b.tenant_id=p.tenant_id
  WHERE b.id IS NULL OR b.status NOT IN ('rejected','failed')
  OR (SELECT count(*) FROM public.raw_import_rows r WHERE r.batch_id=p.batch_id AND r.tenant_id=p.tenant_id)<>p.row_count
  OR EXISTS(SELECT 1 FROM public.raw_import_rows r WHERE r.batch_id=p.batch_id AND r.tenant_id=p.tenant_id AND r.payload<>'{}'::jsonb)
 ) v),'[]'::jsonb))
$fn$;
ALTER FUNCTION private.privacy_restore_state() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.privacy_restore_state() FROM PUBLIC,profitpilot_app;
COMMIT;

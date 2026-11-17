-- Approved, scanned import promotion. No raw file data is returned to HTTP
-- callers, and the ordinary parsed-row API remains blocked for these batches.
BEGIN;
CREATE TABLE private.quarantine_manifests(
 tenant_id uuid NOT NULL,batch_id uuid NOT NULL,
 rows_hash text NOT NULL CHECK(rows_hash ~ '^[a-f0-9]{64}$'),
 row_count integer NOT NULL CHECK(row_count BETWEEN 1 AND 200),
 PRIMARY KEY(tenant_id,batch_id),
 FOREIGN KEY(tenant_id,batch_id) REFERENCES private.quarantined_files(tenant_id,batch_id)
);
CREATE TABLE private.quarantine_promotions(
 tenant_id uuid NOT NULL,batch_id uuid NOT NULL,approved_by uuid NOT NULL,
 approved_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 state text NOT NULL DEFAULT 'approved' CHECK(state IN ('approved','processing','promoted','failed','expired')),
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 3),
 lease_id uuid,lease_until timestamptz,promoted_at timestamptz,
 PRIMARY KEY(tenant_id,batch_id),
 FOREIGN KEY(tenant_id,batch_id) REFERENCES private.quarantine_manifests(tenant_id,batch_id),
 FOREIGN KEY(tenant_id,approved_by) REFERENCES public.tenant_memberships(tenant_id,user_id),
 CHECK((state='processing' AND lease_id IS NOT NULL AND lease_until IS NOT NULL)
 OR (state<>'processing' AND lease_id IS NULL AND lease_until IS NULL)),
 CHECK((state='promoted')=(promoted_at IS NOT NULL))
);
-- Temporary transaction authorization. Only the promotion function can write
-- this private guard; no application-settable GUC can bypass quarantine.
CREATE TABLE private.quarantine_insert_authority(
 tenant_id uuid NOT NULL,batch_id uuid NOT NULL,xid xid8 NOT NULL,
 PRIMARY KEY(tenant_id,batch_id)
);
REVOKE ALL ON private.quarantine_manifests,private.quarantine_promotions,private.quarantine_insert_authority FROM PUBLIC,profitpilot_app,profitpilot_scanner;
ALTER TABLE private.quarantine_lifecycle_events DROP CONSTRAINT quarantine_lifecycle_events_event_type_check;
ALTER TABLE private.quarantine_lifecycle_events ADD CONSTRAINT quarantine_lifecycle_events_event_type_check
 CHECK(event_type IN ('claimed','clean','infected','error','disposed','content_validated','content_rejected','promotion_approved','promotion_claimed','promoted','promotion_failed','promotion_expired'));

CREATE FUNCTION private.quarantine_rows_valid(p_rows jsonb)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $fn$
DECLARE v jsonb;
BEGIN
 IF p_rows IS NULL OR jsonb_typeof(p_rows)<>'array' THEN RETURN false; END IF;
 IF jsonb_array_length(p_rows) NOT BETWEEN 1 AND 200 OR octet_length(p_rows::text)>100000 THEN RETURN false; END IF;
 FOR v IN SELECT value FROM jsonb_array_elements(p_rows) LOOP
  IF NOT private.invoice_import_payload_safe(v) OR NOT (v ?& ARRAY['invoice_id','site','date','amount'])
   OR btrim(v->>'invoice_id')='' OR btrim(v->>'site')=''
   OR (v->>'date') !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' OR coalesce(v->>'amount','')='' THEN RETURN false; END IF;
 END LOOP;
 RETURN true;
END $fn$;
CREATE FUNCTION private.quarantine_rows_digest(p_rows jsonb)
RETURNS text LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $fn$
 SELECT encode(public.digest(convert_to(p_rows::text,'UTF8'),'sha256'),'hex')
$fn$;
CREATE FUNCTION private.finish_quarantine_manifest(p_tenant uuid,p_batch uuid,p_lease uuid,p_verdict text,p_content text,p_rows jsonb)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
BEGIN
 IF p_content='validated' THEN
  IF p_verdict IS DISTINCT FROM 'clean' OR NOT private.quarantine_rows_valid(p_rows) THEN
   RAISE EXCEPTION 'Invalid validated row manifest' USING ERRCODE='22023'; END IF;
 ELSIF p_rows IS NOT NULL THEN RAISE EXCEPTION 'Unvalidated files cannot provide row manifests' USING ERRCODE='22023';
 END IF;
 IF NOT private.finish_quarantine_scan_with_content(p_tenant,p_batch,p_lease,p_verdict,p_content) THEN RETURN false; END IF;
 IF p_content='validated' THEN
  INSERT INTO private.quarantine_manifests(tenant_id,batch_id,rows_hash,row_count)
  VALUES(p_tenant,p_batch,private.quarantine_rows_digest(p_rows),jsonb_array_length(p_rows));
 END IF;
 RETURN true;
END $fn$;
REVOKE ALL ON FUNCTION private.finish_quarantine_scan_with_content(uuid,uuid,uuid,text,text) FROM profitpilot_scanner;
REVOKE ALL ON FUNCTION private.quarantine_rows_valid(jsonb),private.quarantine_rows_digest(jsonb),private.finish_quarantine_manifest(uuid,uuid,uuid,text,text,jsonb) FROM PUBLIC,profitpilot_app;
GRANT EXECUTE ON FUNCTION private.finish_quarantine_manifest(uuid,uuid,uuid,text,text,jsonb) TO profitpilot_scanner;

CREATE FUNCTION private.approve_quarantine_promotion(p_tenant uuid,p_batch uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE actor uuid; b public.import_batches%ROWTYPE; q private.quarantined_files%ROWTYPE;
BEGIN
 IF private.current_tenant_id() IS DISTINCT FROM p_tenant OR coalesce(private.current_actor_role(),'') NOT IN ('owner','admin') THEN
  RAISE EXCEPTION 'Promotion authority denied' USING ERRCODE='42501'; END IF;
 SELECT u.id INTO actor FROM public.users u JOIN public.tenant_memberships m ON m.user_id=u.id JOIN public.tenants t ON t.id=m.tenant_id
 WHERE m.tenant_id=p_tenant AND u.auth_subject=nullif(current_setting('app.tenant_subject',true),'')
 AND u.status='active' AND m.status='active' AND m.role IN ('owner','admin') AND t.status='active' FOR SHARE OF u,m,t;
 IF NOT FOUND THEN RAISE EXCEPTION 'Promotion authority denied' USING ERRCODE='42501'; END IF;
 SELECT * INTO b FROM public.import_batches WHERE tenant_id=p_tenant AND id=p_batch FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO q FROM private.quarantined_files WHERE tenant_id=p_tenant AND batch_id=p_batch FOR UPDATE;
 IF NOT FOUND OR q.scan_state<>'clean' OR q.content_state<>'validated' OR q.ciphertext IS NULL
 OR q.created_at<=clock_timestamp()-interval '24 hours' OR b.status<>'registered'
 OR EXISTS(SELECT 1 FROM private.import_disposal_controls WHERE tenant_id=p_tenant AND batch_id=p_batch AND hold_active)
 OR NOT EXISTS(SELECT 1 FROM private.quarantine_manifests WHERE tenant_id=p_tenant AND batch_id=p_batch)
 THEN RAISE EXCEPTION 'Quarantined file is not eligible for approval' USING ERRCODE='23514'; END IF;
 INSERT INTO private.quarantine_promotions(tenant_id,batch_id,approved_by) VALUES(p_tenant,p_batch,actor);
 INSERT INTO private.quarantine_lifecycle_events(tenant_id,batch_id,event_type) VALUES(p_tenant,p_batch,'promotion_approved');
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,metadata)
 VALUES(p_tenant,actor,'file_promotion_approved','import_batch',p_batch,'{}');
 RETURN true;
END $fn$;

CREATE FUNCTION private.claim_quarantine_promotion()
RETURNS TABLE(tenant_id uuid,batch_id uuid,file_sha256 text,key_id text,nonce bytea,auth_tag bytea,ciphertext bytea,lease_id uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE p private.quarantine_promotions%ROWTYPE; q private.quarantined_files%ROWTYPE;
BEGIN
 SELECT x.* INTO p FROM private.quarantine_promotions x JOIN private.quarantined_files f ON f.tenant_id=x.tenant_id AND f.batch_id=x.batch_id
 WHERE x.attempts<3 AND (x.state='approved' OR (x.state='processing' AND x.lease_until<clock_timestamp()))
 AND f.scan_state='clean' AND f.content_state='validated' AND f.ciphertext IS NOT NULL
 AND f.created_at>clock_timestamp()-interval '24 hours'
 ORDER BY x.approved_at,x.batch_id LIMIT 1 FOR UPDATE OF x SKIP LOCKED;
 IF NOT FOUND THEN RETURN; END IF;
 SELECT * INTO q FROM private.quarantined_files f WHERE f.tenant_id=p.tenant_id AND f.batch_id=p.batch_id;
 UPDATE private.quarantine_promotions x SET state='processing',lease_id=gen_random_uuid(),lease_until=clock_timestamp()+interval '2 minutes',attempts=x.attempts+1
 WHERE x.tenant_id=p.tenant_id AND x.batch_id=p.batch_id RETURNING x.* INTO p;
 INSERT INTO private.quarantine_lifecycle_events(tenant_id,batch_id,event_type) VALUES(p.tenant_id,p.batch_id,'promotion_claimed');
 RETURN QUERY SELECT q.tenant_id,q.batch_id,q.file_sha256,q.key_id,q.nonce,q.auth_tag,q.ciphertext,p.lease_id;
END $fn$;

CREATE OR REPLACE FUNCTION private.guard_quarantined_batch_ingestion()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
BEGIN
 IF session_user='profitpilot_app' AND private.current_tenant_id() IS DISTINCT FROM NEW.tenant_id THEN RETURN NEW; END IF;
 PERFORM 1 FROM public.import_batches WHERE tenant_id=NEW.tenant_id AND id=NEW.batch_id FOR UPDATE;
 IF EXISTS(SELECT 1 FROM private.quarantined_files WHERE tenant_id=NEW.tenant_id AND batch_id=NEW.batch_id)
 AND NOT EXISTS(SELECT 1 FROM private.quarantine_insert_authority WHERE tenant_id=NEW.tenant_id AND batch_id=NEW.batch_id AND xid=pg_current_xact_id()) THEN
  RAISE EXCEPTION 'Quarantined file is not approved for ingestion' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $fn$;

CREATE FUNCTION private.finish_quarantine_promotion(p_tenant uuid,p_batch uuid,p_lease uuid,p_rows jsonb)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE p private.quarantine_promotions%ROWTYPE; q private.quarantined_files%ROWTYPE; b public.import_batches%ROWTYPE; manifest private.quarantine_manifests%ROWTYPE;
BEGIN
 -- Global lock order: batch, file, promotion. Expiry follows the same order.
 -- Scanner has no general write privilege.
 SELECT * INTO b FROM public.import_batches WHERE tenant_id=p_tenant AND id=p_batch FOR UPDATE;
 IF NOT FOUND THEN RETURN -1; END IF;
 SELECT * INTO q FROM private.quarantined_files WHERE tenant_id=p_tenant AND batch_id=p_batch FOR UPDATE;
 SELECT * INTO p FROM private.quarantine_promotions WHERE tenant_id=p_tenant AND batch_id=p_batch AND state='processing'
 AND lease_id=p_lease AND lease_until>=clock_timestamp() FOR UPDATE;
 IF NOT FOUND THEN RETURN -1; END IF;
 SELECT * INTO manifest FROM private.quarantine_manifests WHERE tenant_id=p_tenant AND batch_id=p_batch;
 IF p_rows IS NULL OR NOT private.quarantine_rows_valid(p_rows)
 OR private.quarantine_rows_digest(p_rows) IS DISTINCT FROM manifest.rows_hash
 OR q.scan_state IS DISTINCT FROM 'clean' OR q.content_state IS DISTINCT FROM 'validated' OR q.ciphertext IS NULL
 OR q.created_at<=clock_timestamp()-interval '24 hours' OR b.status IS DISTINCT FROM 'registered'
 OR b.file_sha256 IS DISTINCT FROM q.file_sha256
 OR EXISTS(SELECT 1 FROM private.identity_session_cutoffs c WHERE c.user_id=p.approved_by AND c.revoked_through>=floor(extract(epoch FROM p.approved_at))::bigint)
 OR b.source_type NOT IN ('customer_invoice','supplier_invoice')
 OR EXISTS(SELECT 1 FROM private.import_disposal_controls WHERE tenant_id=p_tenant AND batch_id=p_batch AND hold_active)
 OR EXISTS(SELECT 1 FROM public.raw_import_rows WHERE tenant_id=p_tenant AND batch_id=p_batch)
 THEN
  UPDATE private.quarantine_promotions SET state='failed',lease_id=NULL,lease_until=NULL WHERE tenant_id=p_tenant AND batch_id=p_batch;
  INSERT INTO private.quarantine_lifecycle_events(tenant_id,batch_id,event_type) VALUES(p_tenant,p_batch,'promotion_failed');
  RETURN 0;
 END IF;
 PERFORM 1 FROM public.tenant_memberships m JOIN public.users u ON u.id=m.user_id JOIN public.tenants t ON t.id=m.tenant_id
 WHERE m.tenant_id=p_tenant AND m.user_id=p.approved_by AND m.status='active' AND m.role IN ('owner','admin')
 AND u.status='active' AND t.status='active' FOR SHARE OF m,u,t;
 IF NOT FOUND THEN
  UPDATE private.quarantine_promotions SET state='failed',lease_id=NULL,lease_until=NULL WHERE tenant_id=p_tenant AND batch_id=p_batch;
  INSERT INTO private.quarantine_lifecycle_events(tenant_id,batch_id,event_type) VALUES(p_tenant,p_batch,'promotion_failed');
  RETURN 0;
 END IF;
 INSERT INTO private.quarantine_insert_authority(tenant_id,batch_id,xid) VALUES(p_tenant,p_batch,pg_current_xact_id());
 INSERT INTO public.raw_import_rows(tenant_id,batch_id,row_number,payload)
 SELECT p_tenant,p_batch,(ordinality+1)::integer,value FROM jsonb_array_elements(p_rows) WITH ORDINALITY;
 DELETE FROM private.quarantine_insert_authority WHERE tenant_id=p_tenant AND batch_id=p_batch;
 UPDATE public.import_batches SET status='review' WHERE tenant_id=p_tenant AND id=p_batch;
 UPDATE private.quarantine_promotions SET state='promoted',lease_id=NULL,lease_until=NULL,promoted_at=clock_timestamp() WHERE tenant_id=p_tenant AND batch_id=p_batch;
 INSERT INTO private.quarantine_lifecycle_events(tenant_id,batch_id,event_type) VALUES(p_tenant,p_batch,'promoted');
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,metadata)
 VALUES(p_tenant,p.approved_by,'file_promoted','import_batch',p_batch,jsonb_build_object('rowCount',manifest.row_count));
 RETURN manifest.row_count;
END $fn$;

CREATE FUNCTION private.mark_promotion_expired()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
BEGIN
 IF NEW.scan_state='disposed' AND OLD.scan_state<>'disposed' THEN
  UPDATE private.quarantine_promotions SET state='expired',lease_id=NULL,lease_until=NULL
  WHERE tenant_id=NEW.tenant_id AND batch_id=NEW.batch_id AND state IN ('approved','processing');
  IF FOUND THEN INSERT INTO private.quarantine_lifecycle_events(tenant_id,batch_id,event_type) VALUES(NEW.tenant_id,NEW.batch_id,'promotion_expired'); END IF;
 END IF;
 RETURN NEW;
END $fn$;
CREATE TRIGGER quarantine_promotion_expiry AFTER UPDATE ON private.quarantined_files
 FOR EACH ROW EXECUTE FUNCTION private.mark_promotion_expired();

REVOKE ALL ON FUNCTION private.approve_quarantine_promotion(uuid,uuid),private.claim_quarantine_promotion(),private.finish_quarantine_promotion(uuid,uuid,uuid,jsonb),private.mark_promotion_expired() FROM PUBLIC,profitpilot_app;
GRANT EXECUTE ON FUNCTION private.approve_quarantine_promotion(uuid,uuid) TO profitpilot_app;
GRANT EXECUTE ON FUNCTION private.claim_quarantine_promotion(),private.finish_quarantine_promotion(uuid,uuid,uuid,jsonb) TO profitpilot_scanner;
COMMIT;

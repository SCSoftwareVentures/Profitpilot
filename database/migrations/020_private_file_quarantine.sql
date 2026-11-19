-- Encrypted CSV quarantine prototype. No file download, parsing, promotion or
-- public URL exists. Production upload remains disabled until scanning/lifecycle.
BEGIN;
CREATE TABLE private.quarantined_files (
 tenant_id uuid NOT NULL,
 batch_id uuid NOT NULL,
 file_sha256 text NOT NULL CHECK(file_sha256 ~ '^[a-f0-9]{64}$'),
 byte_count integer NOT NULL CHECK(byte_count BETWEEN 1 AND 65536),
 key_id text NOT NULL CHECK(key_id ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$'),
 nonce bytea NOT NULL CHECK(octet_length(nonce)=12),
 auth_tag bytea NOT NULL CHECK(octet_length(auth_tag)=16),
 ciphertext bytea NOT NULL,
 uploaded_by uuid NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,batch_id),
 UNIQUE(key_id,nonce),
 FOREIGN KEY(tenant_id,batch_id) REFERENCES public.import_batches(tenant_id,id),
 FOREIGN KEY(tenant_id,uploaded_by) REFERENCES public.tenant_memberships(tenant_id,user_id),
 CHECK(octet_length(ciphertext)=byte_count)
);
REVOKE ALL ON private.quarantined_files FROM PUBLIC,profitpilot_app;

CREATE FUNCTION private.quarantine_invoice_file(p_tenant uuid,p_batch uuid,p_sha text,p_key text,p_nonce bytea,p_tag bytea,p_cipher bytea)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE b public.import_batches%ROWTYPE; actor uuid; n integer; stored_at timestamptz;
BEGIN
 IF p_tenant IS NULL OR p_batch IS NULL OR private.current_tenant_id() IS DISTINCT FROM p_tenant OR
  coalesce(private.current_actor_role(),'') NOT IN ('owner','admin') THEN
  RAISE EXCEPTION 'Quarantine authority denied' USING ERRCODE='42501';
 END IF;
 IF p_sha IS NULL OR p_sha !~ '^[a-f0-9]{64}$' OR p_key IS NULL OR p_key !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$'
 OR coalesce(octet_length(p_nonce),0)<>12 OR coalesce(octet_length(p_tag),0)<>16
 OR coalesce(octet_length(p_cipher),0) NOT BETWEEN 1 AND 65536 THEN
  RAISE EXCEPTION 'Invalid encrypted quarantine envelope' USING ERRCODE='22023';
 END IF;
 -- Tenant-level lock bounds concurrent quota checks across API processes.
 PERFORM pg_advisory_xact_lock(hashtextextended('quarantine:'||p_tenant::text,0));
 SELECT u.id INTO actor FROM public.users u
 JOIN public.tenant_memberships m ON m.user_id=u.id
 JOIN public.tenants t ON t.id=m.tenant_id
 WHERE m.tenant_id=p_tenant AND u.auth_subject=nullif(current_setting('app.tenant_subject',true),'')
 AND m.role IN ('owner','admin') AND m.status='active' AND u.status='active' AND t.status='active'
 FOR SHARE OF u,m,t;
 IF NOT FOUND THEN RAISE EXCEPTION 'Quarantine authority denied' USING ERRCODE='42501'; END IF;
 SELECT * INTO b FROM public.import_batches WHERE tenant_id=p_tenant AND id=p_batch FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL; END IF;
 IF b.source_type NOT IN ('customer_invoice','supplier_invoice') OR b.status<>'registered'
 OR b.file_sha256<>p_sha OR EXISTS(SELECT 1 FROM public.raw_import_rows WHERE tenant_id=p_tenant AND batch_id=p_batch) THEN
  RAISE EXCEPTION 'Batch not eligible for quarantine upload' USING ERRCODE='23514';
 END IF;
 IF EXISTS(SELECT 1 FROM private.quarantined_files WHERE tenant_id=p_tenant AND batch_id=p_batch) THEN
  RAISE EXCEPTION 'Quarantine file already exists' USING ERRCODE='23505';
 END IF;
 SELECT count(*) INTO n FROM private.quarantined_files WHERE tenant_id=p_tenant AND ciphertext IS NOT NULL;
 IF n>=100 THEN RAISE EXCEPTION 'Tenant quarantine capacity reached' USING ERRCODE='54000'; END IF;
 -- Preserve disposed markers without letting expired bytes permanently exhaust the live quota.
 SELECT count(*) INTO n FROM private.quarantined_files WHERE tenant_id=p_tenant;
 IF n>=10000 THEN RAISE EXCEPTION 'Tenant quarantine history capacity reached' USING ERRCODE='54000'; END IF;
 INSERT INTO private.quarantined_files(tenant_id,batch_id,file_sha256,byte_count,key_id,nonce,auth_tag,ciphertext,uploaded_by)
 VALUES(p_tenant,p_batch,p_sha,octet_length(p_cipher),p_key,p_nonce,p_tag,p_cipher,actor)
 RETURNING created_at INTO stored_at;
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,metadata)
 VALUES(p_tenant,actor,'file_quarantined','import_batch',p_batch,jsonb_build_object('bytes',octet_length(p_cipher),'scanStatus','pending'));
 RETURN jsonb_build_object('batchId',p_batch,'scanStatus','pending','byteCount',octet_length(p_cipher),'createdAt',stored_at);
END $fn$;
REVOKE ALL ON FUNCTION private.quarantine_invoice_file(uuid,uuid,text,text,bytea,bytea,bytea) FROM PUBLIC,profitpilot_app;
GRANT EXECUTE ON FUNCTION private.quarantine_invoice_file(uuid,uuid,text,text,bytea,bytea,bytea) TO profitpilot_app;

-- Quarantined bytes must not be consumed by the existing parsed-row path.
CREATE FUNCTION private.guard_quarantined_batch_ingestion()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
BEGIN
 IF session_user='profitpilot_app' AND private.current_tenant_id() IS DISTINCT FROM NEW.tenant_id THEN RETURN NEW; END IF;
 -- Serialize with the upload transaction, including direct runtime SQL writes.
 PERFORM 1 FROM public.import_batches WHERE tenant_id=NEW.tenant_id AND id=NEW.batch_id FOR UPDATE;
 IF EXISTS(SELECT 1 FROM private.quarantined_files WHERE tenant_id=NEW.tenant_id AND batch_id=NEW.batch_id) THEN
  RAISE EXCEPTION 'Quarantined file is not approved for ingestion' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $fn$;
REVOKE ALL ON FUNCTION private.guard_quarantined_batch_ingestion() FROM PUBLIC,profitpilot_app;
CREATE TRIGGER quarantine_ingestion_guard BEFORE INSERT ON public.raw_import_rows
 FOR EACH ROW EXECUTE FUNCTION private.guard_quarantined_batch_ingestion();

-- Narrow status function never returns bytes, encryption material, or identity.
CREATE FUNCTION private.quarantine_status(p_tenant uuid,p_batch uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
BEGIN
 IF p_tenant IS NULL OR private.current_tenant_id() IS DISTINCT FROM p_tenant THEN RETURN false; END IF;
 RETURN EXISTS(SELECT 1 FROM private.quarantined_files WHERE tenant_id=p_tenant AND batch_id=p_batch);
END $fn$;
REVOKE ALL ON FUNCTION private.quarantine_status(uuid,uuid) FROM PUBLIC,profitpilot_app;
GRANT EXECUTE ON FUNCTION private.quarantine_status(uuid,uuid) TO profitpilot_app;
COMMIT;

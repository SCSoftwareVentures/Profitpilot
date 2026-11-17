-- Bounded encrypted quarantine only. Never grant runtime access to ciphertext.
BEGIN;
CREATE TABLE private.quarantined_attachments(
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,batch_id uuid NOT NULL,created_by uuid NOT NULL,
 media_type text NOT NULL CHECK(media_type IN ('application/pdf','image/png','image/jpeg')),
 key_id text NOT NULL CHECK(key_id ~ '^[A-Za-z0-9._-]{1,64}$'),
 byte_count integer NOT NULL CHECK(byte_count BETWEEN 8 AND 262144),
 nonce bytea,tag bytea,ciphertext bytea,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),discarded_at timestamptz,
 FOREIGN KEY(tenant_id,batch_id) REFERENCES public.import_batches(tenant_id,id),
 FOREIGN KEY(tenant_id,created_by) REFERENCES public.tenant_memberships(tenant_id,user_id),
 CHECK((discarded_at IS NULL AND nonce IS NOT NULL AND octet_length(nonce)=12 AND tag IS NOT NULL AND octet_length(tag)=16 AND ciphertext IS NOT NULL AND octet_length(ciphertext)=byte_count)
 OR (discarded_at IS NOT NULL AND nonce IS NULL AND tag IS NULL AND ciphertext IS NULL))
);
ALTER TABLE private.quarantined_attachments OWNER TO profitpilot_context_owner;
REVOKE ALL ON private.quarantined_attachments FROM PUBLIC,profitpilot_app;
CREATE INDEX quarantine_tenant_batch ON private.quarantined_attachments(tenant_id,batch_id);
CREATE UNIQUE INDEX quarantine_key_nonce_unique ON private.quarantined_attachments(key_id,nonce) WHERE nonce IS NOT NULL;
CREATE FUNCTION private.store_quarantined_attachment(p_tenant uuid,p_batch uuid,p_id uuid,p_type text,p_key text,p_size integer,p_nonce bytea,p_tag bytea,p_cipher bytea,p_auth_time bigint,p_proof text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
DECLARE actor uuid; batch public.import_batches%ROWTYPE;
BEGIN
 IF p_id IS NULL OR p_type IS NULL OR p_type NOT IN ('application/pdf','image/png','image/jpeg') OR p_key IS NULL OR p_key !~ '^[A-Za-z0-9._-]{1,64}$'
 OR p_size IS NULL OR p_size NOT BETWEEN 8 AND 262144 OR p_nonce IS NULL OR octet_length(p_nonce)<>12 OR p_tag IS NULL OR octet_length(p_tag)<>16
 OR p_cipher IS NULL OR octet_length(p_cipher)<>p_size THEN RAISE EXCEPTION 'Invalid quarantine envelope' USING ERRCODE='22023';END IF;
 actor:=private.assert_privacy_step_up(p_tenant,p_batch,'quarantine_attachment:'||p_id::text||':'||p_type||':'||p_key||':'||p_size::text||':'||encode(p_nonce,'hex')||':'||encode(p_tag,'hex')||':'||encode(public.digest(p_cipher,'sha256'),'hex'),p_auth_time,p_proof);
 IF private.has_scoped_permission(p_tenant,'imports.rows.write') IS DISTINCT FROM true THEN RAISE EXCEPTION 'Import permission required' USING ERRCODE='42501';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('quarantine:'||p_tenant::text,0));
 SELECT * INTO batch FROM public.import_batches WHERE tenant_id=p_tenant AND id=p_batch FOR SHARE;
 IF NOT FOUND THEN RETURN jsonb_build_object('status',404,'error','Import batch not found');END IF;
 IF batch.created_by<>actor THEN RETURN jsonb_build_object('status',403,'error','Original importer required');END IF;
 IF batch.status NOT IN ('uploaded','review') THEN RETURN jsonb_build_object('status',409,'error','Batch is not open');END IF;
 -- The cap counts tombstones too, preventing unbounded repeated synthetic upload/discard cycles.
 IF (SELECT count(*) FROM private.quarantined_attachments WHERE tenant_id=p_tenant)>=20
 OR (SELECT count(*) FROM private.quarantined_attachments WHERE tenant_id=p_tenant AND batch_id=p_batch)>=3
 THEN RETURN jsonb_build_object('status',409,'error','Quarantine capacity reached');END IF;
 INSERT INTO private.quarantined_attachments(id,tenant_id,batch_id,created_by,media_type,key_id,byte_count,nonce,tag,ciphertext)
 VALUES(p_id,p_tenant,p_batch,actor,p_type,p_key,p_size,p_nonce,p_tag,p_cipher);
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata)
 VALUES(p_tenant,actor,'attachment_quarantined','quarantined_attachment',p_id,'Synthetic attachment encrypted and quarantined',jsonb_build_object('batchId',p_batch,'mediaType',p_type,'byteCount',p_size,'scannerVerified',false));
 RETURN jsonb_build_object('status',201,'item',jsonb_build_object('id',p_id,'status','quarantined','scannerVerified',false,'downloadAvailable',false));
END
$fn$;
ALTER FUNCTION private.store_quarantined_attachment(uuid,uuid,uuid,text,text,integer,bytea,bytea,bytea,bigint,text) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.store_quarantined_attachment(uuid,uuid,uuid,text,text,integer,bytea,bytea,bytea,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.store_quarantined_attachment(uuid,uuid,uuid,text,text,integer,bytea,bytea,bytea,bigint,text) TO profitpilot_app;

CREATE FUNCTION private.discard_quarantined_attachment(p_tenant uuid,p_batch uuid,p_id uuid,p_auth_time bigint,p_proof text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
DECLARE actor uuid; item private.quarantined_attachments%ROWTYPE; at_time timestamptz;
BEGIN
 actor:=private.assert_privacy_step_up(p_tenant,p_batch,'discard_quarantined_attachment:'||p_id::text,p_auth_time,p_proof);
 IF private.has_scoped_permission(p_tenant,'imports.rows.write') IS DISTINCT FROM true THEN RAISE EXCEPTION 'Import permission required' USING ERRCODE='42501';END IF;
 SELECT * INTO item FROM private.quarantined_attachments WHERE tenant_id=p_tenant AND batch_id=p_batch AND id=p_id AND created_by=actor FOR UPDATE;
 IF NOT FOUND THEN RETURN jsonb_build_object('status',404,'error','Quarantined attachment not found');END IF;
 PERFORM private.lock_privacy_retention_subject(p_tenant,actor);
 IF item.discarded_at IS NOT NULL
 OR EXISTS(SELECT 1 FROM private.privacy_retention_holds WHERE tenant_id=p_tenant)
 OR EXISTS(SELECT 1 FROM private.discarded_import_holds WHERE tenant_id=p_tenant)
 OR EXISTS(SELECT 1 FROM public.privacy_requests WHERE tenant_id=p_tenant AND status IN ('requested','identity_verification','under_review','legal_hold'))
 THEN RETURN jsonb_build_object('status',409,'error','Quarantine is already discarded or retained for review');END IF;
 at_time:=clock_timestamp();
 UPDATE private.quarantined_attachments SET ciphertext=NULL,nonce=NULL,tag=NULL,discarded_at=at_time WHERE id=p_id;
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata)
 VALUES(p_tenant,actor,'attachment_quarantine_discarded','quarantined_attachment',p_id,'Quarantined byte envelope removed from active database',jsonb_build_object('batchId',p_batch,'completePersonalDataDeletion',false));
 RETURN jsonb_build_object('status',200,'item',jsonb_build_object('id',p_id,'status','discarded','completePersonalDataDeletion',false));
END
$fn$;
ALTER FUNCTION private.discard_quarantined_attachment(uuid,uuid,uuid,bigint,text) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.discard_quarantined_attachment(uuid,uuid,uuid,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.discard_quarantined_attachment(uuid,uuid,uuid,bigint,text) TO profitpilot_app;

CREATE FUNCTION private.guard_quarantine_tombstone() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Quarantine deletion tombstones must be preserved' USING ERRCODE='55000';END IF;
 IF OLD.discarded_at IS NOT NULL OR NEW.discarded_at IS NULL OR
 ROW(NEW.id,NEW.tenant_id,NEW.batch_id,NEW.created_by,NEW.media_type,NEW.key_id,NEW.byte_count,NEW.created_at)
 IS DISTINCT FROM ROW(OLD.id,OLD.tenant_id,OLD.batch_id,OLD.created_by,OLD.media_type,OLD.key_id,OLD.byte_count,OLD.created_at)
 THEN RAISE EXCEPTION 'Quarantine is immutable except one-way discard' USING ERRCODE='55000';END IF;
 RETURN NEW;
END
$fn$;
ALTER FUNCTION private.guard_quarantine_tombstone() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.guard_quarantine_tombstone() FROM PUBLIC;
CREATE TRIGGER quarantine_tombstone_guard BEFORE UPDATE OR DELETE ON private.quarantined_attachments
 FOR EACH ROW EXECUTE FUNCTION private.guard_quarantine_tombstone();
ALTER FUNCTION private.privacy_restore_state() RENAME TO privacy_restore_state_before_quarantine;
CREATE FUNCTION private.privacy_restore_state() RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
 SELECT jsonb_build_object('markers',s.state->'markers'||COALESCE((SELECT jsonb_agg(jsonb_build_object('kind','attachment_discard','id',a.id,'tenantId',a.tenant_id,'at',extract(epoch FROM a.discarded_at)::text) ORDER BY a.id) FROM private.quarantined_attachments a WHERE a.discarded_at IS NOT NULL),'[]'::jsonb),'violations',s.state->'violations')
 FROM (SELECT private.privacy_restore_state_before_quarantine() AS state) s
$fn$;
ALTER FUNCTION private.privacy_restore_state() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.privacy_restore_state(),private.privacy_restore_state_before_quarantine() FROM PUBLIC,profitpilot_app;
COMMIT;

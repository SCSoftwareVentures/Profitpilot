-- Bind asynchronous approval to a short-lived server-attested MFA session.
BEGIN;
ALTER TABLE private.quarantine_promotions
 ADD COLUMN approval_session_digest text CHECK(approval_session_digest ~ '^[0-9a-f]{64}$'),
 ADD COLUMN approval_auth_time bigint CHECK(approval_auth_time>0),
 ADD CONSTRAINT approval_session_pair CHECK((approval_session_digest IS NULL)=(approval_auth_time IS NULL));
-- Previously queued approvals lack session binding; never promote them.
UPDATE private.quarantine_promotions SET state='failed',lease_id=NULL,lease_until=NULL
 WHERE state IN ('approved','processing');
REVOKE EXECUTE ON FUNCTION private.approve_quarantine_promotion(uuid,uuid) FROM profitpilot_app;
CREATE FUNCTION private.approve_quarantine_promotion_attested(
 p_tenant uuid,p_batch uuid,p_auth bigint,p_iat bigint,p_digest text,p_expires bigint,p_nonce text,p_key text,p_signature text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE subject text; uid uuid; now_s bigint; secret_value bytea; expected text; approved boolean;
BEGIN
 subject:=nullif(current_setting('app.tenant_subject',true),'');
 now_s:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 IF p_tenant IS NULL OR p_batch IS NULL OR private.current_tenant_id() IS DISTINCT FROM p_tenant
 OR subject IS NULL OR coalesce(private.current_actor_role(),'') NOT IN ('owner','admin')
 OR p_auth IS NULL OR p_auth<=0 OR p_auth<now_s-300 OR p_auth>now_s+5
 OR p_iat IS NULL OR p_auth>p_iat+5 OR p_iat>now_s+5 OR p_iat<now_s-905
 OR p_digest IS NULL OR p_digest !~ '^[a-f0-9]{64}$'
 OR p_expires IS NULL OR p_expires<now_s OR p_expires>now_s+30
 OR p_nonce IS NULL OR p_nonce !~ '^[a-f0-9]{32}$'
 OR p_key IS NULL OR p_key !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$'
 OR p_signature IS NULL OR p_signature !~ '^[a-f0-9]{64}$'
 THEN RAISE EXCEPTION 'Invalid session-bound promotion authority' USING ERRCODE='42501'; END IF;
 SELECT secret INTO secret_value FROM private.tenant_context_keys WHERE key_id=p_key AND active;
 IF NOT FOUND THEN RAISE EXCEPTION 'Promotion key unavailable' USING ERRCODE='42501'; END IF;
 expected:=encode(public.hmac(convert_to('profitpilot-promotion-v1'||E'\n'||p_tenant||E'\n'||p_batch||E'\n'||subject||E'\n'||p_auth||E'\n'||p_iat||E'\n'||p_digest||E'\n'||p_expires||E'\n'||p_nonce||E'\n'||p_key,'UTF8'),secret_value,'sha256'),'hex');
 IF expected<>p_signature THEN RAISE EXCEPTION 'Invalid promotion signature' USING ERRCODE='42501'; END IF;
 -- Lock the actor before checking revocations, as the existing approval
 -- function does. Concurrent revocation either commits before us or waits.
 SELECT u.id INTO uid FROM public.users u WHERE u.auth_subject=subject AND u.status='active' FOR SHARE;
 IF NOT FOUND OR EXISTS(SELECT 1 FROM private.identity_session_cutoffs WHERE user_id=uid AND revoked_through>=p_auth)
 OR EXISTS(SELECT 1 FROM private.revoked_identity_sessions WHERE user_id=uid AND session_digest=p_digest)
 THEN RAISE EXCEPTION 'Promotion session revoked' USING ERRCODE='42501'; END IF;
 approved:=private.approve_quarantine_promotion(p_tenant,p_batch);
 IF approved THEN
  UPDATE private.quarantine_promotions SET approval_session_digest=p_digest,approval_auth_time=p_auth
  WHERE tenant_id=p_tenant AND batch_id=p_batch AND approved_by=uid;
  IF NOT FOUND THEN RAISE EXCEPTION 'Promotion actor mismatch' USING ERRCODE='42501'; END IF;
 END IF;
 RETURN approved;
END $fn$;
REVOKE ALL ON FUNCTION private.approve_quarantine_promotion_attested(uuid,uuid,bigint,bigint,text,bigint,text,text,text) FROM PUBLIC,profitpilot_app;
GRANT EXECUTE ON FUNCTION private.approve_quarantine_promotion_attested(uuid,uuid,bigint,bigint,text,bigint,text,text,text) TO profitpilot_app;

CREATE OR REPLACE FUNCTION private.finish_quarantine_promotion(p_tenant uuid,p_batch uuid,p_lease uuid,p_rows jsonb)
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
 OR p.approval_session_digest IS NULL OR p.approval_auth_time IS NULL
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
 IF NOT FOUND
 OR EXISTS(SELECT 1 FROM private.identity_session_cutoffs c WHERE c.user_id=p.approved_by AND c.revoked_through>=p.approval_auth_time)
 OR EXISTS(SELECT 1 FROM private.revoked_identity_sessions s WHERE s.user_id=p.approved_by AND s.session_digest=p.approval_session_digest)
 THEN
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

COMMIT;

-- Emergency containment is independent of business suspension. Separate
-- privileges for imposing and releasing an incident; no automatic expiry.
BEGIN;
DO $check$ BEGIN
 IF NOT private.verify_security_catalog() THEN RAISE EXCEPTION 'Prior security catalog does not verify'; END IF;
END $check$;
DO $roles$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='profitpilot_incident_operator') THEN
  CREATE ROLE profitpilot_incident_operator NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='profitpilot_incident_recovery') THEN
  CREATE ROLE profitpilot_incident_recovery NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
 END IF;
END $roles$;
GRANT USAGE ON SCHEMA private TO profitpilot_incident_operator,profitpilot_incident_recovery;
CREATE TABLE private.tenant_emergency_incidents(
 incident_id uuid PRIMARY KEY,
 tenant_id uuid NOT NULL REFERENCES public.tenants(id),
 category text NOT NULL CHECK(category IN ('suspected_compromise','data_exposure','integrity_failure','operational_emergency')),
 authority_ref text NOT NULL CHECK(private.disposal_reference_valid(authority_ref)),
 activated_by text NOT NULL DEFAULT session_user,
 activated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 released_at timestamptz,
 release_ref text CHECK(private.disposal_reference_valid(release_ref)),
 released_by text,
 CHECK((released_at IS NULL AND release_ref IS NULL AND released_by IS NULL) OR
 (released_at IS NOT NULL AND release_ref IS NOT NULL AND released_by IS NOT NULL AND released_at>=activated_at))
);
CREATE UNIQUE INDEX tenant_one_active_emergency ON private.tenant_emergency_incidents(tenant_id) WHERE released_at IS NULL;
REVOKE ALL ON private.tenant_emergency_incidents FROM PUBLIC,profitpilot_app,profitpilot_incident_operator,profitpilot_incident_recovery;
GRANT SELECT ON private.tenant_emergency_incidents TO profitpilot_context_owner;
CREATE FUNCTION private.guard_incident_history()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
BEGIN
 IF OLD.released_at IS NOT NULL OR NEW.released_at IS NULL OR
 ROW(NEW.incident_id,NEW.tenant_id,NEW.category,NEW.authority_ref,NEW.activated_by,NEW.activated_at)
 IS DISTINCT FROM ROW(OLD.incident_id,OLD.tenant_id,OLD.category,OLD.authority_ref,OLD.activated_by,OLD.activated_at)
 THEN RAISE EXCEPTION 'Emergency incident history is immutable'; END IF;
 RETURN NEW;
END $fn$;
CREATE TRIGGER incident_history_guard BEFORE UPDATE ON private.tenant_emergency_incidents
 FOR EACH ROW EXECUTE FUNCTION private.guard_incident_history();
CREATE TRIGGER incident_history_no_delete BEFORE DELETE OR TRUNCATE ON private.tenant_emergency_incidents
 FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();
CREATE FUNCTION private.activate_tenant_emergency(p_tenant uuid,p_incident uuid,p_category text,p_ref text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
BEGIN
 IF p_tenant IS NULL OR p_incident IS NULL OR p_category IS NULL OR p_category NOT IN ('suspected_compromise','data_exposure','integrity_failure','operational_emergency')
 OR NOT private.disposal_reference_valid(p_ref) THEN RAISE EXCEPTION 'Invalid incident authority' USING ERRCODE='22023'; END IF;
 PERFORM 1 FROM public.tenants WHERE id=p_tenant FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Tenant unavailable'; END IF;
 INSERT INTO private.tenant_emergency_incidents(incident_id,tenant_id,category,authority_ref) VALUES(p_incident,p_tenant,p_category,p_ref);
 -- Invalidate outstanding promotion approvals, not existing evidence.
 WITH changed AS (
  UPDATE private.quarantine_promotions SET state='failed',lease_id=NULL,lease_until=NULL
  WHERE tenant_id=p_tenant AND state IN ('approved','processing') RETURNING tenant_id,batch_id
 ) INSERT INTO private.quarantine_lifecycle_events(tenant_id,batch_id,event_type)
 SELECT tenant_id,batch_id,'promotion_failed' FROM changed;
 INSERT INTO public.audit_events(tenant_id,action,object_type,object_id,metadata)
 VALUES(p_tenant,'emergency_containment_activated','security_control',p_incident,jsonb_build_object('category',p_category,'authorityRef',p_ref));
END $fn$;
CREATE FUNCTION private.release_tenant_emergency(p_tenant uuid,p_incident uuid,p_ref text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
BEGIN
 IF p_tenant IS NULL OR p_incident IS NULL OR NOT private.disposal_reference_valid(p_ref) THEN RAISE EXCEPTION 'Invalid recovery authority' USING ERRCODE='22023'; END IF;
 PERFORM 1 FROM public.tenants WHERE id=p_tenant FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Tenant unavailable'; END IF;
 UPDATE private.tenant_emergency_incidents SET released_at=clock_timestamp(),release_ref=p_ref,released_by=session_user
 WHERE tenant_id=p_tenant AND incident_id=p_incident AND released_at IS NULL;
 IF NOT FOUND THEN RAISE EXCEPTION 'Active incident does not match'; END IF;
 INSERT INTO public.audit_events(tenant_id,action,object_type,object_id,metadata)
 VALUES(p_tenant,'emergency_containment_released','security_control',p_incident,jsonb_build_object('authorityRef',p_ref));
END $fn$;

-- Runtime helper takes the same tenant row lock as emergency operators.
-- Calls after a completed activation cannot serve or persist tenant data.
CREATE FUNCTION private.lock_tenant_available(p_tenant uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
BEGIN
 IF p_tenant IS NULL OR (session_user='profitpilot_app' AND private.current_tenant_id() IS DISTINCT FROM p_tenant) THEN RETURN false; END IF;
 PERFORM 1 FROM public.tenants WHERE id=p_tenant AND status='active' FOR SHARE;
 IF NOT FOUND THEN RETURN false; END IF;
 RETURN NOT EXISTS(SELECT 1 FROM private.tenant_emergency_incidents WHERE tenant_id=p_tenant AND released_at IS NULL);
END $fn$;
REVOKE ALL ON FUNCTION private.guard_incident_history(),private.activate_tenant_emergency(uuid,uuid,text,text),private.release_tenant_emergency(uuid,uuid,text),private.lock_tenant_available(uuid) FROM PUBLIC,profitpilot_app;
GRANT EXECUTE ON FUNCTION private.activate_tenant_emergency(uuid,uuid,text,text) TO profitpilot_incident_operator;
GRANT EXECUTE ON FUNCTION private.release_tenant_emergency(uuid,uuid,text) TO profitpilot_incident_recovery;
GRANT EXECUTE ON FUNCTION private.lock_tenant_available(uuid) TO profitpilot_app;

CREATE OR REPLACE FUNCTION private.current_tenant_id()
RETURNS uuid LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,private
AS $function$
DECLARE
 v_tenant uuid; v_subject text; v_expires bigint; v_nonce text;
 v_key_id text; v_signature text; v_secret bytea; v_payload text; v_expected text;
BEGIN
 v_tenant:=nullif(current_setting('app.tenant_id',true),'')::uuid;
 v_subject:=nullif(current_setting('app.tenant_subject',true),'');
 v_expires:=nullif(current_setting('app.tenant_expires',true),'')::bigint;
 v_nonce:=nullif(current_setting('app.tenant_nonce',true),'');
 v_key_id:=nullif(current_setting('app.tenant_key_id',true),'');
 v_signature:=lower(nullif(current_setting('app.tenant_signature',true),''));
 IF v_tenant IS NULL OR v_subject IS NULL OR v_expires IS NULL OR v_nonce IS NULL OR v_key_id IS NULL OR v_signature IS NULL THEN RETURN NULL; END IF;
 IF v_expires < floor(extract(epoch FROM statement_timestamp()))::bigint OR v_expires > floor(extract(epoch FROM statement_timestamp()))::bigint+60 THEN RETURN NULL; END IF;
 IF v_nonce !~ '^[a-f0-9]{32}$' OR v_signature !~ '^[a-f0-9]{64}$' THEN RETURN NULL; END IF;
 SELECT secret INTO v_secret FROM private.tenant_context_keys WHERE key_id=v_key_id AND active=true;
 IF v_secret IS NULL THEN RETURN NULL; END IF;
 v_payload:=v_tenant::text||E'\n'||v_subject||E'\n'||v_expires::text||E'\n'||v_nonce||E'\n'||v_key_id;
 v_expected:=encode(public.hmac(convert_to(v_payload,'UTF8'),v_secret,'sha256'),'hex');
 IF v_expected<>v_signature THEN RETURN NULL; END IF;
 IF NOT EXISTS(SELECT 1 FROM public.tenant_memberships tm JOIN public.users u ON u.id=tm.user_id JOIN public.tenants t ON t.id=tm.tenant_id WHERE tm.tenant_id=v_tenant AND u.auth_subject=v_subject AND tm.status='active' AND u.status='active' AND t.status='active') THEN RETURN NULL; END IF;
 IF EXISTS(SELECT 1 FROM private.tenant_emergency_incidents WHERE tenant_id=v_tenant AND released_at IS NULL) THEN RETURN NULL; END IF;
 RETURN v_tenant;
EXCEPTION WHEN OTHERS THEN RETURN NULL;
END;
$function$;

CREATE OR REPLACE FUNCTION private.finish_quarantine_promotion(p_tenant uuid,p_batch uuid,p_lease uuid,p_rows jsonb)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE p private.quarantine_promotions%ROWTYPE; q private.quarantined_files%ROWTYPE; b public.import_batches%ROWTYPE; manifest private.quarantine_manifests%ROWTYPE;
BEGIN
 -- Serialize with emergency containment before processing.
 IF NOT private.lock_tenant_available(p_tenant) THEN RETURN -1; END IF;
 -- Global lock order: tenant, batch, file, promotion. Expiry follows batch order.
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


CREATE OR REPLACE FUNCTION private.claim_quarantine_scan()
RETURNS TABLE(tenant_id uuid,batch_id uuid,file_sha256 text,key_id text,nonce bytea,auth_tag bytea,ciphertext bytea,lease_id uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE candidate private.quarantined_files%ROWTYPE;
BEGIN
 SELECT q.* INTO candidate FROM private.quarantined_files q
 WHERE NOT EXISTS(SELECT 1 FROM private.tenant_emergency_incidents i WHERE i.tenant_id=q.tenant_id AND i.released_at IS NULL)
 AND q.created_at>clock_timestamp()-interval '24 hours' AND q.attempts<3
 AND (q.scan_state IN ('pending','error') OR (q.scan_state='scanning' AND q.lease_until<clock_timestamp()))
 ORDER BY q.created_at,q.batch_id LIMIT 1 FOR UPDATE SKIP LOCKED;
 IF NOT FOUND THEN RETURN; END IF;
 UPDATE private.quarantined_files q SET scan_state='scanning',lease_id=gen_random_uuid(),
 lease_until=clock_timestamp()+interval '2 minutes',attempts=q.attempts+1
 WHERE q.tenant_id=candidate.tenant_id AND q.batch_id=candidate.batch_id RETURNING q.* INTO candidate;
 INSERT INTO private.quarantine_lifecycle_events(tenant_id,batch_id,event_type)
 VALUES(candidate.tenant_id,candidate.batch_id,'claimed');
 RETURN QUERY SELECT candidate.tenant_id,candidate.batch_id,candidate.file_sha256,candidate.key_id,candidate.nonce,candidate.auth_tag,candidate.ciphertext,candidate.lease_id;
END $fn$;


CREATE OR REPLACE FUNCTION private.finish_quarantine_scan(p_tenant uuid,p_batch uuid,p_lease uuid,p_verdict text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
BEGIN
 IF NOT private.lock_tenant_available(p_tenant) THEN RETURN false; END IF;
 IF p_verdict IS NULL OR p_verdict NOT IN ('clean','infected','error') THEN RAISE EXCEPTION 'Invalid scan verdict'; END IF;
 UPDATE private.quarantined_files q SET scan_state=p_verdict,lease_id=NULL,lease_until=NULL,scanned_at=clock_timestamp()
 WHERE q.tenant_id=p_tenant AND q.batch_id=p_batch AND q.scan_state='scanning'
 AND q.lease_id=p_lease AND q.lease_until>=clock_timestamp();
 IF NOT FOUND THEN RETURN false; END IF;
 INSERT INTO private.quarantine_lifecycle_events(tenant_id,batch_id,event_type) VALUES(p_tenant,p_batch,p_verdict);
 RETURN true;
END $fn$;


CREATE OR REPLACE FUNCTION private.claim_quarantine_promotion()
RETURNS TABLE(tenant_id uuid,batch_id uuid,file_sha256 text,key_id text,nonce bytea,auth_tag bytea,ciphertext bytea,lease_id uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE p private.quarantine_promotions%ROWTYPE; q private.quarantined_files%ROWTYPE;
BEGIN
 SELECT x.* INTO p FROM private.quarantine_promotions x JOIN private.quarantined_files f ON f.tenant_id=x.tenant_id AND f.batch_id=x.batch_id
 WHERE NOT EXISTS(SELECT 1 FROM private.tenant_emergency_incidents i WHERE i.tenant_id=x.tenant_id AND i.released_at IS NULL)
 AND x.attempts<3 AND (x.state='approved' OR (x.state='processing' AND x.lease_until<clock_timestamp()))
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



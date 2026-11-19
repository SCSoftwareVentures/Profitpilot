-- SANDBOX ONLY. No automatic retention duration; explicit approved policy required.
BEGIN;
CREATE ROLE securepay_retention_runtime NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS;
GRANT USAGE ON SCHEMA securepay_private TO securepay_retention_runtime;
CREATE TABLE securepay_private.evidence_scan_keys(
 key_id text PRIMARY KEY CHECK(key_id ~ '^[a-z0-9-]{1,32}$'),
 secret bytea NOT NULL CHECK(octet_length(secret)=32),active boolean NOT NULL DEFAULT true,valid_until timestamptz
);
ALTER TABLE securepay_private.evidence_scan_keys OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.evidence_scan_keys FROM PUBLIC,securepay_dispute_runtime,securepay_retention_runtime;
-- Do not silently treat historical evidence as scanned.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM securepay_private.dispute_photos) THEN RAISE EXCEPTION 'Existing evidence requires reviewed screening migration'; END IF;
END $$;
ALTER TABLE securepay_private.dispute_photos ADD COLUMN scan_key_id text REFERENCES securepay_private.evidence_scan_keys(key_id),
 ADD COLUMN screened_at timestamptz,ADD COLUMN purged_at timestamptz,
 ALTER COLUMN content DROP NOT NULL,
 ADD CONSTRAINT sp_evidence_payload_pair CHECK((purged_at IS NULL AND content IS NOT NULL) OR (purged_at IS NOT NULL AND content IS NULL));
-- The pre-screening function is internal only: callers cannot bypass the scanner.
REVOKE EXECUTE ON FUNCTION securepay_private.store_dispute_photo(uuid,uuid,uuid,uuid,uuid,text,text,bytea,bigint,text) FROM securepay_dispute_runtime;
CREATE FUNCTION securepay_private.store_screened_photo(p uuid,t uuid,m uuid,d uuid,a uuid,mime text,digest text,blob bytea,expires bigint,sig text,scan_exp bigint,envelope text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE kid text; k bytea; n bigint; payload text;
BEGIN
 n:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 IF p IS NULL OR t IS NULL OR m IS NULL OR d IS NULL OR a IS NULL OR mime IS DISTINCT FROM 'image/png' OR digest IS NULL OR digest !~ '^[a-f0-9]{64}$'
 OR scan_exp IS NULL OR scan_exp<n OR scan_exp>n+45 OR envelope IS NULL OR envelope !~ '^[a-z0-9-]{1,32}[.][a-f0-9]{64}$' THEN RETURN false; END IF;
 kid:=split_part(envelope,'.',1);
 SELECT secret INTO k FROM securepay_private.evidence_scan_keys WHERE key_id=kid AND active AND (valid_until IS NULL OR valid_until>clock_timestamp());
 payload:=concat_ws(':','sp-evidence-scan-v1',p,t,m,d,a,mime,digest,scan_exp,kid);
 IF k IS NULL OR encode(public.hmac(convert_to(payload,'UTF8'),k,'sha256'),'hex')<>split_part(envelope,'.',2) THEN RETURN false; END IF;
 IF securepay_private.store_dispute_photo(p,t,m,d,a,mime,digest,blob,expires,sig) IS DISTINCT FROM true THEN RETURN false; END IF;
 UPDATE securepay_private.dispute_photos SET scan_key_id=kid,screened_at=clock_timestamp() WHERE photo_id=p;
 RETURN true;
END $$;
ALTER FUNCTION securepay_private.store_screened_photo(uuid,uuid,uuid,uuid,uuid,text,text,bytea,bigint,text,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.store_screened_photo(uuid,uuid,uuid,uuid,uuid,text,text,bytea,bigint,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.store_screened_photo(uuid,uuid,uuid,uuid,uuid,text,text,bytea,bigint,text,bigint,text) TO securepay_dispute_runtime;
CREATE OR REPLACE FUNCTION securepay_private.read_dispute_photo(p uuid,t uuid,m uuid,d uuid,a uuid,expires bigint,sig text)
 RETURNS TABLE(media_type text,digest text,content bytea)
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c securepay_private.dispute_cases%ROWTYPE; role_name text; record_photo securepay_private.dispute_photos%ROWTYPE; secret_key bytea; plain bytea;
BEGIN
 IF p IS NULL OR t IS NULL OR m IS NULL OR d IS NULL OR a IS NULL THEN RETURN; END IF;
 role_name:=securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-photo-read-v1',p,t,m,d,a,expires),expires,sig);
 IF role_name IS NULL OR role_name NOT IN ('owner','customer','reviewer') THEN RETURN; END IF;
 SELECT * INTO c FROM securepay_private.dispute_cases WHERE case_id=d AND tenant_id=t AND milestone_id=m;
 IF NOT FOUND OR (role_name='owner' AND a<>c.owner_id) OR (role_name='customer' AND a<>c.customer_id)
 OR (role_name='reviewer' AND (a IN (c.owner_id,c.customer_id) OR NOT EXISTS(SELECT 1 FROM securepay_private.dispute_photo_reviewers v WHERE v.case_id=d AND v.tenant_id=t AND v.reviewer_id=a))) THEN RETURN; END IF;
 SELECT q.* INTO record_photo FROM securepay_private.dispute_photos q WHERE q.photo_id=p AND q.case_id=d;
 IF NOT FOUND OR record_photo.purged_at IS NOT NULL THEN RETURN; END IF;
 SELECT secret INTO secret_key FROM securepay_private.evidence_keys WHERE key_id=record_photo.key_id AND read_enabled;
 IF secret_key IS NULL THEN RAISE EXCEPTION 'Evidence unavailable' USING ERRCODE='22000'; END IF;
 plain:=public.pgp_sym_decrypt_bytea(record_photo.content,encode(secret_key,'hex'));
 IF octet_length(plain)<>record_photo.plaintext_size OR encode(public.digest(plain,'sha256'),'hex')<>record_photo.digest THEN
  RAISE EXCEPTION 'Evidence integrity failure' USING ERRCODE='22000';
 END IF;
 PERFORM securepay_private.append_audit_chain(t,'dispute_photos','READ',encode(public.digest(convert_to(concat_ws(':',p,d,a,record_photo.digest),'UTF8'),'sha256'),'hex'));
 RETURN QUERY SELECT record_photo.media_type,record_photo.digest,plain;
END $$;
CREATE TABLE securepay_private.evidence_retention_policy(
 case_id uuid PRIMARY KEY REFERENCES securepay_private.dispute_cases(case_id),
 tenant_id uuid NOT NULL,retain_until timestamptz NOT NULL,legal_hold boolean NOT NULL DEFAULT true,
 reason text NOT NULL CHECK(length(btrim(reason)) BETWEEN 10 AND 1000),
 approved_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE securepay_private.evidence_retention_policy OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.evidence_retention_policy FROM PUBLIC,securepay_retention_runtime,securepay_dispute_runtime;
CREATE TRIGGER sp_chain_retention_policy AFTER INSERT OR UPDATE OR DELETE ON securepay_private.evidence_retention_policy FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
CREATE FUNCTION securepay_private.purge_expired_evidence(batch_size integer) RETURNS integer
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c securepay_private.dispute_cases%ROWTYPE; total integer:=0; changed integer; n timestamptz:=clock_timestamp();
BEGIN
 IF batch_size IS NULL OR batch_size NOT BETWEEN 1 AND 100 THEN RETURN 0; END IF;
 FOR c IN SELECT q.* FROM securepay_private.dispute_cases q JOIN securepay_private.evidence_retention_policy p ON p.case_id=q.case_id AND p.tenant_id=q.tenant_id
 WHERE q.status='settled' AND NOT p.legal_hold AND p.retain_until<=n
 AND EXISTS(SELECT 1 FROM securepay_private.dispute_photos x WHERE x.case_id=q.case_id AND x.purged_at IS NULL)
 ORDER BY p.retain_until,q.case_id LIMIT batch_size FOR UPDATE OF q SKIP LOCKED LOOP
  PERFORM 1 FROM securepay_private.evidence_retention_policy p WHERE p.case_id=c.case_id AND p.tenant_id=c.tenant_id AND NOT p.legal_hold AND p.retain_until<=clock_timestamp() FOR UPDATE;
  IF NOT FOUND THEN CONTINUE; END IF;
  UPDATE securepay_private.dispute_photos SET content=NULL,purged_at=clock_timestamp() WHERE case_id=c.case_id AND purged_at IS NULL;
  GET DIAGNOSTICS changed=ROW_COUNT;total:=total+changed;
 END LOOP;
 RETURN total;
END $$;
ALTER FUNCTION securepay_private.purge_expired_evidence(integer) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.purge_expired_evidence(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.purge_expired_evidence(integer) TO securepay_retention_runtime;
COMMIT;

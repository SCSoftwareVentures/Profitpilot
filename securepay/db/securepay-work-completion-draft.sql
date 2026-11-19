-- Mandatory ordinary work completion, sandbox only. No provider execution.
BEGIN;
CREATE ROLE securepay_completion_runtime NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS;
GRANT USAGE ON SCHEMA securepay_private TO securepay_completion_runtime;
CREATE TABLE securepay_private.work_assignments(
 tenant_id uuid NOT NULL,milestone_id uuid NOT NULL,owner_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,milestone_id),FOREIGN KEY(tenant_id,milestone_id) REFERENCES public.securepay_milestones(tenant_id,id),
 FOREIGN KEY(tenant_id,owner_id) REFERENCES securepay_private.dispute_actors(tenant_id,actor_id)
);
CREATE TABLE securepay_private.work_completion(
 completion_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,milestone_id uuid NOT NULL,owner_id uuid NOT NULL,
 customer_id uuid NOT NULL,amount_cents bigint NOT NULL CHECK(amount_cents>0),
 status text NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','submitted','approved')),
 manifest_digest text CHECK(manifest_digest ~ '^[a-f0-9]{64}$'),approved_version bigint,
 comments text NOT NULL DEFAULT '' CHECK(length(comments)<=2000),
 UNIQUE(tenant_id,milestone_id),FOREIGN KEY(tenant_id,milestone_id) REFERENCES public.securepay_milestones(tenant_id,id),
 CHECK((status='draft')=(manifest_digest IS NULL)),CHECK((status='approved')=(approved_version IS NOT NULL))
);
CREATE TABLE securepay_private.work_photos(
 photo_id uuid PRIMARY KEY,completion_id uuid NOT NULL REFERENCES securepay_private.work_completion(completion_id),
 tenant_id uuid NOT NULL,digest text NOT NULL CHECK(digest ~ '^[a-f0-9]{64}$'),original_digest text NOT NULL CHECK(original_digest ~ '^[a-f0-9]{64}$'),
 original_media_type text NOT NULL CHECK(original_media_type IN ('image/png','image/jpeg')),
 content bytea NOT NULL CHECK(octet_length(content) BETWEEN 32 AND 2101248),plaintext_size integer NOT NULL CHECK(plaintext_size BETWEEN 8 AND 2097152),
 key_id text NOT NULL REFERENCES securepay_private.evidence_keys(key_id),scan_key_id text NOT NULL REFERENCES securepay_private.evidence_scan_keys(key_id),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(completion_id,digest)
);
CREATE TABLE securepay_private.work_photo_views(
 tenant_id uuid NOT NULL,completion_id uuid NOT NULL REFERENCES securepay_private.work_completion(completion_id),
 photo_id uuid NOT NULL REFERENCES securepay_private.work_photos(photo_id),customer_id uuid NOT NULL,
 viewed_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(completion_id,photo_id,customer_id)
);
CREATE TABLE securepay_private.work_approvals(
 completion_id uuid PRIMARY KEY REFERENCES securepay_private.work_completion(completion_id),tenant_id uuid NOT NULL,customer_id uuid NOT NULL,
 manifest_digest text NOT NULL,amount_cents bigint NOT NULL,approved_version bigint NOT NULL,approved_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE securepay_private.work_assignments OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.work_assignments FROM PUBLIC,securepay_completion_runtime,securepay_payer_runtime,securepay_provider_runtime,securepay_dispute_runtime,securepay_reporting_runtime;
CREATE TRIGGER sp_chain_work_assignments AFTER INSERT OR UPDATE OR DELETE ON securepay_private.work_assignments FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
ALTER TABLE securepay_private.work_completion OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.work_completion FROM PUBLIC,securepay_completion_runtime,securepay_payer_runtime,securepay_provider_runtime,securepay_dispute_runtime,securepay_reporting_runtime;
CREATE TRIGGER sp_chain_work_completion AFTER INSERT OR UPDATE OR DELETE ON securepay_private.work_completion FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
ALTER TABLE securepay_private.work_photos OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.work_photos FROM PUBLIC,securepay_completion_runtime,securepay_payer_runtime,securepay_provider_runtime,securepay_dispute_runtime,securepay_reporting_runtime;
CREATE TRIGGER sp_chain_work_photos AFTER INSERT OR UPDATE OR DELETE ON securepay_private.work_photos FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
ALTER TABLE securepay_private.work_photo_views OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.work_photo_views FROM PUBLIC,securepay_completion_runtime,securepay_payer_runtime,securepay_provider_runtime,securepay_dispute_runtime,securepay_reporting_runtime;
CREATE TRIGGER sp_chain_work_photo_views AFTER INSERT OR UPDATE OR DELETE ON securepay_private.work_photo_views FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
ALTER TABLE securepay_private.work_approvals OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.work_approvals FROM PUBLIC,securepay_completion_runtime,securepay_payer_runtime,securepay_provider_runtime,securepay_dispute_runtime,securepay_reporting_runtime;
CREATE TRIGGER sp_chain_work_approvals AFTER INSERT OR UPDATE OR DELETE ON securepay_private.work_approvals FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
CREATE FUNCTION securepay_private.work_manifest(z uuid) RETURNS text
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT encode(public.digest(convert_to(concat_ws(':','sp-work-v1',w.completion_id,w.tenant_id,w.milestone_id,w.customer_id,w.amount_cents,
 encode(convert_to(w.comments,'UTF8'),'hex'),(SELECT string_agg(p.photo_id::text||':'||p.digest||':'||p.original_digest||':'||p.original_media_type,':' ORDER BY p.photo_id) FROM securepay_private.work_photos p WHERE p.completion_id=z)),'UTF8'),'sha256'),'hex')
 FROM securepay_private.work_completion w WHERE w.completion_id=z
$$;
CREATE FUNCTION securepay_private.start_work_completion(z uuid,t uuid,m uuid,a uuid,expires bigint,sig text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE x public.securepay_milestones%ROWTYPE;
BEGIN
 IF z IS NULL OR t IS NULL OR m IS NULL OR a IS NULL OR securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-work-start-v1',z,t,m,a,expires),expires,sig) IS DISTINCT FROM 'owner' THEN RETURN false; END IF;
 SELECT * INTO x FROM public.securepay_milestones WHERE tenant_id=t AND id=m FOR UPDATE;
 IF NOT FOUND OR x.status<>'planned' OR x.payer_customer_id IS NULL OR a=x.payer_customer_id OR NOT EXISTS(SELECT 1 FROM securepay_private.work_assignments WHERE tenant_id=t AND milestone_id=m AND owner_id=a) THEN RETURN false; END IF;
 INSERT INTO securepay_private.work_completion(completion_id,tenant_id,milestone_id,owner_id,customer_id,amount_cents) VALUES(z,t,m,a,x.payer_customer_id,x.amount_cents);
 RETURN true;
EXCEPTION WHEN unique_violation THEN RETURN false;
END $$;
CREATE FUNCTION securepay_private.store_work_photo(p uuid,z uuid,t uuid,m uuid,a uuid,digest text,original_mime text,source_digest text,blob bytea,expires bigint,sig text,scan_exp bigint,envelope text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE w securepay_private.work_completion%ROWTYPE;k bytea;kid text;ek bytea;eid text;
BEGIN
 IF p IS NULL OR z IS NULL OR t IS NULL OR m IS NULL OR a IS NULL OR digest IS NULL OR digest !~ '^[a-f0-9]{64}$'
 OR source_digest IS NULL OR source_digest !~ '^[a-f0-9]{64}$' OR original_mime IS NULL OR original_mime NOT IN ('image/png','image/jpeg') OR (original_mime='image/png' AND source_digest<>digest)
 OR blob IS NULL OR octet_length(blob) NOT BETWEEN 8 AND 2097152 OR substring(blob FROM 1 FOR 8)<>decode('89504e470d0a1a0a','hex') OR encode(public.digest(blob,'sha256'),'hex')<>digest
 OR scan_exp IS NULL OR scan_exp NOT BETWEEN floor(extract(epoch FROM clock_timestamp()))::bigint AND floor(extract(epoch FROM clock_timestamp()))::bigint+45
 OR envelope IS NULL OR envelope !~ '^[a-z0-9-]{1,32}[.][a-f0-9]{64}$' THEN RETURN false; END IF;
 IF securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-work-photo-v1',p,z,t,m,a,digest,original_mime,source_digest,expires),expires,sig) IS DISTINCT FROM 'owner' THEN RETURN false; END IF;
 kid:=split_part(envelope,'.',1);
 SELECT secret INTO k FROM securepay_private.evidence_scan_keys WHERE key_id=kid AND active AND (valid_until IS NULL OR valid_until>clock_timestamp());
 IF k IS NULL OR encode(public.hmac(convert_to(concat_ws(':','sp-work-scan-v1',p,t,m,z,a,'image/png',digest,original_mime,source_digest,scan_exp,kid),'UTF8'),k,'sha256'),'hex')<>split_part(envelope,'.',2) THEN RETURN false; END IF;
 PERFORM 1 FROM public.securepay_milestones WHERE tenant_id=t AND id=m AND status='planned' FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO w FROM securepay_private.work_completion WHERE completion_id=z AND tenant_id=t AND milestone_id=m AND owner_id=a AND status='draft' FOR UPDATE;
 IF NOT FOUND OR (SELECT count(*) FROM securepay_private.work_photos WHERE completion_id=z)>=12 THEN RETURN false; END IF;
 SELECT key_id,secret INTO eid,ek FROM securepay_private.evidence_keys WHERE write_enabled FOR SHARE;
 IF ek IS NULL THEN RETURN false; END IF;
 INSERT INTO securepay_private.work_photos(photo_id,completion_id,tenant_id,digest,original_digest,original_media_type,content,plaintext_size,key_id,scan_key_id)
 VALUES(p,z,t,digest,source_digest,original_mime,public.pgp_sym_encrypt_bytea(blob,encode(ek,'hex'),'cipher-algo=aes256,compress-algo=0'),octet_length(blob),eid,kid);
 RETURN true;
EXCEPTION WHEN unique_violation THEN RETURN false;
END $$;
CREATE FUNCTION securepay_private.submit_work_completion(z uuid,t uuid,m uuid,a uuid,notes text,expires bigint,sig text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE x public.securepay_milestones%ROWTYPE;w securepay_private.work_completion%ROWTYPE;
BEGIN
 IF z IS NULL OR t IS NULL OR m IS NULL OR a IS NULL OR notes IS NULL OR length(notes)>2000 OR securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-work-submit-v1',z,t,m,a,encode(convert_to(notes,'UTF8'),'hex'),expires),expires,sig) IS DISTINCT FROM 'owner' THEN RETURN false; END IF;
 SELECT * INTO x FROM public.securepay_milestones WHERE tenant_id=t AND id=m FOR UPDATE;
 IF NOT FOUND OR x.status<>'planned' THEN RETURN false; END IF;
 SELECT * INTO w FROM securepay_private.work_completion WHERE completion_id=z AND tenant_id=t AND milestone_id=m AND owner_id=a AND status='draft' FOR UPDATE;
 IF NOT FOUND OR w.customer_id IS DISTINCT FROM x.payer_customer_id OR w.amount_cents<>x.amount_cents OR NOT EXISTS(SELECT 1 FROM securepay_private.work_photos WHERE completion_id=z) THEN RETURN false; END IF;
 UPDATE securepay_private.work_completion SET comments=notes WHERE completion_id=z;
 UPDATE securepay_private.work_completion SET status='submitted',manifest_digest=securepay_private.work_manifest(z) WHERE completion_id=z;
 UPDATE public.securepay_milestones SET status='submitted',version=version+1,updated_at=clock_timestamp() WHERE id=m AND tenant_id=t;
 RETURN true;
END $$;
CREATE FUNCTION securepay_private.payer_completion_view(t uuid,m uuid) RETURNS jsonb
 LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('completionId',w.completion_id,'manifestDigest',w.manifest_digest,'comments',w.comments,'version',x.version::text,'amountCents',w.amount_cents::text,'status',w.status,
 'photos',(SELECT coalesce(jsonb_agg(jsonb_build_object('photoId',p.photo_id,'digest',p.digest) ORDER BY p.photo_id),'[]'::jsonb) FROM securepay_private.work_photos p WHERE p.completion_id=w.completion_id))
 FROM securepay_private.work_completion w JOIN public.securepay_milestones x ON x.tenant_id=w.tenant_id AND x.id=w.milestone_id
 WHERE w.tenant_id=t AND w.milestone_id=m AND w.customer_id=securepay_private.current_payer(t) AND x.payer_customer_id=w.customer_id AND w.status IN ('submitted','approved')
$$;
CREATE FUNCTION securepay_private.payer_work_photo(t uuid,m uuid,p uuid) RETURNS TABLE(digest text,content bytea)
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c uuid;w securepay_private.work_completion%ROWTYPE;photo securepay_private.work_photos%ROWTYPE;k bytea;plain bytea;
BEGIN
 c:=securepay_private.current_payer(t);
 IF c IS NULL THEN RETURN; END IF;
 PERFORM 1 FROM public.securepay_milestones WHERE tenant_id=t AND id=m AND payer_customer_id=c FOR UPDATE;
 IF NOT FOUND THEN RETURN; END IF;
 SELECT * INTO w FROM securepay_private.work_completion WHERE tenant_id=t AND milestone_id=m AND customer_id=c AND status IN ('submitted','approved') FOR UPDATE;
 IF NOT FOUND THEN RETURN; END IF;
 SELECT * INTO photo FROM securepay_private.work_photos WHERE photo_id=p AND completion_id=w.completion_id AND tenant_id=t;
 IF NOT FOUND THEN RETURN; END IF;
 SELECT secret INTO k FROM securepay_private.evidence_keys WHERE key_id=photo.key_id AND read_enabled;
 IF k IS NULL THEN RAISE EXCEPTION 'Evidence unavailable'; END IF;
 plain:=public.pgp_sym_decrypt_bytea(photo.content,encode(k,'hex'));
 IF octet_length(plain)<>photo.plaintext_size OR encode(public.digest(plain,'sha256'),'hex')<>photo.digest THEN RAISE EXCEPTION 'Evidence integrity failure'; END IF;
 INSERT INTO securepay_private.work_photo_views(tenant_id,completion_id,photo_id,customer_id) VALUES(t,w.completion_id,p,c) ON CONFLICT DO NOTHING;
 RETURN QUERY SELECT photo.digest,plain;
END $$;
CREATE FUNCTION securepay_private.approve_work_completion(t uuid,m uuid,z uuid,manifest text,amount bigint,ver bigint) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c uuid;x public.securepay_milestones%ROWTYPE;w securepay_private.work_completion%ROWTYPE;
BEGIN
 c:=securepay_private.current_payer(t);
 IF c IS NULL OR z IS NULL OR manifest IS NULL OR amount IS NULL OR ver IS NULL THEN RETURN false; END IF;
 SELECT * INTO x FROM public.securepay_milestones WHERE tenant_id=t AND id=m FOR UPDATE;
 IF NOT FOUND OR x.status<>'submitted' OR x.payer_customer_id IS DISTINCT FROM c OR x.amount_cents<>amount OR x.version<>ver THEN RETURN false; END IF;
 SELECT * INTO w FROM securepay_private.work_completion WHERE completion_id=z AND tenant_id=t AND milestone_id=m AND customer_id=c AND status='submitted' FOR UPDATE;
 IF NOT FOUND OR w.amount_cents<>amount OR w.manifest_digest<>manifest OR securepay_private.work_manifest(z) IS DISTINCT FROM manifest
 OR NOT EXISTS(SELECT 1 FROM securepay_private.work_photos WHERE completion_id=z)
 OR EXISTS(SELECT 1 FROM securepay_private.work_photos p WHERE p.completion_id=z AND NOT EXISTS(SELECT 1 FROM securepay_private.work_photo_views v WHERE v.completion_id=z AND v.photo_id=p.photo_id AND v.customer_id=c)) THEN RETURN false; END IF;
 INSERT INTO securepay_private.work_approvals(completion_id,tenant_id,customer_id,manifest_digest,amount_cents,approved_version) VALUES(z,t,c,manifest,amount,ver+1);
 UPDATE securepay_private.work_completion SET status='approved',approved_version=ver+1 WHERE completion_id=z;
 UPDATE public.securepay_milestones SET status='approved',version=version+1,updated_at=clock_timestamp() WHERE tenant_id=t AND id=m;
 RETURN true;
EXCEPTION WHEN unique_violation THEN RETURN false;
END $$;
CREATE FUNCTION securepay_private.completion_approved(t uuid,m uuid,c uuid,a bigint,v bigint) RETURNS boolean
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM securepay_private.work_completion w JOIN securepay_private.work_approvals x ON x.completion_id=w.completion_id
 WHERE w.tenant_id=t AND w.milestone_id=m AND w.customer_id=c AND w.status='approved' AND w.amount_cents=a AND w.approved_version=v
 AND x.tenant_id=t AND x.customer_id=c AND x.amount_cents=a AND x.approved_version=v AND x.manifest_digest=w.manifest_digest
 AND w.manifest_digest=securepay_private.work_manifest(w.completion_id)
 AND EXISTS(SELECT 1 FROM securepay_private.work_photos p WHERE p.completion_id=w.completion_id)
 AND NOT EXISTS(SELECT 1 FROM securepay_private.work_photos p WHERE p.completion_id=w.completion_id AND NOT EXISTS(SELECT 1 FROM securepay_private.work_photo_views q WHERE q.completion_id=w.completion_id AND q.photo_id=p.photo_id AND q.customer_id=c)))
$$;
ALTER FUNCTION securepay_private.work_manifest(uuid) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.work_manifest(uuid) FROM PUBLIC;
ALTER FUNCTION securepay_private.start_work_completion(uuid,uuid,uuid,uuid,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.start_work_completion(uuid,uuid,uuid,uuid,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.start_work_completion(uuid,uuid,uuid,uuid,bigint,text) TO securepay_completion_runtime;
ALTER FUNCTION securepay_private.store_work_photo(uuid,uuid,uuid,uuid,uuid,text,text,text,bytea,bigint,text,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.store_work_photo(uuid,uuid,uuid,uuid,uuid,text,text,text,bytea,bigint,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.store_work_photo(uuid,uuid,uuid,uuid,uuid,text,text,text,bytea,bigint,text,bigint,text) TO securepay_completion_runtime;
ALTER FUNCTION securepay_private.submit_work_completion(uuid,uuid,uuid,uuid,text,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.submit_work_completion(uuid,uuid,uuid,uuid,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.submit_work_completion(uuid,uuid,uuid,uuid,text,bigint,text) TO securepay_completion_runtime;
ALTER FUNCTION securepay_private.payer_completion_view(uuid,uuid) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.payer_completion_view(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.payer_completion_view(uuid,uuid) TO securepay_payer_runtime;
ALTER FUNCTION securepay_private.payer_work_photo(uuid,uuid,uuid) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.payer_work_photo(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.payer_work_photo(uuid,uuid,uuid) TO securepay_payer_runtime;
ALTER FUNCTION securepay_private.approve_work_completion(uuid,uuid,uuid,text,bigint,bigint) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.approve_work_completion(uuid,uuid,uuid,text,bigint,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.approve_work_completion(uuid,uuid,uuid,text,bigint,bigint) TO securepay_payer_runtime;
ALTER FUNCTION securepay_private.completion_approved(uuid,uuid,uuid,bigint,bigint) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.completion_approved(uuid,uuid,uuid,bigint,bigint) FROM PUBLIC;
CREATE OR REPLACE FUNCTION securepay_private.reserve_signed(t uuid,c uuid,m uuid,amount bigint,ver bigint,
 req uuid,idem uuid,proof uuid,credential_salt text,credential_hash text,expires bigint,sig text)
 RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE k public.securepay_customer_pins%ROWTYPE; milestone public.securepay_milestones%ROWTYPE;
BEGIN
 IF securepay_private.current_payer(t) IS DISTINCT FROM c THEN RETURN NULL; END IF;
 PERFORM 1 FROM public.securepay_payer_identities WHERE tenant_id=t AND customer_id=c AND active FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL; END IF;
 SELECT * INTO milestone FROM public.securepay_milestones WHERE tenant_id=t AND id=m FOR UPDATE;
 IF NOT FOUND OR milestone.status<>'approved' OR milestone.payer_customer_id IS DISTINCT FROM c
 OR milestone.amount_cents<>amount OR milestone.version<>ver THEN RETURN NULL; END IF;
 IF NOT securepay_private.completion_approved(t,m,c,amount,ver) THEN RETURN NULL; END IF;
 PERFORM 1 FROM securepay_private.provider_funding WHERE tenant_id=t AND milestone_id=m AND amount_cents=amount AND status='funded' FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL; END IF;
 SELECT * INTO k FROM public.securepay_customer_pins WHERE tenant_id=t AND customer_id=c FOR UPDATE;
 IF NOT FOUND OR k.salt IS DISTINCT FROM credential_salt OR k.pin_hash IS DISTINCT FROM credential_hash
 OR k.locked_until>clock_timestamp() THEN RETURN NULL; END IF;
 IF securepay_private.command_valid(concat_ws(':','sp-release-v1',t,c,m,amount,ver,req,idem,proof,credential_salt,credential_hash,expires),sig,expires) IS DISTINCT FROM true
 THEN RETURN NULL; END IF;
 UPDATE public.securepay_customer_pins SET failed_attempts=0,locked_until=NULL WHERE tenant_id=t AND customer_id=c;
 INSERT INTO public.securepay_release_proofs(proof_ref,tenant_id,milestone_id,customer_id,amount_cents,expires_at,consumed_at,consumed_request_id)
 VALUES(proof::text,t,m,c,amount,to_timestamp(expires),clock_timestamp(),req);
 INSERT INTO public.securepay_release_requests(id,tenant_id,milestone_id,idempotency_key,amount_cents,authorization_ref,status)
 VALUES(req,t,m,idem::text,amount,proof::text,'pending');
 UPDATE public.securepay_milestones SET status='release_pending',version=version+1,updated_at=clock_timestamp() WHERE tenant_id=t AND id=m;
 RETURN req;
END $$;
CREATE OR REPLACE FUNCTION securepay_private.provider_begin_dispatch(t uuid,m uuid,r uuid) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE milestone public.securepay_milestones%ROWTYPE; funding securepay_private.provider_funding%ROWTYPE; req public.securepay_release_requests%ROWTYPE;
BEGIN
 SELECT * INTO milestone FROM public.securepay_milestones WHERE tenant_id=t AND id=m FOR UPDATE;
 IF NOT FOUND OR milestone.status<>'release_pending' THEN RETURN false; END IF;
 IF NOT securepay_private.completion_approved(t,m,milestone.payer_customer_id,milestone.amount_cents,milestone.version-1) THEN RETURN false; END IF;
 SELECT * INTO funding FROM securepay_private.provider_funding WHERE tenant_id=t AND milestone_id=m FOR UPDATE;
 IF NOT FOUND OR funding.status<>'funded' OR funding.amount_cents<>milestone.amount_cents THEN RETURN false; END IF;
 SELECT * INTO req FROM public.securepay_release_requests WHERE tenant_id=t AND milestone_id=m AND id=r FOR UPDATE;
 IF NOT FOUND OR req.status<>'pending' OR req.amount_cents<>milestone.amount_cents THEN RETURN false; END IF;
 IF NOT EXISTS(SELECT 1 FROM public.securepay_release_proofs p WHERE p.proof_ref=req.authorization_ref
 AND p.tenant_id=t AND p.milestone_id=m AND p.customer_id=milestone.payer_customer_id AND p.amount_cents=req.amount_cents
 AND p.consumed_request_id=r AND p.consumed_at IS NOT NULL) THEN RETURN false; END IF;
 UPDATE public.securepay_release_requests SET status='submitted' WHERE id=r;
 RETURN true;
END $$;
COMMIT;

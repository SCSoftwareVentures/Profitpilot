-- Sandbox-only encryption of photograph bytes. Keys remain accessible to trusted DB admins.
BEGIN;
-- Fail closed rather than leave old plaintext in a table. Existing-data migration,
-- including backups and WAL cleanup, requires a separately reviewed procedure.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM securepay_private.dispute_photos) THEN RAISE EXCEPTION 'Existing photos require reviewed migration'; END IF;
END $$;
CREATE TABLE securepay_private.evidence_keys(
 key_id text PRIMARY KEY CHECK(key_id ~ '^[a-z0-9-]{1,32}$'),
 secret bytea NOT NULL CHECK(octet_length(secret)=32),
 write_enabled boolean NOT NULL DEFAULT false, read_enabled boolean NOT NULL DEFAULT true,
 CHECK(NOT write_enabled OR read_enabled)
);
CREATE UNIQUE INDEX sp_one_evidence_writer ON securepay_private.evidence_keys(write_enabled) WHERE write_enabled;
ALTER TABLE securepay_private.evidence_keys OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.evidence_keys FROM PUBLIC,securepay_dispute_runtime,securepay_payer_runtime,securepay_provider_runtime,securepay_settlement_runtime;
ALTER TABLE securepay_private.dispute_photos DROP CONSTRAINT dispute_photos_content_check,
 ADD COLUMN key_id text NOT NULL REFERENCES securepay_private.evidence_keys(key_id),
 ADD COLUMN plaintext_size integer NOT NULL CHECK(plaintext_size BETWEEN 8 AND 2097152),
 ADD CONSTRAINT sp_ciphertext_size CHECK(octet_length(content) BETWEEN 32 AND 2101248);
CREATE OR REPLACE FUNCTION securepay_private.store_dispute_photo(p uuid,t uuid,m uuid,d uuid,a uuid,mime text,digest text,blob bytea,expires bigint,sig text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c securepay_private.dispute_cases%ROWTYPE; role_name text; kid text; secret_key bytea;
BEGIN
 IF p IS NULL OR t IS NULL OR m IS NULL OR d IS NULL OR a IS NULL OR mime IS NULL OR mime NOT IN ('image/jpeg','image/png')
 OR digest IS NULL OR digest !~ '^[a-f0-9]{64}$' OR blob IS NULL OR octet_length(blob) NOT BETWEEN 8 AND 2097152
 OR encode(public.digest(blob,'sha256'),'hex')<>digest THEN RETURN false; END IF;
 IF (mime='image/png' AND substring(blob FROM 1 FOR 8)<>decode('89504e470d0a1a0a','hex'))
 OR (mime='image/jpeg' AND (substring(blob FROM 1 FOR 3)<>decode('ffd8ff','hex') OR substring(blob FROM octet_length(blob)-1 FOR 2)<>decode('ffd9','hex'))) THEN RETURN false; END IF;
 role_name:=securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-photo-v1',p,t,m,d,a,mime,digest,expires),expires,sig);
 IF role_name IS NULL OR role_name NOT IN ('owner','customer') THEN RETURN false; END IF;
 SELECT * INTO c FROM securepay_private.dispute_cases WHERE case_id=d AND tenant_id=t AND milestone_id=m AND status IN ('open','appealed') FOR UPDATE;
 IF NOT FOUND OR (role_name='owner' AND a<>c.owner_id) OR (role_name='customer' AND a<>c.customer_id) THEN RETURN false; END IF;
 IF (SELECT count(*) FROM securepay_private.dispute_photos WHERE case_id=d)>=12 THEN RETURN false; END IF;
 SELECT key_id,secret INTO kid,secret_key FROM securepay_private.evidence_keys WHERE write_enabled FOR SHARE;
 IF secret_key IS NULL THEN RETURN false; END IF;
 INSERT INTO securepay_private.dispute_photos(photo_id,case_id,actor_id,media_type,digest,content,key_id,plaintext_size)
 VALUES(p,d,a,mime,digest,public.pgp_sym_encrypt_bytea(blob,encode(secret_key,'hex'),'cipher-algo=aes256,compress-algo=0'),kid,octet_length(blob));
 RETURN true;
EXCEPTION WHEN unique_violation THEN RETURN false;
END $$;
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
 IF NOT FOUND THEN RETURN; END IF;
 SELECT secret INTO secret_key FROM securepay_private.evidence_keys WHERE key_id=record_photo.key_id AND read_enabled;
 IF secret_key IS NULL THEN RAISE EXCEPTION 'Evidence unavailable' USING ERRCODE='22000'; END IF;
 plain:=public.pgp_sym_decrypt_bytea(record_photo.content,encode(secret_key,'hex'));
 IF octet_length(plain)<>record_photo.plaintext_size OR encode(public.digest(plain,'sha256'),'hex')<>record_photo.digest THEN
  RAISE EXCEPTION 'Evidence integrity failure' USING ERRCODE='22000';
 END IF;
 RETURN QUERY SELECT record_photo.media_type,record_photo.digest,plain;
END $$;
COMMIT;

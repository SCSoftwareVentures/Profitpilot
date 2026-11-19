-- Normalized photo provenance. Old raw uploader remains inaccessible.
BEGIN;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM securepay_private.dispute_photos) THEN RAISE EXCEPTION 'Existing evidence requires reviewed provenance migration'; END IF;
END $$;
ALTER TABLE securepay_private.dispute_photos
 ADD COLUMN original_media_type text CHECK(original_media_type IN ('image/png','image/jpeg')),
 ADD COLUMN original_digest text CHECK(original_digest ~ '^[a-f0-9]{64}$');
REVOKE EXECUTE ON FUNCTION securepay_private.store_screened_photo(uuid,uuid,uuid,uuid,uuid,text,text,bytea,bigint,text,bigint,text) FROM securepay_dispute_runtime;
CREATE FUNCTION securepay_private.store_screened_photo_v2(p uuid,t uuid,m uuid,d uuid,a uuid,mime text,digest text,blob bytea,expires bigint,sig text,scan_exp bigint,envelope text,original_mime text,source_digest text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE kid text; k bytea; n bigint; payload text;
BEGIN
 n:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 IF p IS NULL OR t IS NULL OR m IS NULL OR d IS NULL OR a IS NULL OR mime IS DISTINCT FROM 'image/png' OR digest IS NULL OR digest !~ '^[a-f0-9]{64}$'
 OR original_mime IS NULL OR original_mime NOT IN ('image/png','image/jpeg') OR source_digest IS NULL OR source_digest !~ '^[a-f0-9]{64}$' OR (original_mime='image/png' AND source_digest<>digest)
 OR scan_exp IS NULL OR scan_exp<n OR scan_exp>n+45 OR envelope IS NULL OR envelope !~ '^[a-z0-9-]{1,32}[.][a-f0-9]{64}$' THEN RETURN false; END IF;
 kid:=split_part(envelope,'.',1);
 SELECT secret INTO k FROM securepay_private.evidence_scan_keys WHERE key_id=kid AND active AND (valid_until IS NULL OR valid_until>clock_timestamp());
 payload:=concat_ws(':','sp-evidence-scan-v2',p,t,m,d,a,mime,digest,original_mime,source_digest,scan_exp,kid);
 IF k IS NULL OR encode(public.hmac(convert_to(payload,'UTF8'),k,'sha256'),'hex')<>split_part(envelope,'.',2) THEN RETURN false; END IF;
 IF securepay_private.store_dispute_photo(p,t,m,d,a,mime,digest,blob,expires,sig) IS DISTINCT FROM true THEN RETURN false; END IF;
 UPDATE securepay_private.dispute_photos SET scan_key_id=kid,screened_at=clock_timestamp(),original_media_type=original_mime,original_digest=source_digest WHERE photo_id=p;
 RETURN true;
END $$;
ALTER FUNCTION securepay_private.store_screened_photo_v2(uuid,uuid,uuid,uuid,uuid,text,text,bytea,bigint,text,bigint,text,text,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.store_screened_photo_v2(uuid,uuid,uuid,uuid,uuid,text,text,bytea,bigint,text,bigint,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.store_screened_photo_v2(uuid,uuid,uuid,uuid,uuid,text,text,bytea,bigint,text,bigint,text,text,text) TO securepay_dispute_runtime;
COMMIT;

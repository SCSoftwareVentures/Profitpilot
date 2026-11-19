-- Sandbox draft. Replace singleton keys with distinct purpose-specific key rings.
-- Admin inserts a new key, rolls out signer, then disables the retired key.
BEGIN;
ALTER TABLE securepay_private.context_key DROP COLUMN singleton,
 ADD COLUMN key_id text PRIMARY KEY DEFAULT 'primary' CHECK(key_id ~ '^[a-z0-9-]{1,32}$'),
 ADD COLUMN active boolean NOT NULL DEFAULT true,
 ADD COLUMN valid_until timestamptz,
 ADD COLUMN created_at timestamptz NOT NULL DEFAULT clock_timestamp();
REVOKE ALL ON securepay_private.context_key FROM PUBLIC,securepay_payer_runtime,securepay_notification_runtime;
ALTER TABLE securepay_private.command_key DROP COLUMN singleton,
 ADD COLUMN key_id text PRIMARY KEY DEFAULT 'primary' CHECK(key_id ~ '^[a-z0-9-]{1,32}$'),
 ADD COLUMN active boolean NOT NULL DEFAULT true,
 ADD COLUMN valid_until timestamptz,
 ADD COLUMN created_at timestamptz NOT NULL DEFAULT clock_timestamp();
REVOKE ALL ON securepay_private.command_key FROM PUBLIC,securepay_payer_runtime,securepay_notification_runtime;
ALTER TABLE securepay_private.recovery_key DROP COLUMN singleton,
 ADD COLUMN key_id text PRIMARY KEY DEFAULT 'primary' CHECK(key_id ~ '^[a-z0-9-]{1,32}$'),
 ADD COLUMN active boolean NOT NULL DEFAULT true,
 ADD COLUMN valid_until timestamptz,
 ADD COLUMN created_at timestamptz NOT NULL DEFAULT clock_timestamp();
REVOKE ALL ON securepay_private.recovery_key FROM PUBLIC,securepay_payer_runtime,securepay_notification_runtime;
CREATE FUNCTION securepay_private.key_signature_valid(purpose text,payload text,envelope text) RETURNS boolean
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE kid text; mac text; k bytea;
BEGIN
 IF envelope IS NULL OR envelope !~ '^[a-z0-9-]{1,32}[.][a-f0-9]{64}$' OR payload IS NULL THEN RETURN false; END IF;
 kid:=split_part(envelope,'.',1);mac:=split_part(envelope,'.',2);
 IF purpose='context' THEN
  SELECT secret INTO k FROM securepay_private.context_key WHERE key_id=kid AND active AND (valid_until IS NULL OR valid_until>clock_timestamp());
 ELSIF purpose='command' THEN
  SELECT secret INTO k FROM securepay_private.command_key WHERE key_id=kid AND active AND (valid_until IS NULL OR valid_until>clock_timestamp());
 ELSIF purpose='recovery' THEN
  SELECT secret INTO k FROM securepay_private.recovery_key WHERE key_id=kid AND active AND (valid_until IS NULL OR valid_until>clock_timestamp());
 ELSE RETURN false; END IF;
 RETURN coalesce(encode(public.hmac(convert_to(payload||':'||kid,'UTF8'),k,'sha256'),'hex')=mac,false);
END $$;
ALTER FUNCTION securepay_private.key_signature_valid(text,text,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.key_signature_valid(text,text,text) FROM PUBLIC,securepay_payer_runtime,securepay_notification_runtime;
CREATE OR REPLACE FUNCTION securepay_private.current_payer(t uuid) RETURNS uuid
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE
 raw_t text; sub text; exp bigint; nonce text; sig text; secret_key bytea; payload text; payer uuid;
BEGIN
 raw_t:=current_setting('sp.tenant',true);
 sub:=current_setting('sp.subject',true);
 exp:=nullif(current_setting('sp.expiry',true),'')::bigint;
 nonce:=current_setting('sp.nonce',true);
 sig:=current_setting('sp.signature',true);
 IF t IS NULL OR raw_t IS DISTINCT FROM t::text OR sub IS NULL OR length(sub) NOT BETWEEN 1 AND 512
   OR exp IS NULL OR exp<floor(extract(epoch FROM statement_timestamp()))::bigint
   OR exp>floor(extract(epoch FROM statement_timestamp()))::bigint+60
   OR nonce IS NULL OR nonce !~ '^[a-f0-9]{32}$' OR sig IS NULL
 THEN RETURN NULL; END IF;
 -- Length-prefix the subject via its UTF-8 hex representation; domain separate from staff context.
 payload:='securepay-payer-v1:'||t::text||':'||encode(convert_to(sub,'UTF8'),'hex')||':'||exp::text||':'||nonce;
 IF securepay_private.key_signature_valid('context',payload,sig) IS DISTINCT FROM true THEN RETURN NULL; END IF;
 SELECT customer_id INTO payer FROM public.securepay_payer_identities
  WHERE tenant_id=t AND auth_subject=sub AND active;
 RETURN payer;
EXCEPTION WHEN OTHERS THEN RETURN NULL;
END $$;
CREATE OR REPLACE FUNCTION securepay_private.command_valid(payload text,sig text,expires bigint) RETURNS boolean
 LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT coalesce(expires BETWEEN floor(extract(epoch FROM clock_timestamp()))::bigint AND floor(extract(epoch FROM clock_timestamp()))::bigint+30
 AND securepay_private.key_signature_valid('command',payload,sig),false)
$$;
CREATE OR REPLACE FUNCTION securepay_private.issue_pin_grant(t uuid,c uuid,op text,digest text,g uuid,assertion_exp bigint,command_exp bigint,sig text)
 RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE key_bytes bytea; existing boolean; n bigint;
BEGIN
 IF t IS NULL OR c IS NULL OR g IS NULL OR op IS NULL OR op NOT IN ('enroll','recover')
 OR digest IS NULL OR digest !~ '^[0-9a-f]{64}$' OR sig IS NULL
 OR securepay_private.current_payer(t) IS DISTINCT FROM c THEN RETURN NULL; END IF;
 PERFORM 1 FROM public.securepay_payer_identities WHERE tenant_id=t AND customer_id=c AND active FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL; END IF;
 n:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 IF assertion_exp IS NULL OR command_exp IS NULL OR assertion_exp<=n OR assertion_exp>n+300
 OR command_exp<n OR command_exp>n+30 OR command_exp>assertion_exp THEN RETURN NULL; END IF;
 IF securepay_private.key_signature_valid('recovery',concat_ws(':','sp-grant-v1',t,c,op,digest,g,assertion_exp,command_exp),sig) IS DISTINCT FROM true
 THEN RETURN NULL; END IF;
 SELECT EXISTS(SELECT 1 FROM public.securepay_customer_pins WHERE tenant_id=t AND customer_id=c) INTO existing;
 IF (op='enroll' AND existing) OR (op='recover' AND NOT existing) THEN RETURN NULL; END IF;
 INSERT INTO securepay_private.recovery_assertions(assertion_digest,tenant_id,customer_id,purpose,grant_ref)
 VALUES(digest,t,c,op,g) ON CONFLICT(assertion_digest) DO NOTHING;
 IF NOT FOUND THEN RETURN NULL; END IF;
 UPDATE public.securepay_pin_change_grants SET consumed_at=clock_timestamp()
 WHERE tenant_id=t AND customer_id=c AND consumed_at IS NULL;
 INSERT INTO public.securepay_pin_change_grants(grant_ref,tenant_id,customer_id,purpose,expires_at)
 VALUES(g,t,c,op,least(to_timestamp(assertion_exp),clock_timestamp()+interval '2 minutes'));
 RETURN g;
END $$;
COMMIT;

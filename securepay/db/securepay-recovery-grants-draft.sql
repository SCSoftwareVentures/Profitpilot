-- Draft following the command-boundary migration; sandbox only.
BEGIN;
CREATE TABLE securepay_private.recovery_key(
 singleton boolean PRIMARY KEY CHECK(singleton), secret bytea NOT NULL CHECK(octet_length(secret)=32)
);
CREATE TABLE securepay_private.recovery_assertions(
 assertion_digest text PRIMARY KEY CHECK(assertion_digest ~ '^[0-9a-f]{64}$'),
 tenant_id uuid NOT NULL, customer_id uuid NOT NULL, purpose text NOT NULL,
 grant_ref uuid NOT NULL UNIQUE, used_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE securepay_private.recovery_key OWNER TO securepay_context_owner;
ALTER TABLE securepay_private.recovery_assertions OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.recovery_key,securepay_private.recovery_assertions FROM PUBLIC,securepay_payer_runtime;
CREATE FUNCTION securepay_private.issue_pin_grant(t uuid,c uuid,op text,digest text,g uuid,assertion_exp bigint,command_exp bigint,sig text)
 RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE key_bytes bytea; existing boolean; n bigint;
BEGIN
 IF t IS NULL OR c IS NULL OR g IS NULL OR op IS NULL OR op NOT IN ('enroll','recover')
 OR digest IS NULL OR digest !~ '^[0-9a-f]{64}$' OR sig IS NULL OR sig !~ '^[0-9a-f]{64}$'
 OR securepay_private.current_payer(t) IS DISTINCT FROM c THEN RETURN NULL; END IF;
 PERFORM 1 FROM public.securepay_payer_identities WHERE tenant_id=t AND customer_id=c AND active FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL; END IF;
 n:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 IF assertion_exp IS NULL OR command_exp IS NULL OR assertion_exp<=n OR assertion_exp>n+300
 OR command_exp<n OR command_exp>n+30 OR command_exp>assertion_exp THEN RETURN NULL; END IF;
 SELECT secret INTO key_bytes FROM securepay_private.recovery_key WHERE singleton;
 IF key_bytes IS NULL OR encode(public.hmac(convert_to(concat_ws(':','sp-grant-v1',t,c,op,digest,g,assertion_exp,command_exp),'UTF8'),key_bytes,'sha256'),'hex')<>sig
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
ALTER FUNCTION securepay_private.issue_pin_grant(uuid,uuid,text,text,uuid,bigint,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.issue_pin_grant(uuid,uuid,text,text,uuid,bigint,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.issue_pin_grant(uuid,uuid,text,text,uuid,bigint,bigint,text) TO securepay_payer_runtime;
COMMIT;

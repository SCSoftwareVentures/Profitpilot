-- Draft post-RLS hardening. Runtime may read scoped records but can no longer
-- directly manufacture proofs, requests or PIN credentials. Only exact signed
-- commands are accepted by the narrow definer functions.
BEGIN;
CREATE TABLE securepay_private.command_key(singleton boolean PRIMARY KEY CHECK(singleton), secret bytea NOT NULL CHECK(octet_length(secret)=32));
ALTER TABLE securepay_private.command_key OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.command_key FROM PUBLIC,securepay_payer_runtime;
GRANT SELECT,INSERT,UPDATE,DELETE ON public.securepay_customer_pins,public.securepay_pin_change_grants,
 public.securepay_release_proofs,public.securepay_release_requests,public.securepay_milestones TO securepay_context_owner;
GRANT UPDATE(active) ON public.securepay_payer_identities TO securepay_context_owner;
-- Column grants must be revoked explicitly.
REVOKE INSERT(tenant_id,customer_id,salt,pin_hash), UPDATE(salt,pin_hash,failed_attempts,locked_until)
 ON public.securepay_customer_pins FROM securepay_payer_runtime;
REVOKE UPDATE(consumed_at) ON public.securepay_pin_change_grants FROM securepay_payer_runtime;
REVOKE UPDATE(status,version,updated_at) ON public.securepay_milestones FROM securepay_payer_runtime;
REVOKE INSERT(proof_ref,tenant_id,milestone_id,customer_id,amount_cents,expires_at),
 UPDATE(consumed_at,consumed_request_id), DELETE ON public.securepay_release_proofs FROM securepay_payer_runtime;
REVOKE INSERT(id,tenant_id,milestone_id,idempotency_key,amount_cents,authorization_ref,status)
 ON public.securepay_release_requests FROM securepay_payer_runtime;

CREATE FUNCTION securepay_private.command_valid(payload text,sig text,expires bigint) RETURNS boolean
 LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT coalesce(sig ~ '^[a-f0-9]{64}$' AND expires BETWEEN floor(extract(epoch FROM clock_timestamp()))::bigint
 AND floor(extract(epoch FROM clock_timestamp()))::bigint+30
 AND encode(public.hmac(convert_to(payload,'UTF8'),secret,'sha256'),'hex')=sig,false)
 FROM securepay_private.command_key WHERE singleton
$$;
ALTER FUNCTION securepay_private.command_valid(text,text,bigint) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.command_valid(text,text,bigint) FROM PUBLIC,securepay_payer_runtime;

CREATE FUNCTION securepay_private.reserve_signed(t uuid,c uuid,m uuid,amount bigint,ver bigint,
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

CREATE FUNCTION securepay_private.record_pin_failure(t uuid,c uuid) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE k public.securepay_customer_pins%ROWTYPE; n integer;
BEGIN
 IF securepay_private.current_payer(t) IS DISTINCT FROM c THEN RETURN false; END IF;
 PERFORM 1 FROM public.securepay_payer_identities WHERE tenant_id=t AND customer_id=c AND active FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO k FROM public.securepay_customer_pins WHERE tenant_id=t AND customer_id=c FOR UPDATE;
 IF NOT FOUND OR k.locked_until>clock_timestamp() THEN RETURN false; END IF;
 n:=CASE WHEN k.locked_until IS NOT NULL THEN 1 ELSE least(k.failed_attempts+1,5) END;
 UPDATE public.securepay_customer_pins SET failed_attempts=n,
 locked_until=CASE WHEN n=5 THEN clock_timestamp()+interval '15 minutes' ELSE NULL END WHERE tenant_id=t AND customer_id=c;
 RETURN true;
END $$;

CREATE FUNCTION securepay_private.change_pin_signed(t uuid,c uuid,g uuid,op text,new_salt text,new_hash text,expires bigint,sig text)
 RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE existing boolean;
BEGIN
 IF securepay_private.current_payer(t) IS DISTINCT FROM c OR op NOT IN ('enroll','recover')
 OR new_salt !~ '^[0-9a-f]{32}$' OR new_hash !~ '^[0-9a-f]{64}$' THEN RETURN false; END IF;
 PERFORM 1 FROM public.securepay_payer_identities WHERE tenant_id=t AND customer_id=c AND active FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT EXISTS(SELECT 1 FROM public.securepay_customer_pins WHERE tenant_id=t AND customer_id=c) INTO existing;
 IF (op='enroll' AND existing) OR (op='recover' AND NOT existing) THEN RETURN false; END IF;
 IF securepay_private.command_valid(concat_ws(':','sp-pin-change-v1',t,c,g,op,new_salt,new_hash,expires),sig,expires) IS DISTINCT FROM true
 THEN RETURN false; END IF;
 UPDATE public.securepay_pin_change_grants SET consumed_at=clock_timestamp() WHERE grant_ref=g AND tenant_id=t AND customer_id=c
 AND purpose=op AND consumed_at IS NULL AND expires_at>clock_timestamp();
 IF NOT FOUND THEN RETURN false; END IF;
 IF op='enroll' THEN
  INSERT INTO public.securepay_customer_pins(tenant_id,customer_id,salt,pin_hash) VALUES(t,c,new_salt,new_hash);
 ELSE
  UPDATE public.securepay_customer_pins SET salt=new_salt,pin_hash=new_hash,failed_attempts=0,locked_until=NULL WHERE tenant_id=t AND customer_id=c;
  DELETE FROM public.securepay_release_proofs WHERE tenant_id=t AND customer_id=c AND consumed_at IS NULL;
 END IF;
 UPDATE public.securepay_pin_change_grants SET consumed_at=clock_timestamp() WHERE tenant_id=t AND customer_id=c AND consumed_at IS NULL;
 RETURN true;
END $$;
ALTER FUNCTION securepay_private.reserve_signed(uuid,uuid,uuid,bigint,bigint,uuid,uuid,uuid,text,text,bigint,text) OWNER TO securepay_context_owner;
ALTER FUNCTION securepay_private.record_pin_failure(uuid,uuid) OWNER TO securepay_context_owner;
ALTER FUNCTION securepay_private.change_pin_signed(uuid,uuid,uuid,text,text,text,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.reserve_signed(uuid,uuid,uuid,bigint,bigint,uuid,uuid,uuid,text,text,bigint,text),securepay_private.record_pin_failure(uuid,uuid),securepay_private.change_pin_signed(uuid,uuid,uuid,text,text,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.reserve_signed(uuid,uuid,uuid,bigint,bigint,uuid,uuid,uuid,text,text,bigint,text),securepay_private.record_pin_failure(uuid,uuid),securepay_private.change_pin_signed(uuid,uuid,uuid,text,text,text,bigint,text) TO securepay_payer_runtime;
COMMIT;

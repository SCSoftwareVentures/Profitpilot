-- SANDBOX ONLY. Synthetic provider facts, not receipt or custody of real money.
BEGIN;
CREATE ROLE securepay_provider_runtime NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS;
GRANT USAGE ON SCHEMA securepay_private TO securepay_provider_runtime;
CREATE TABLE securepay_private.provider_key(
 key_id text PRIMARY KEY CHECK(key_id ~ '^[a-z0-9-]{1,32}$'),
 secret bytea NOT NULL CHECK(octet_length(secret)=32), active boolean NOT NULL DEFAULT true,
 valid_until timestamptz
);
CREATE TABLE securepay_private.provider_funding(
 tenant_id uuid NOT NULL, milestone_id uuid NOT NULL, funding_ref uuid UNIQUE NOT NULL,
 amount_cents bigint NOT NULL CHECK(amount_cents>0), status text NOT NULL CHECK(status IN ('funded','held','released')),
 confirmed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,milestone_id), FOREIGN KEY(tenant_id,milestone_id) REFERENCES public.securepay_milestones(tenant_id,id)
);
CREATE TABLE securepay_private.provider_events(
 event_id uuid PRIMARY KEY, tenant_id uuid NOT NULL, milestone_id uuid NOT NULL,
 kind text NOT NULL CHECK(kind IN ('funded','held','released','failed')),
 funding_ref uuid NOT NULL, request_id uuid, amount_cents bigint NOT NULL CHECK(amount_cents>0),
 transaction_ref uuid UNIQUE, recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE securepay_private.provider_reconciliation(
 event_id uuid PRIMARY KEY REFERENCES securepay_private.provider_events(event_id),
 tenant_id uuid NOT NULL, milestone_id uuid NOT NULL,
 reason text NOT NULL CHECK(reason IN ('hold_after_dispatch','provider_failure')),
 opened_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE securepay_private.provider_reconciliation OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.provider_reconciliation FROM PUBLIC,securepay_payer_runtime,securepay_notification_runtime,securepay_provider_runtime;
ALTER TABLE securepay_private.provider_key OWNER TO securepay_context_owner;
ALTER TABLE securepay_private.provider_funding OWNER TO securepay_context_owner;
ALTER TABLE securepay_private.provider_events OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.provider_key,securepay_private.provider_funding,securepay_private.provider_events FROM PUBLIC,securepay_payer_runtime,securepay_notification_runtime,securepay_provider_runtime;
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


-- Submission means a synthetic dispatch was reserved, not that money moved.
CREATE FUNCTION securepay_private.provider_begin_dispatch(t uuid,m uuid,r uuid) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE milestone public.securepay_milestones%ROWTYPE; funding securepay_private.provider_funding%ROWTYPE; req public.securepay_release_requests%ROWTYPE;
BEGIN
 SELECT * INTO milestone FROM public.securepay_milestones WHERE tenant_id=t AND id=m FOR UPDATE;
 IF NOT FOUND OR milestone.status<>'release_pending' THEN RETURN false; END IF;
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
CREATE FUNCTION securepay_private.provider_event(e uuid,t uuid,m uuid,k text,f uuid,r uuid,a bigint,x uuid,expires bigint,envelope text)
 RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE milestone public.securepay_milestones%ROWTYPE; funding securepay_private.provider_funding%ROWTYPE; req public.securepay_release_requests%ROWTYPE;
 previous securepay_private.provider_events%ROWTYPE; kid text; mac text; secret_key bytea; payload text; n bigint;
BEGIN
 IF e IS NULL OR t IS NULL OR m IS NULL OR f IS NULL OR a IS NULL OR a<=0 OR k IS NULL OR k NOT IN ('funded','held','released','failed')
 OR expires IS NULL OR envelope IS NULL OR envelope !~ '^[a-z0-9-]{1,32}[.][a-f0-9]{64}$' THEN RETURN 'denied'; END IF;
 IF (k IN ('funded','held') AND (r IS NOT NULL OR x IS NOT NULL)) OR (k='released' AND (r IS NULL OR x IS NULL))
 OR (k='failed' AND (r IS NULL OR x IS NOT NULL)) THEN RETURN 'denied'; END IF;
 n:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 IF expires<n OR expires>n+60 THEN RETURN 'denied'; END IF;
 kid:=split_part(envelope,'.',1);mac:=split_part(envelope,'.',2);
 SELECT secret INTO secret_key FROM securepay_private.provider_key WHERE key_id=kid AND active AND (valid_until IS NULL OR valid_until>clock_timestamp());
 payload:=concat_ws(':','sp-sandbox-provider-v1',e,t,m,k,f,coalesce(r::text,'-'),a,coalesce(x::text,'-'),expires,kid);
 IF secret_key IS NULL OR encode(public.hmac(convert_to(payload,'UTF8'),secret_key,'sha256'),'hex')<>mac THEN RETURN 'denied'; END IF;
 -- Same event identity is serialized across tenants before milestone/funding/request locks.
 PERFORM pg_advisory_xact_lock(hashtextextended(e::text,810));
 SELECT * INTO previous FROM securepay_private.provider_events WHERE event_id=e;
 IF FOUND THEN
  IF previous.tenant_id=t AND previous.milestone_id=m AND previous.kind=k AND previous.funding_ref=f
  AND previous.request_id IS NOT DISTINCT FROM r AND previous.amount_cents=a AND previous.transaction_ref IS NOT DISTINCT FROM x
  THEN RETURN 'duplicate'; END IF;
  RETURN 'denied';
 END IF;
 SELECT * INTO milestone FROM public.securepay_milestones WHERE tenant_id=t AND id=m FOR UPDATE;
 IF NOT FOUND OR milestone.amount_cents<>a THEN RETURN 'denied'; END IF;
 SELECT * INTO funding FROM securepay_private.provider_funding WHERE tenant_id=t AND milestone_id=m FOR UPDATE;
 IF k='funded' THEN
  IF FOUND OR milestone.status NOT IN ('planned','submitted','approved') THEN RETURN 'denied'; END IF;
  INSERT INTO securepay_private.provider_funding(tenant_id,milestone_id,funding_ref,amount_cents,status) VALUES(t,m,f,a,'funded');
 ELSE
  IF NOT FOUND OR funding.funding_ref<>f OR funding.amount_cents<>a THEN RETURN 'denied'; END IF;
  IF k='held' THEN
   IF EXISTS(SELECT 1 FROM public.securepay_release_requests WHERE tenant_id=t AND milestone_id=m AND status IN ('submitted','confirmed')) THEN
    INSERT INTO securepay_private.provider_events(event_id,tenant_id,milestone_id,kind,funding_ref,amount_cents) VALUES(e,t,m,k,f,a);
    INSERT INTO securepay_private.provider_reconciliation(event_id,tenant_id,milestone_id,reason) VALUES(e,t,m,'hold_after_dispatch');
    RETURN 'reconcile';
   END IF;
   IF funding.status<>'funded' THEN RETURN 'denied'; END IF;
   UPDATE securepay_private.provider_funding SET status='held' WHERE tenant_id=t AND milestone_id=m;
  ELSE
   IF funding.status<>'funded' THEN RETURN 'denied'; END IF;
   SELECT * INTO req FROM public.securepay_release_requests WHERE tenant_id=t AND milestone_id=m AND id=r FOR UPDATE;
   IF NOT FOUND OR req.status<>'submitted' OR milestone.status<>'release_pending' OR req.amount_cents<>a THEN RETURN 'denied'; END IF;
   IF k='released' THEN
    UPDATE public.securepay_release_requests SET status='confirmed',provider_transaction_ref=x::text WHERE id=r;
    UPDATE public.securepay_milestones SET status='released',provider_transaction_ref=x::text,version=version+1,updated_at=clock_timestamp() WHERE id=m;
    UPDATE securepay_private.provider_funding SET status='released' WHERE tenant_id=t AND milestone_id=m;
   ELSE
    -- No automatic retry or refund: retain the reservation and require reconciliation.
    UPDATE public.securepay_release_requests SET status='failed' WHERE id=r;
    UPDATE securepay_private.provider_funding SET status='held' WHERE tenant_id=t AND milestone_id=m;
   END IF;
  END IF;
 END IF;
 INSERT INTO securepay_private.provider_events(event_id,tenant_id,milestone_id,kind,funding_ref,request_id,amount_cents,transaction_ref)
 VALUES(e,t,m,k,f,r,a,x);
 IF k='failed' THEN INSERT INTO securepay_private.provider_reconciliation(event_id,tenant_id,milestone_id,reason) VALUES(e,t,m,'provider_failure'); END IF;
 RETURN 'applied';
EXCEPTION WHEN unique_violation THEN RETURN 'denied';
END $$;
ALTER FUNCTION securepay_private.provider_begin_dispatch(uuid,uuid,uuid) OWNER TO securepay_context_owner;
ALTER FUNCTION securepay_private.provider_event(uuid,uuid,uuid,text,uuid,uuid,bigint,uuid,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.provider_begin_dispatch(uuid,uuid,uuid),securepay_private.provider_event(uuid,uuid,uuid,text,uuid,uuid,bigint,uuid,bigint,text) FROM PUBLIC,securepay_payer_runtime,securepay_notification_runtime;
GRANT EXECUTE ON FUNCTION securepay_private.provider_begin_dispatch(uuid,uuid,uuid),securepay_private.provider_event(uuid,uuid,uuid,text,uuid,uuid,bigint,uuid,bigint,text) TO securepay_provider_runtime;
COMMIT;

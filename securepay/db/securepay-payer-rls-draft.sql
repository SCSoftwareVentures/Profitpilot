-- Draft, not a production migration. Run only as database administrator.
-- Separate payer runtime: do not grant membership to profitpilot_app.
BEGIN;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE ROLE securepay_context_owner NOLOGIN NOINHERIT NOSUPERUSER BYPASSRLS;
CREATE ROLE securepay_payer_runtime NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS;
CREATE SCHEMA securepay_private AUTHORIZATION securepay_context_owner;
REVOKE ALL ON SCHEMA securepay_private FROM PUBLIC;
CREATE TABLE securepay_private.context_key(
 singleton boolean PRIMARY KEY CHECK(singleton),
 secret bytea NOT NULL CHECK(octet_length(secret)>=32)
);
ALTER TABLE securepay_private.context_key OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.context_key FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO securepay_context_owner,securepay_payer_runtime;
GRANT SELECT ON public.securepay_payer_identities TO securepay_context_owner;

CREATE FUNCTION securepay_private.current_payer(t uuid) RETURNS uuid
 LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
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
   OR nonce IS NULL OR nonce !~ '^[a-f0-9]{32}$' OR sig IS NULL OR sig !~ '^[a-f0-9]{64}$'
 THEN RETURN NULL; END IF;
 SELECT secret INTO secret_key FROM securepay_private.context_key WHERE singleton=true;
 IF secret_key IS NULL THEN RETURN NULL; END IF;
 -- Length-prefix the subject via its UTF-8 hex representation; domain separate from staff context.
 payload:='securepay-payer-v1:'||t::text||':'||encode(convert_to(sub,'UTF8'),'hex')||':'||exp::text||':'||nonce;
 IF encode(public.hmac(convert_to(payload,'UTF8'),secret_key,'sha256'),'hex')<>sig THEN RETURN NULL; END IF;
 SELECT customer_id INTO payer FROM public.securepay_payer_identities
  WHERE tenant_id=t AND auth_subject=sub AND active;
 RETURN payer;
EXCEPTION WHEN OTHERS THEN RETURN NULL;
END $$;
ALTER FUNCTION securepay_private.current_payer(uuid) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.current_payer(uuid) FROM PUBLIC;
GRANT USAGE ON SCHEMA securepay_private TO securepay_payer_runtime;
GRANT EXECUTE ON FUNCTION securepay_private.current_payer(uuid) TO securepay_payer_runtime;

-- Existing application bootstrap grants default table privileges. Explicitly remove
-- those from the staff runtime; payer tables are not ordinary tenant-wide data.
REVOKE ALL ON public.securepay_payer_identities, public.securepay_customer_pins,
 public.securepay_pin_change_grants, public.securepay_milestones,
 public.securepay_release_proofs, public.securepay_release_requests FROM PUBLIC;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='profitpilot_app') THEN
  REVOKE ALL ON public.securepay_payer_identities, public.securepay_customer_pins,
   public.securepay_pin_change_grants, public.securepay_milestones,
   public.securepay_release_proofs, public.securepay_release_requests FROM profitpilot_app;
 END IF;
END $$;

GRANT SELECT ON public.securepay_payer_identities,public.securepay_customer_pins,
 public.securepay_pin_change_grants,public.securepay_milestones,public.securepay_release_proofs,
 public.securepay_release_requests TO securepay_payer_runtime;
-- Identity row lock needs UPDATE permission; policy below only permits active=true.
GRANT UPDATE(active) ON public.securepay_payer_identities TO securepay_payer_runtime;
GRANT INSERT(tenant_id,customer_id,salt,pin_hash), UPDATE(salt,pin_hash,failed_attempts,locked_until)
 ON public.securepay_customer_pins TO securepay_payer_runtime;
GRANT UPDATE(consumed_at) ON public.securepay_pin_change_grants TO securepay_payer_runtime;
GRANT UPDATE(status,version,updated_at) ON public.securepay_milestones TO securepay_payer_runtime;
GRANT INSERT(proof_ref,tenant_id,milestone_id,customer_id,amount_cents,expires_at),
 UPDATE(consumed_at,consumed_request_id), DELETE ON public.securepay_release_proofs TO securepay_payer_runtime;
GRANT INSERT(id,tenant_id,milestone_id,idempotency_key,amount_cents,authorization_ref,status)
 ON public.securepay_release_requests TO securepay_payer_runtime;

CREATE POLICY payer_identity_read ON public.securepay_payer_identities FOR SELECT TO securepay_payer_runtime
 USING(active AND customer_id=securepay_private.current_payer(tenant_id));
CREATE POLICY payer_identity_lock ON public.securepay_payer_identities FOR UPDATE TO securepay_payer_runtime
 USING(active AND customer_id=securepay_private.current_payer(tenant_id))
 WITH CHECK(active AND customer_id=securepay_private.current_payer(tenant_id));

CREATE POLICY payer_pin_scope ON public.securepay_customer_pins TO securepay_payer_runtime
 USING(customer_id=securepay_private.current_payer(tenant_id))
 WITH CHECK(customer_id=securepay_private.current_payer(tenant_id));
CREATE POLICY payer_grant_read ON public.securepay_pin_change_grants FOR SELECT TO securepay_payer_runtime
 USING(customer_id=securepay_private.current_payer(tenant_id));
CREATE POLICY payer_grant_consume ON public.securepay_pin_change_grants FOR UPDATE TO securepay_payer_runtime
 USING(customer_id=securepay_private.current_payer(tenant_id))
 WITH CHECK(customer_id=securepay_private.current_payer(tenant_id) AND consumed_at IS NOT NULL);

CREATE POLICY payer_milestone_read ON public.securepay_milestones FOR SELECT TO securepay_payer_runtime
 USING(payer_customer_id=securepay_private.current_payer(tenant_id));
CREATE POLICY payer_milestone_reserve ON public.securepay_milestones FOR UPDATE TO securepay_payer_runtime
 USING(payer_customer_id=securepay_private.current_payer(tenant_id) AND status='approved')
 WITH CHECK(payer_customer_id=securepay_private.current_payer(tenant_id) AND status='release_pending');

CREATE POLICY payer_proof_read ON public.securepay_release_proofs FOR SELECT TO securepay_payer_runtime
 USING(customer_id=securepay_private.current_payer(tenant_id));
CREATE POLICY payer_proof_insert ON public.securepay_release_proofs FOR INSERT TO securepay_payer_runtime
 WITH CHECK(customer_id=securepay_private.current_payer(tenant_id) AND consumed_at IS NULL
  AND EXISTS(SELECT 1 FROM public.securepay_milestones m WHERE m.tenant_id=securepay_release_proofs.tenant_id
   AND m.id=securepay_release_proofs.milestone_id AND m.amount_cents=securepay_release_proofs.amount_cents AND m.status='approved'));
CREATE POLICY payer_proof_consume ON public.securepay_release_proofs FOR UPDATE TO securepay_payer_runtime
 USING(customer_id=securepay_private.current_payer(tenant_id) AND consumed_at IS NULL)
 WITH CHECK(customer_id=securepay_private.current_payer(tenant_id) AND consumed_at IS NOT NULL);
CREATE POLICY payer_proof_revoke ON public.securepay_release_proofs FOR DELETE TO securepay_payer_runtime
 USING(customer_id=securepay_private.current_payer(tenant_id) AND consumed_at IS NULL);
CREATE POLICY payer_request_read ON public.securepay_release_requests FOR SELECT TO securepay_payer_runtime
 USING(EXISTS(SELECT 1 FROM public.securepay_milestones m WHERE m.tenant_id=securepay_release_requests.tenant_id
  AND m.id=securepay_release_requests.milestone_id));
CREATE POLICY payer_request_insert ON public.securepay_release_requests FOR INSERT TO securepay_payer_runtime
 WITH CHECK(status='pending' AND EXISTS(SELECT 1 FROM public.securepay_milestones m
  JOIN public.securepay_release_proofs p ON p.tenant_id=m.tenant_id AND p.milestone_id=m.id
  WHERE m.tenant_id=securepay_release_requests.tenant_id AND m.id=securepay_release_requests.milestone_id
  AND m.amount_cents=securepay_release_requests.amount_cents AND m.status='approved'
  AND p.proof_ref=securepay_release_requests.authorization_ref AND p.consumed_request_id=securepay_release_requests.id
  AND p.consumed_at IS NOT NULL AND p.amount_cents=m.amount_cents));
COMMIT;
-- Provision the separate signing key out-of-band. Runtime login/bootstrap,
-- trusted API credential isolation and production security review are outstanding.
